package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// —— 公开端点（loginRateLimit 由路由注册挂载，同 /auth/login）——

// MFAVerifyLogin POST /auth/mfa/verify — 登录第二步：挑战令牌 + 验证码 → JWT。
func (h *Handlers) MFAVerifyLogin(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	var req struct {
		MFAToken string `json:"mfa_token" binding:"required"`
		Code     string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	var userID int
	var passwordVersion, challengeVersion int64
	var user models.User
	err := db.DB.QueryRow(`SELECT u.id, u.password_version, ch.password_version, u.username, u.role, u.display_name, u.is_enabled, u.created_at, u.last_login, COALESCE(u.auth_provider,'local')
		FROM mfa_challenges ch JOIN users u ON u.id = ch.user_id
		WHERE ch.token=? AND ch.expires_at > datetime('now')`, req.MFAToken).
		Scan(&userID, &passwordVersion, &challengeVersion, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &user.AuthProvider)
	if err != nil {
		// 历史修复（历史）：DB 故障与无效挑战分判——基础设施错误 500，
		// 不再伪装成 401（挑战无效不泄露具体原因的口径仅适用于 ErrNoRows）。
		if !errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
			return
		}
		// 挑战无效不泄露具体原因
		services.RecordAuditLog("", "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战令牌无效或已过期"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战无效或已过期，请重新登录"})
		return
	}
	if !user.IsEnabled {
		// 挑战无效不泄露具体原因
		services.RecordAuditLog("", "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战令牌无效或已过期"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战无效或已过期，请重新登录"})
		return
	}
	user.ID = userID

	// 挑战绑定签发时的密码版本——签发后密码被改（自助/管理员重置），
	// 旧挑战即使持有有效第二因子也不得换取携带新 pwd_ver 的 JWT；顺带删除。
	if challengeVersion != passwordVersion {
		_, _ = db.DB.Exec("DELETE FROM mfa_challenges WHERE token=?", req.MFAToken)
		services.RecordAuditLog("", "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战令牌无效或已过期"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战无效或已过期，请重新登录"})
		return
	}

	// 登录失败锁定（2026-09 用户裁定）：MFA 验证码失败与密码失败同计一个
	// 账户级计数（login_*），受「登录失败锁定」开关控制；锁定期间验证步直接
	// 429，不再消耗挑战次数。
	// 锁定状态/开关读取失败必须 历史修复（500，不消费挑战）——
	// 旧实现把 DB 错误静默当作「未锁定」。
	var loginLockedUntil sql.NullString
	if err := db.DB.QueryRow("SELECT login_locked_until FROM users WHERE id=?", userID).Scan(&loginLockedUntil); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			services.RecordAuditLog("", "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战令牌无效或已过期"), c.ClientIP())
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战无效或已过期，请重新登录"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	locked, lockErr := loginLockedNow(loginLockedUntil)
	if lockErr != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	if locked {
		services.RecordAuditLog(user.Username, "登录失败", "用户认证", services.FormatAuditDetail(services.AuditUserPart(userID, user.Username), "账户已锁定"), c.ClientIP())
		c.JSON(http.StatusTooManyRequests, models.APIResponse{Code: 429, Message: fmt.Sprintf("账户已锁定，请 %d 分钟后重试", loginLockRemainingMinutes(loginLockedUntil, time.Now().UTC()))})
		return
	}

	// 历史问题：先消费挑战、后验码——消费判定是挑战状态的唯一权威（已消费/并发
	// 落败/过期窗口在此 401，不触碰凭证）；旧顺序先验码，恢复码「提交即消费」
	// 会在「挑战已被使用」路径白烧。验码失败归还挑战（错误码不烧挑战，同 token
	// 可重试；失败计数由 MFARecordChallengeFailure 负责，达阈值仍作废）。
	consumed, consumeErr := services.MFAConsumeChallenge(req.MFAToken, userID)
	if consumeErr != nil {
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战消费服务故障"), c.ClientIP())
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
		return
	}
	if !consumed {
		// 历史修复（历史）：并发登录落败/挑战达阈值作废后的重放是爆破与
		// 外部竞态的观测面——与同函数其余拒绝分支同密度留痕（此前这是唯一
		// 无审计的拒绝分支，事后无法区分「客户端重试」与「重放已消费挑战」）。
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "挑战已被使用"), c.ClientIP())
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "MFA 挑战已被使用，请重新登录"})
		return
	}
	if ok, verr := services.MFAVerifyCode(userID, req.Code, time.Now()); !ok {
		services.MFARestoreChallenge(req.MFAToken, userID)
		if errors.Is(verr, services.ErrMFANotEnabled) {
			// 业务态：签发挑战后密钥被并发清除（禁用/重置）——按业务文案 400，
			// 不累加失败计数（不是验证码错误，也不锁账户）。
			services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "MFA 未启用"), c.ClientIP())
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: verr.Error()})
			return
		}
		if verr != nil {
			// 查询/写库故障不是「验证码错误」——不审计验证码错误、
			// 不累加挑战级/账户级失败计数（否则基础设施抖动会烧掉挑战额度
			// 并把用户锁 10 分钟）。
			services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验证服务故障"), c.ClientIP())
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
			return
		}
		services.RecordAuditLog(user.Username, "认证拒绝", "用户认证", services.FormatAuditDetail("MFA", "验证码错误"), c.ClientIP())
		// 历史问题：挑战级失败计数——分布式 IP 限流绕过下对单挑战的爆破收敛
		//（10 次作废，需重新走密码步取新挑战）。
		_ = services.MFARecordChallengeFailure(req.MFAToken)
		// 统一登录失败计数（开关语义见 recordLoginFailure）。
		recordLoginFailure(userID)
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "验证码错误"})
		return
	}
	// 完整登录成功：清零登录失败计数与锁定（密码步未清零，见 Login 注释）。
	// 已验证的登录不因此撤销 JWT，但清零失败必须留痕，避免旧计数无声残留。
	if _, err := db.DB.Exec("UPDATE users SET login_failed_attempts=0, login_locked_until=NULL WHERE id=?", userID); err != nil {
		services.Logf("warn", "MFA 登录成功清零登录失败计数与锁定失败: user_id=%d: %v", userID, err)
	}
	h.respondLoginWithMFA(c, user, passwordVersion, time.Now().Unix(), true)
}

// —— 自助端点（JWT）——

// MFAStatus GET /auth/mfa/status
func (h *Handlers) MFAStatus(c *gin.Context) {
	userID := int(contextUserID(c))
	st, err := services.MFAGetStatus(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 MFA 状态失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: st})
}

// MFASetup POST /auth/mfa/setup — 生成 pending secret + otpauth URI（未启用）。
// 历史问题：已启用 MFA 的用户重新 setup 需当前有效验证码确认（守卫验码放行
// 或本层验码，见下）——此前无任何门：持被劫持会话即可静默轮换第二因子
// （setup 响应明文返回新 secret + URI，攻击者配好自己的 authenticator 后
// activate 即夺取 MFA；受害者未启用场景则被强开攻击者控制的 MFA = 永久
// 登录 DoS）。未启用用户保持无门（首次绑定的可用性优先，会话本身已过密码
// 认证）。登录后不再有密码输入要求（2026-09 用户裁定），原注释
// 的「密码+验证码双重确认」已过时。
// rejectOIDCUserMFAOperation v2.3.0 用户裁定:OIDC 用户与本地 MFA 体系完全
// 解耦——对其禁止本地 MFA 的启用/激活/禁用/重置(身份保证在 IdP 侧)。
// targetUserID=0 表示操作自己(从 JWT 取)。
func rejectOIDCUserMFAOperation(c *gin.Context, targetUserID int) bool {
	uid := targetUserID
	if uid == 0 {
		uid = int(contextUserID(c))
	}
	var provider string
	if err := db.DB.QueryRow("SELECT COALESCE(auth_provider,'local') FROM users WHERE id=?", uid).Scan(&provider); err != nil {
		// ErrNoRows=目标用户不存在(输入错误,404);真实读故障才是 500。
		// 两者都必须拒绝操作——身份来源不可判定时不按非 OIDC 放行。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
			return true
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户身份失败"})
		return true
	}
	if provider == "oidc" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "OIDC 用户不支持本地 MFA（身份验证由认证服务承担）"})
		return true
	}
	return false
}

// mfaVerifyFailureResponse 收敛「登录后验码失败」的响应与审计口径（历史修复，
// 历史）：verr != nil = 查询/写库故障 → 500（不把底层 SQL 错误文本透给
// 客户端、也不写「验证码错误」误导排障）；verr == nil = 真验证码错误 → 调用方
// 既有审计文案 + 401。四处入口（重绑/禁用/step-up/管理员重置）共用，与 Login
// 的 历史修复 及 MFAActivate 已确立的三态口径一致。
func mfaVerifyFailureResponse(c *gin.Context, verr error, failureDetail string) {
	if errors.Is(verr, services.ErrMFANotEnabled) {
		// 业务态（用户未启用/已被并发禁用）：400 业务文案，与 MFAActivate 的
		// 三态口径一致（哨兵→400、真码错→401、基础设施故障→500）。
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: verr.Error()})
		return
	}
	if verr != nil {
		recordAudit(c, "认证拒绝", "用户认证", services.FormatAuditDetail("验证服务故障", services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
		return
	}
	recordAudit(c, "认证拒绝", "用户认证", failureDetail)
	c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "验证码错误"})
}

// mfaInternalFailure 收敛 MFA 写端点的「基础设施故障」响应：固定
// 文案 + 服务端日志留痕，不把底层 SQL 错误文本透给客户端——与
// mfaVerifyFailureResponse / Login 已确立的三态口径一致；业务态错误由调用方
// 按哨兵错误映射 400，不走此路径。
func mfaInternalFailure(c *gin.Context, op string, err error) {
	services.Logf("error", "MFA %s 失败: %v", op, err)
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 操作失败，请稍后重试"})
}

func (h *Handlers) MFASetup(c *gin.Context) {
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardAuthJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var mfaEnabled bool
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&mfaEnabled); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 MFA 状态失败"})
		return
	}
	if mfaEnabled {
		// 2026-09 用户裁定：登录后不再有密码输入要求——重绑仅验当前有效验证码
		//（历史问题 的验码确认保留；验码失败只提示不计数，全系统唯一锁定为
		// 登录阶段 5 次/10 分钟、受「登录失败锁定」开关控制）。
		var req struct {
			Code string `json:"code"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
			return
		}
		// 历史问题(历史问题 同形对齐):守卫验码放行路径跳过本层验码(同 MFADisable)。
		if !mfaStepUpVerifiedInContext(c) {
			if ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now()); !ok {
				mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("重绑 MFA 前验证失败", services.AuditResultPart("failure")))
				return
			}
		}
	}
	// otpauth 账号位用用户名（services/mfa.go 约定 accountName 即用户名；
	// jwtAuth/apiKeyAuth 均注入 c username）——此前用数字 ID，所有用户的
	// Authenticator 条目都显示「LazyBalancer:1」不可区分。空值回退数字 ID 保可用。
	username := c.GetString("username")
	if username == "" {
		username = strconv.FormatInt(contextUserID(c), 10)
	}
	secret, uri, err := services.MFAGenerateSecret(username)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成 MFA 密钥失败"})
		return
	}
	// 单条 UPDATE 原子落库（新密钥 + 失败计数清零同生共死）——此前
	// 两段写（先清后设）在首成次败时已返回 200+secret 而 pending 为空，用户
	// 扫码后 activate 必报「没有待激活的 MFA 密钥」，且两语句间存在瞬时空窗。
	if _, err := db.DB.Exec("UPDATE users SET mfa_pending_secret=?, mfa_pending_fails=0 WHERE id=?", secret, userID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 MFA 密钥失败"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"secret": secret, "uri": uri}})
}

// MFAActivate POST /auth/mfa/activate — 验证当前码 → 启用 + 恢复码（仅此一次明文）。
func (h *Handlers) MFAActivate(c *gin.Context) {
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardAuthJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if ok, verr := services.MFAVerifyPending(userID, req.Code, time.Now()); !ok {
		if verr != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "MFA 验证服务暂时不可用，请稍后重试"})
			return
		}
		// 历史问题：pending 码失败计数——VerifyPending 无锁定无限流（loginRateLimit
		// 只挂公开路由），持会话者可对 10^6 码空间暴力；5 次失败作废 pending（重新
		// setup 才能再试），与挑战级计数同为与全局开关无关的硬闸。
		if invalidated := services.MFARecordPendingFailure(userID); invalidated {
			c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "验证码错误次数过多，绑定已作废，请重新开始绑定"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "验证码错误，请确认 Authenticator 时间同步后重试"})
		return
	}
	services.MFAClearPendingFailures(userID)
	codes, err := services.MFAActivate(userID)
	if err != nil {
		if errors.Is(err, services.ErrMFANoPendingSecret) || errors.Is(err, services.ErrMFASecretChanged) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
		mfaInternalFailure(c, "激活", err)
		return
	}
	recordAudit(c, "启用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "MFA 已启用", Data: gin.H{"recovery_codes": codes}})
}

// MFADisable POST /auth/mfa/disable — 确认有效验证码后禁用（2026-09 用户裁定：
// 登录后无密码输入；验码失败只提示不计数，唯一锁定在登录阶段）。
func (h *Handlers) MFADisable(c *gin.Context) {
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardAuthJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 历史问题(历史,历史问题,历史问题 同形对齐):守卫验码放行路径(标记在)跳过
	// 本层验码——守卫/verify-step 已消费 TOTP 时间片,前端 428 重试带同码时
	// 同片重放拒绝使禁用流程结构性必 401;机器身份/守卫关(无标记)本层验码保持。
	if !mfaStepUpVerifiedInContext(c) {
		if ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now()); !ok {
			// 历史修复 高敏动作的失败尝试与成功同等可审计（对齐 MFAResetByAdmin 前置验码失败留痕）。
			mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("禁用 MFA 前验证失败", services.AuditResultPart("failure")))
			return
		}
	}
	if err := services.MFAResetForUser(userID); err != nil {
		mfaInternalFailure(c, "禁用", err)
		return
	}
	recordAudit(c, "禁用", "用户认证", services.FormatAuditDetail("MFA", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "MFA 已禁用"})
}

// MFARecoveryCodes POST /auth/mfa/recovery-codes — 重生成恢复码（2026-09 用户
// 裁定：登录后不再有密码输入要求，JWT 会话即确认；会话安全为信任边界）。
// 历史问题（历史）：补 OIDC 门——五个 MFA 写入口仅此一处缺席，与
// setup/activate/disable 同为自助端点，targetUserID=0（操作自己，从 JWT 取）。
func (h *Handlers) MFARecoveryCodes(c *gin.Context) {
	if rejectOIDCUserMFAOperation(c, 0) {
		return
	}
	if !guardAuthJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var enabled bool
	// 历史问题（历史）：DB 读失败不得并入「MFA 未启用」400——
	// 基础设施故障 500，业务态未启用保持 400。
	if err := db.DB.QueryRow("SELECT COALESCE(mfa_enabled,0) FROM users WHERE id=?", userID).Scan(&enabled); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 MFA 状态失败"})
		return
	}
	if !enabled {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "MFA 未启用"})
		return
	}
	// 原地重写（旧码全部作废）
	codes, err := services.MFARegenerateRecoveryCodes(userID)
	if err != nil {
		mfaInternalFailure(c, "重生成恢复码", err)
		return
	}
	// 历史修复（2026-09-05 审计裁定）：恢复码重生成是纯会话门下「旧码全作废+明文
	// 下发 10 个登录可用凭证」的高敏动作——成功留痕，与禁用/重置 MFA 同密度。
	recordAudit(c, "生成", "恢复码", services.FormatAuditDetail("MFA", "旧恢复码全部作废", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "恢复码已重新生成（旧码全部作废）", Data: gin.H{"recovery_codes": codes}})
}

// MFAVerifyStep POST /auth/mfa/历史修复 — 验证码 → 新 JWT（mfa_ts 刷新）。
func (h *Handlers) MFAVerifyStep(c *gin.Context) {
	if !guardAuthJSONBody(c) {
		return
	}
	userID := int(contextUserID(c))
	var req struct {
		Code string `json:"code" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	if ok, verr := services.MFAVerifyTOTPCode(userID, req.Code, time.Now()); !ok {
		mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("MFA", "step-up 验证失败"))
		return
	}
	// 重签 JWT：保留原身份声明，仅刷新 mfa_ts（与 respondLogin 同构；node_mode 重读）
	var user models.User
	var passwordVersion int64
	// 历史问题（历史）：重读用户的 DB 错误不得并入 401「用户不可用」
	// ——基础设施故障 500；行缺失/禁用保持 401（JWT 仍有效但账号已不可用）。
	// 历史修复（历史）：重读列必须含 auth_provider（COALESCE 与登录路径同
	// 口径）——漏列会让所有 step-up 响应的 auth_provider 变成 ""，且存量
	// OIDC 行（mfa_enabled=1）在 verify-step 成功后丢掉 auth_method=oidc 声明
	// （middleware 的 MFA 门短路与集群票据直通依赖该声明）。
	if err := db.DB.QueryRow(`SELECT id, username, role, display_name, is_enabled, created_at, last_login, password_version, COALESCE(auth_provider,'local') FROM users WHERE id=?`, userID).
		Scan(&user.ID, &user.Username, &user.Role, &user.DisplayName, &user.IsEnabled, &user.CreatedAt, &user.LastLogin, &passwordVersion, &user.AuthProvider); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户信息失败"})
		return
	}
	if !user.IsEnabled {
		c.JSON(http.StatusUnauthorized, models.APIResponse{Code: 401, Message: "用户不可用"})
		return
	}
	h.respondLoginWithMFA(c, user, passwordVersion, time.Now().Unix(), false)
}

// —— 写操作 step-up 判定（路由守卫与 handler 内联副本的单源）——

// step-up 判定的两类基建故障：判定逻辑只有一份，失败口径由调用方按各自裁定
// 保留（路由守卫 fail-open + warn 留痕；特权 Key 创建 fail-closed 500）。
var (
	ErrMFAStepUpGuardUnreadable = errors.New("MFA 写操作验证开关读取失败")
	ErrMFAStepUpStateUnreadable = errors.New("MFA 状态查询失败")
)

// mfaStepUpGraceWindow 宽限窗：距上次验码小于该值的写操作静默放行（TOTP 同片
// 不可重用，零窗会让相邻写操作结构性无码可用）。
const mfaStepUpGraceWindow = 60 * time.Second

// MFAStepUpDecision step-up 判定结果。
type MFAStepUpDecision struct {
	// Applies 请求属于 step-up 覆盖面（JWT 身份 + 守卫开 + 用户启用 MFA）。
	Applies bool
	// Verified 宽限窗内已验证（守卫据此置 mfa_stepup_verified 标记）。
	Verified bool
	// SecondsAgo 距上次验证的整秒数（响应头 X-Mfa-Verified-Seconds-Ago）。
	SecondsAgo int64
}

// DecideMFAStepUp 判定请求是否需要 MFA step-up 及是否已在宽限窗内通过。
// 调用方按自身路由语义给出 covered（守卫：写方法/敏感导出 GET；特权 API Key
// 创建：固定 true），其余短路条件必须单源——任一侧漏掉 OIDC 会话短路或只读
// 语义写路由豁免，就是 428 误弹码/二因子旁路。
// mfaEnabledCheck 由调用方注入（守卫保留测试注入点）。
func DecideMFAStepUp(c *gin.Context, covered bool, mfaEnabledCheck func(int) (bool, error)) (MFAStepUpDecision, error) {
	// 非写操作/非敏感 GET，或机器身份（API Key/MCP）——无 MFA 概念。
	if !covered || c.GetString("auth_type") != "jwt" {
		return MFAStepUpDecision{}, nil
	}
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}
	// step-up 机制本体（verify-step）与登出不得要求验码，否则 428→验码→再 428
	// 死锁；只读语义 POST（批量查询/测试/预览）与只读 API Key 同一事实源豁免。
	if path == "/api/v1/auth/mfa/verify-step" || path == "/api/v1/auth/logout" {
		return MFAStepUpDecision{}, nil
	}
	if services.IsReadOnlyWriteRoute(c.Request.Method, path) {
		return MFAStepUpDecision{}, nil
	}
	// OIDC 会话与本地 MFA 体系完全解耦（身份保证在 IdP），DB 查询前显式短路。
	if c.GetString("auth_method") == "oidc" {
		return MFAStepUpDecision{}, nil
	}
	guardEnabled, err := services.MFAWriteGuardEnabled()
	if err != nil {
		return MFAStepUpDecision{}, fmt.Errorf("%w: %v", ErrMFAStepUpGuardUnreadable, err)
	}
	if !guardEnabled {
		return MFAStepUpDecision{}, nil
	}
	userID, ok := mfaStepUpUserID(c)
	if !ok {
		return MFAStepUpDecision{}, nil
	}
	mfaEnabled, err := mfaEnabledCheck(userID)
	if err != nil {
		return MFAStepUpDecision{}, fmt.Errorf("%w: %v", ErrMFAStepUpStateUnreadable, err)
	}
	if !mfaEnabled {
		// 本地未绑 MFA 保持直通。
		return MFAStepUpDecision{}, nil
	}
	mfaTs := c.GetFloat64("mfa_ts")
	elapsed := time.Since(time.Unix(int64(mfaTs), 0))
	if mfaTs > 0 && elapsed < mfaStepUpGraceWindow {
		return MFAStepUpDecision{Applies: true, Verified: true, SecondsAgo: int64(elapsed.Seconds())}, nil
	}
	return MFAStepUpDecision{Applies: true}, nil
}

// mfaStepUpUserID 类型化读取 JWT 用户 ID（jwtAuth 存 float64；测试/MCP 路径
// 可能存 int/int64/string）——gin GetString 对数字恒返回空串，不得用。
func mfaStepUpUserID(c *gin.Context) (int, bool) {
	v, exists := c.Get("user_id")
	if !exists {
		return 0, false
	}
	switch id := v.(type) {
	case float64:
		return int(id), true
	case int:
		return id, true
	case int64:
		return int(id), true
	case string:
		parsed, err := strconv.Atoi(id)
		if err != nil {
			return 0, false
		}
		return parsed, true
	}
	return 0, false
}

// —— Admin 端点 ——

// mfaStepUpVerifiedInContext:守卫(开启态)验码放行路径的标记优先;开关
// 关闭或机器身份时守卫未运行,无标记,本层验码保持(历史问题:消除
// handler 重读开关的毫秒窗 TOCTOU——开关在中间件后翻转不再产生
// 「守卫未验码+本层跳过」的免验窗口)。历史问题(MFAResetByAdmin)起用,
// 历史问题(历史)提升为包级供 MFA 自助写端点(禁用/重绑确认)复用。
func mfaStepUpVerifiedInContext(c *gin.Context) bool {
	v, ok := c.Get("mfa_stepup_verified")
	return ok && v == true
}

// MFAResetByAdmin POST /users/:id/mfa/reset — 仅 admin 组可达（middleware.go
// 路由门）；本人自助解绑请用 POST /auth/mfa/disable。重置需确认 + 校验——操作者
// 自己启用了 MFA 时须提供有效验证码（防会话劫持后一键拆第二因子）。请求体
// 可选 {code}。
func (h *Handlers) MFAResetByAdmin(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的用户 ID"})
		return
	}
	if rejectOIDCUserMFAOperation(c, id) {
		return
	}
	if !guardAuthJSONBody(c) {
		return
	}
	operatorID := int(contextUserID(c))
	var req struct {
		Code string `json:"code"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误"})
		return
	}
	// 操作者自己启用 MFA → 必须验码（本人重置自己的 MFA 也一样——与
	// MFADisable 的双重确认同语义；无密码项：admin 路由已过 JWT + 用户管理
	// 确认弹框承担意图确认）。
	// 历史问题（用户裁决）：写操作守卫（mfaStepUpGuard）开启时第一层豁免——守卫已对
	// 本写操作完成验码（60 秒窗内静默放行或 428→verify-step 刷新 mfa_ts），再验
	// 一次会在 TOTP 重放保护下同片互斥：verify-step 消费时间片后第一层无码可用，
	// 必 401（验证码错误→踢出登录→连续失败触发 10 分钟锁定）。
	// mfaStepUpVerifiedInContext:守卫(开启态)验码放行路径的标记优先;开关
	// 关闭或机器身份时守卫未运行,无标记,本层验码保持(历史问题:消除
	// handler 重读开关的毫秒窗 TOCTOU——开关在中间件后翻转不再产生
	// 「守卫未验码+本层跳过」的免验窗口)。
	// 历史问题 补正（审计 问题-3）：守卫真正验过码的只有 JWT 路径——mfaStepUpGuard
	// 按设计豁免 auth_type != "jwt"，API Key/MCP 机器身份不被守卫验码，豁免理由
	// 不成立，故不免第一层（历史问题 二次防劫持语义对机器身份同样保持）。守卫关闭
	// 或请求为机器身份时才走本层验码——此时守卫均不参与、无双重消费，重放保护
	// 照旧。
	if operatorMfa, err := services.MFAUserEnabled(operatorID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取操作者 MFA 状态失败"})
		return
	} else if operatorMfa && !mfaStepUpVerifiedInContext(c) {
		if ok, verr := services.MFAVerifyCode(operatorID, req.Code, time.Now()); !ok {
			// 历史问题 七次：重置前置验码失败留痕——高敏动作的失败尝试与成功同等
			// 可审计（含 brute 尝试面）。
			mfaVerifyFailureResponse(c, verr, services.FormatAuditDetail("重置 MFA 前验证失败", services.AuditResultPart("failure")))
			return
		}
	}
	var target string
	if err := db.DB.QueryRow("SELECT username FROM users WHERE id=?", id).Scan(&target); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "用户不存在"})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取用户失败"})
		return
	}
	if err := services.MFAResetForUser(id); err != nil {
		mfaInternalFailure(c, "管理员重置", err)
		return
	}
	// 历史问题：detail 同时写目标用户与操作者（username 列即操作者；本人重置时两者相同，
	// 跨用户重置时 detail 可区分——此前仅「用户 X」在列表中无法判断是自重置还是
	// 管理员代重置）。
	detail := fmt.Sprintf("目标用户 %s", target)
	if operatorName := c.GetString("username"); operatorName != target {
		detail = fmt.Sprintf("目标用户 %s（由 %s 操作）", target, operatorName)
	}
	recordAudit(c, "重置", "用户认证", services.FormatAuditDetail(detail, services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已重置用户 MFA（用户需重新绑定）"})
}
