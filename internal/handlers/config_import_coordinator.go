package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type importPhase string

const (
	importPhaseSnapshot    importPhase = "snapshot"
	importPhaseCertificate importPhase = "certificate"
	importPhaseCaddy       importPhase = "caddy"
	importPhaseVersion     importPhase = "version"
	importPhaseCommit      importPhase = "commit"
	importPhaseQueue       importPhase = "queue"
)

var (
	removeImportRuleLogFiles    = services.RemoveRuleLogFiles
	removeImportCertJobLogFiles = services.RemoveCertJobLogFiles
	cancelImportInFlightRuns    = func() {
		if te := services.TaskEngine(); te != nil {
			te.CancelInFlightRuns()
		}
	}
)

type importCoordinatorError struct {
	phase         importPhase
	err           error
	caddyRejected bool
	// action 是本次操作的动作词（「导入」/「还原」）：失败描述的动作前缀必须
	// 跟随调用方语义——自动备份还原失败文案曾恒写「导入失败」，与审计动作
	// 「还原失败」形成双前缀且误导排障。
	action string
}

func (err *importCoordinatorError) actionLabel() string {
	if err.action == "" {
		return "导入"
	}
	return err.action
}

func (err *importCoordinatorError) Error() string { return importFailureAuditDescription(err) }
func (err *importCoordinatorError) Unwrap() error { return err.err }

// importFailurePhaseDescription 返回与动作词无关的阶段判定（审计 detail、
// HTTP 文案共用单源）。空串=未知阶段。
//
// 「数据库未变更」的适用边界：除 commit 阶段外的中止都在事务回滚后收尾，
// 库内容确定未变；commit 阶段的失败结果不可判定（数据库/sql 在 Commit 报错
// 时无法区分「未提交」与「已提交但确认丢失」），文案必须如实表述为
// 「提交结果不确定」，不得断言未变更。
func importFailurePhaseDescription(phase importPhase, caddyRejected bool) string {
	switch phase {
	case importPhaseSnapshot:
		return "运行配置快照失败，数据库未变更"
	case importPhaseCertificate:
		return "证书准备失败，数据库未变更"
	case importPhaseCaddy:
		if caddyRejected {
			return "Caddy 验证失败，数据库未变更"
		}
		return "Caddy 应用失败，数据库未变更"
	case importPhaseVersion:
		return "集群版本更新失败，数据库未变更"
	case importPhaseCommit:
		return "数据库提交结果不确定"
	case importPhaseQueue:
		return "数据库已提交，证书任务恢复失败"
	}
	return ""
}

// importFailureAuditDescription 返回带动作前缀的失败描述（*importCoordinatorError
// 的 Error() 与「无动作上下文的调用点」共用；有动作上下文的审计 detail 用
// importFailureAuditDetail，避免动作词重复）。
func importFailureAuditDescription(err error) string {
	var coordinatorErr *importCoordinatorError
	if !errors.As(err, &coordinatorErr) {
		return "导入失败：" + err.Error()
	}
	phase := importFailurePhaseDescription(coordinatorErr.phase, coordinatorErr.caddyRejected)
	if phase == "" {
		return coordinatorErr.actionLabel() + "失败：" + coordinatorErr.err.Error()
	}
	if coordinatorErr.phase == importPhaseQueue {
		return coordinatorErr.actionLabel() + "部分失败（" + phase + "）：" + coordinatorErr.err.Error()
	}
	return coordinatorErr.actionLabel() + "失败（" + phase + "）：" + coordinatorErr.err.Error()
}

// importFailureAuditDetail 返回审计 detail：auditAction 已携带「导入/还原失败」
// 前缀，detail 不再重复动作词（消双前缀），只描述阶段与真实错误。
func importFailureAuditDetail(err error) string {
	var coordinatorErr *importCoordinatorError
	if !errors.As(err, &coordinatorErr) {
		return err.Error()
	}
	phase := importFailurePhaseDescription(coordinatorErr.phase, coordinatorErr.caddyRejected)
	if phase == "" {
		return coordinatorErr.err.Error()
	}
	return phase + "：" + coordinatorErr.err.Error()
}

type configImportSession struct {
	h               *Handlers
	ctx             context.Context
	tx              *sql.Tx
	recovery        importQueueRecovery
	existingRuleIDs []string
	// action 是本次会话的动作词（「导入」/「还原」，由调用方在建会话后立即
	// 写入）：commit 阶段错误必须携带该动作，失败文案/审计才不把还原写成导入。
	action                string
	runtime               *importRuntimeSnapshot
	runtimeApplyAttempted bool
	finished              bool
	// resumeEngine 恢复任务引擎 tick 派发
	// beginConfigImport 期间 PauseScheduling，会话 close 时恢复——不能用作
	// begin 函数的 defer（该函数在导入体执行前就返回）。
	resumeEngine func()
	// releaseBeforeLock 释放排空之后、caddyOpMu/事务之前取得的资源锁
	// （配置导入的 WAF 文件锁）。close 在 caddyOpMu 之后释放，
	// 保持与获取顺序相反的锁序。
	releaseBeforeLock func()
	// replaceRuleArtifacts 标记本次导入是否替换了规则/证书任务数据面。
	// 仅此情形才允许清理「消失规则」与「失效证书任务」——users-only 等
	// 分类导入必须对 live 的 cert_jobs/证书文件零触碰。
	replaceRuleArtifacts bool
}

// errCertQueueDrainIncomplete 证书队列排空未完成：PauseAndDrain
// 超时后仍有执行中的签发任务——此时开始导入会让证书任务与全量替换并发，
// 明确拒绝（409）而非沿用「已排干」假设。
var errCertQueueDrainIncomplete = errors.New("证书任务执行中，请稍后重试")
var errImportTaskDrainIncomplete = errors.New("在途任务未排空，请稍后重试")

// importInFlightDrainTimeout 导入前排空在途任务的有界等待（历史
// 审计）：与证书队列 PauseAndDrain 的 30s 屏障同量级。自此超时
// fail-closed 拒绝导入（部分 Run 体不消费取消信号），恢复调度并留失败审计，
// 不再让旧任务与全量替换并发。
var importInFlightDrainTimeout = 30 * time.Second

// configImportBeginMu 串行化整个导入会话
// Pause/Resume 是单布尔位，若两个导入都先 Pause 再抢 caddyOpMu，先结束者
// Resume 会让后者在调度已恢复的状态下执行。此锁覆盖 Pause→事务→close，
// 后到导入在暂停开始前排队。
var configImportBeginMu sync.Mutex

// 测试屏障（生产恒 nil）：分别在会话锁获取前与业务 prelock 获取前触发，
// 供锁序测试用通道证明到达点，替代固定 sleep。
var configImportBeginAttemptHook func()
var configImportBeforePrelockHook func()

// configImportBusy 探测导入会话是否持有全局导入锁（不阻塞）：启停/控制
// 常驻任务在导入期间必须 409，避免绕过 PauseAndDrain。
func configImportBusy() bool {
	if configImportBeginMu.TryLock() {
		configImportBeginMu.Unlock()
		return false
	}
	return true
}

// rejectNodeWriteDuringImport：配置导入窗口内
// 节点写端点（注册/审批/拒绝/删除/改访问地址/改站点坐标/清 pin/节点上报等）
// 一律 409 fast-fail。导入事务全量替换 nodes 表：窗口内的节点写入要么被
// 导入覆盖（静默丢失），要么阻塞在 SQLite 写锁上至 busy_timeout（30s）后
// 500——两种形态都比干净 409 差。与 taskmonitor 的调度开关门共用
// configImportBusy 探测，文案同族。
func rejectNodeWriteDuringImport(c *gin.Context) bool {
	return rejectWriteDuringImport(c, "执行节点写操作")
}

// rejectWriteDuringImport 导入窗口内通用写端点快筛。
// 证书配置表（certificate_configs）与 CA 提供商表（ca_providers）都在导入全量
// 替代表清单内：排空结束、导入事务尚未开启的窗口内提交会被导入静默覆盖
// （数据丢失），事务开启后提交则阻塞至 busy_timeout(30s) 后 500。与节点写族
// 同口径 409。证书配置 Create/Update/Delete 与 CA 提供商写端点全族均走本门；
// Update/Delete 虽取 caddyOpMu，但锁只保证串行不提供 fast-fail——排队到导入
// 提交后按陈旧 id 落库同样会改写导入结果，故门必须在取锁之前。
func rejectWriteDuringImport(c *gin.Context, action string) bool {
	if !configImportBusy() {
		return false
	}
	c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "配置导入进行中，暂不能" + action})
	return true
}

// action 是本次会话的动作词（「导入」/「还原」）——排空失败等建会话前的审计
// 也要带正确动作，不能一律记「导入失败」（自动备份还原路径同样走本函数）。
func (h *Handlers) beginConfigImport(ctx context.Context, action string) (*configImportSession, error) {
	return h.beginConfigImportWithPrelock(ctx, prelockNone, action)
}

// prelockNone 显式表达「无预锁」——与「有预锁」区分，避免调用方误传 nil 顺序
// 参数造成可读性歧义。
func prelockNone() func() { return nil }

// beginConfigImportWithPrelock 在 Pause/Cancel/Wait 排空完成之后、取
// caddyOpMu 与开启事务之前调用 prelock（返回释放函数）。配置导入用它把
// WAF 文件锁放在排空之后：先取锁会让阻塞在 wafFileMu 的更新任务无法被取消。
func (h *Handlers) beginConfigImportWithPrelock(ctx context.Context, prelock func() func(), action string) (*configImportSession, error) {
	if action == "" {
		action = "导入"
	}
	if configImportBeginAttemptHook != nil {
		configImportBeginAttemptHook()
	}
	configImportBeginMu.Lock()
	releaseSession := func() { configImportBeginMu.Unlock() }
	// 导入将全量替换业务数据——先暂停 tick
	// 派发并取消在途 Scheduled/Periodic/Oneshot Run（Daemon 不在范围），再有界
	// 等待其在途落定，避免其提交落在导入事务之后形成 last-writer-wins。
	// 此前只发取消信号不等待：不消费 rc.Ctx 的 Run 体会在导入期间继续跑完。
	//
	// 顺序铁律（Fix81Inf 复核）：Pause/Cancel/Wait 必须在取 caddyOpMu
	// **之前**。autoban 的 RunAutobanCycle 在 services.CaddyOpLock（=caddyOpMu）
	// 临界区内合并名单；若先持锁再等待，会形成「导入持锁等 Run 退出 ↔ Run 等
	// 锁」的互等到 30s 超时，且该 Run 仍会在导入提交后写库。Pause/Cancel/Wait
	// 不改库，无原子性损失；并发第二个导入同样先排空再阻塞在锁上（无害）。
	engine := services.TaskEngine()
	resumeEngine := func() {}
	if engine != nil {
		engine.PauseScheduling()
		resumeEngine = func() { engine.ResumeScheduling() }
	}
	cancelImportInFlightRuns()
	if engine != nil {
		drainCtx, cancel := context.WithTimeout(context.Background(), importInFlightDrainTimeout)
		drained := engine.WaitInFlightRuns(drainCtx)
		cancel()
		if !drained {
			services.Logf("warn", "配置导入：等待在途任务落定超时（%s），已中止导入", importInFlightDrainTimeout)
			// 审计词条必须是字面量（词汇门禁校验）：按动作分支各写一次。
			drainDetail := "在途任务未排空，导入未执行（配置未修改）"
			if action == "还原" {
				drainDetail = "在途任务未排空，还原未执行（配置未修改）"
				services.RecordAuditLog("system", "还原失败", "配置备份", drainDetail, "")
			} else {
				services.RecordAuditLog("system", "导入失败", "配置备份", drainDetail, "")
			}
			// 与 close 同序：先恢复本代暂停，再允许下一代导入进入。
			resumeEngine()
			releaseSession()
			return nil, errImportTaskDrainIncomplete
		}
	}
	// CA 队列 PauseAndDrain 必须先于 caddyOpMu——在途
	// 证书部署需要 CaddyOpLock（部署临界区入口即取锁，
	// certissuer.go deployIssuedCertificate/快速路径）；旧顺序「先持锁再排空」
	// 形成自锁：部署 worker 等锁、导入等排空，30s 后必然 409。与上方任务引擎
	// 「先排空再取锁」铁律同序。排空在 WAF 预锁之前，避免持 WAF 锁阻塞更新任务。
	recovery := importQueueRecovery{manager: services.GetCAQueueManager()}
	if recovery.manager != nil {
		recovery.wasActive = recovery.manager.IsActive()
		// 屏障先于排空建立（粘性 hold）：排空完成后常驻 cert-issuance 的
		// 有界重拉/角色对账仍可能经 StartACME 重开队列——hold 期间 Start/
		// Resume 只登记意图，导入结束由 recovery.finish 统一兑现。
		recovery.hold = true
		services.BeginConfigImportHold()
		// 排空结果必须被消费——未完全排空（30s 超时仍有执行中任务）
		// 不得继续导入。
		if !recovery.manager.PauseAndDrain() {
			// 先解除 hold 再恢复队列/释放会话锁——否则第二个导入可在锁窗口
			// 内看到「队列 inactive」并在第一个导入 Resume 后与之并发。
			recovery.hold = false
			services.EndConfigImportHold()
			if recovery.wasActive {
				recovery.manager.Resume()
			}
			resumeEngine()
			releaseSession()
			return nil, errCertQueueDrainIncomplete
		}
	}
	releaseBeforeLock := releaseSession
	if prelock != nil {
		if configImportBeforePrelockHook != nil {
			configImportBeforePrelockHook()
		}
		if release := prelock(); release != nil {
			releaseBeforeLock = func() {
				release()
				releaseSession()
			}
		}
	}
	releaseBegin := func() {
		h.caddyOpMu.Unlock()
		resumeEngine()
		releaseBeforeLock()
	}
	h.caddyOpMu.Lock()
	session := &configImportSession{h: h, ctx: ctx, recovery: recovery, resumeEngine: resumeEngine, releaseBeforeLock: releaseBeforeLock, action: action}
	ruleIDs, err := currentRuleIDs(ctx)
	if err != nil {
		// CA 已暂停：必须在释放会话锁之前恢复既有活动态——否则第二个导入可
		// 在窗口内把「队列 inactive」当作稳定状态，随后与本导入的 Resume 并发。
		err = finishImportFailure(nil, &session.recovery, fmt.Errorf("读取现有规则: %w", err))
		releaseBegin()
		return nil, err
	}
	session.existingRuleIDs = ruleIDs
	session.tx, err = db.DB.BeginTx(ctx, nil)
	if err != nil {
		err = finishImportFailure(nil, &session.recovery, err)
		releaseBegin()
		return nil, fmt.Errorf("开始导入事务: %w", err)
	}
	return session, nil
}

// respondImportBeginError 导入会话建立失败的统一响应：排空未完成 → 409
// （可重试语义），其余（读规则/开事务）→ 500。
func respondImportBeginError(c *gin.Context, err error) {
	if errors.Is(err, errCertQueueDrainIncomplete) || errors.Is(err, errImportTaskDrainIncomplete) {
		c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: err.Error()})
		return
	}
	c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
}

func (session *configImportSession) close() {
	if !session.finished {
		_ = session.abort(errors.New("导入流程未完成"))
	}
	session.h.caddyOpMu.Unlock()
	// 导入全程（含失败 abort 的恢复动作）结束后
	// 先恢复 tick，再释放串行会话锁。反向释放会让下一代导入的 Pause 被
	// 本代 Resume 覆盖，破坏 Pause→事务→close 的串行排空不变量。
	if session.resumeEngine != nil {
		session.resumeEngine()
	}
	if session.releaseBeforeLock != nil {
		session.releaseBeforeLock()
	}
}

func (session *configImportSession) abort(importErr error) error {
	if session.finished {
		return importErr
	}
	// 会话内 CLI 预检/强制应用等渲染已按未提交导入内容
	// 重写投影文件——abort 必回滚 tx，磁盘同步回退到已提交态（零 /load；
	// 快照阶段失败等未渲染形态为同字节 no-op）。已持 caddyOpMu（begin 起）。
	session.h.caddyService.RollbackIPListProjectionsToCommittedInLock()
	if session.runtime != nil {
		if session.runtimeApplyAttempted {
			// 事务内 apply 可能已成功写入未提交配置与 LKG。先释放事务写锁，
			// 再以已提交视图重渲染/强制应用：即使恢复 /load 失败，
			// RestoreRuntimeToCommittedInLock 也会把已提交字节写回 LKG。
			certErr := services.RestoreCertFiles(session.runtime.certFiles)
			restoreErr := session.h.recoverCommittedViewAfterCommitFailure(session.tx)
			if restoreErr != nil {
				// 恢复已提交视图失败=运行配置可能停留在导入候选（传输失败
				// 且 Caddy 已应用/恢复 /load 再失败），而 DB 已回滚。LKG 由
				// RestoreRuntimeToCommittedInLock 钉回已提交字节，但横幅事实
				// 源此前为空——刷新页面后分叉完全不可见。与规则域 apply 失败
				// 同口径持久化失败横幅。
				session.h.recordCaddyApplyFailure(fmt.Errorf("导入失败后恢复已提交运行配置失败: %w", restoreErr), restoreErr)
			}
			importErr = errors.Join(importErr, certErr, restoreErr)
			session.finished = true
			return finishImportFailure(session.tx, &session.recovery, importErr)
		}
		if restoreErr := session.h.restoreImportRuntime(*session.runtime); restoreErr != nil {
			importErr = errors.Join(importErr, fmt.Errorf("恢复运行配置失败: %w", restoreErr))
		}
	}
	session.finished = true
	return finishImportFailure(session.tx, &session.recovery, importErr)
}

func (session *configImportSession) commit(affectedRuleIDs []string, certificates []importCertificate) error {
	runtime, err := session.h.snapshotImportRuntime(affectedRuleIDs)
	if err != nil {
		return &importCoordinatorError{phase: importPhaseSnapshot, err: session.abort(err), action: session.action}
	}
	session.runtime = &runtime
	if err := materializeImportCertificates(certificates); err != nil {
		return &importCoordinatorError{phase: importPhaseCertificate, err: session.abort(err), action: session.action}
	}
	// v2 导入事务全量重插 cert_jobs（restoreTable 保留原 id），证书
	// 候选必须读事务自身——经已提交视图会拿到将被替换的旧行，旧 PEM 覆写导入
	// 刚落盘的新证书文件。导入期 CA 队列已 PauseAndDrain，无并发证书提交。
	// 导入强制重载——证书已在上方落盘，生成期比对相等，
	// 非强制会被 errSameConfig 短路（旧证书继续服务）。

	// 2026-09-06 裁定 ④' 边界补齐：导入同样过 Caddy CLI 校验层（校验输入=
	// 事务视图渲染）。校验器不可用放行——下方 ApplyConfigFromTxCertAwareForce
	// 仍是门控（全有全无）。
	// rulesWrittenInTx=true：导入事务可能重插 lb_rules（含新 acme 规则），
	// 谓词 miss 补查必须开启（证书候选源为已提交视图时新规则会被子查询排除）。
	if err := session.h.caddyService.ValidateTxRenderViaCLI(session.tx, true); err != nil && !errors.Is(err, services.ErrCLIValidatorUnavailable) {
		return &importCoordinatorError{phase: importPhaseCaddy, err: session.abort(err), caddyRejected: services.IsConfigRejected(err), action: session.action}
	}
	session.runtimeApplyAttempted = true
	appliedConfig, applyErr := session.h.caddyService.ApplyConfigFromTxCertAwareForce(session.tx)
	if applyErr != nil {
		return &importCoordinatorError{phase: importPhaseCaddy, err: session.abort(applyErr), caddyRejected: services.IsConfigRejected(applyErr), action: session.action}
	}
	if err := services.BumpClusterVersion(session.ctx, session.tx); err != nil {
		return &importCoordinatorError{phase: importPhaseVersion, err: session.abort(err), action: session.action}
	}
	if err := session.tx.Commit(); err != nil {
		return &importCoordinatorError{phase: importPhaseCommit, err: session.abort(err), action: session.action}
	}
	// commit 成功后才落 last-known-good（事务内 apply 有意不写），字节即
	// 刚被 Caddy 接受的候选——导入的 LKG 因此恒为已提交视图。
	session.h.caddyService.PersistLastGoodBytesInLock(appliedConfig)
	session.runtime = nil
	// /全量替换导入对消失规则的产物清理。v2/v1 导入均清光
	// lb_rules 后重插（v1 还换新 caddy_id），但产物轴此前只写不删：消失规则的
	// 证书文件（含 ACME 私钥）在 /app/certs 无限残留——与 DeleteRule「规则消失
	// → 密钥删除」的约定矛盾，卷读权限者可恢复管理员以为已删除的密钥；v1 路径
	// 还遗留指向已删 caddy_id 的孤儿 cert_jobs 行（终态行永不清理，任务列表
	// 噪音）。提交成功后按 begin 期收集的 existingRuleIDs 求差清理（v2 的
	// 事务内孤儿 SQL 幂等重复无害）。清理失败不否决导入（数据已提交），
	// 留痕审计 + 日志。
	session.cleanupDisappearedRuleArtifacts()
	if err := session.recovery.finish(); err != nil {
		session.finished = true
		return &importCoordinatorError{phase: importPhaseQueue, err: err, action: session.action}
	}
	session.finished = true
	return nil
}

func importFailurePhase(err error) importPhase {
	var coordinatorErr *importCoordinatorError
	if errors.As(err, &coordinatorErr) {
		return coordinatorErr.phase
	}
	return ""
}

func importFailureCaddyRejected(err error) bool {
	var coordinatorErr *importCoordinatorError
	return errors.As(err, &coordinatorErr) && coordinatorErr.phase == importPhaseCaddy && coordinatorErr.caddyRejected
}

// cleanupDisappearedRuleArtifacts 清理本次导入中消失规则的产物
// 证书文件、孤儿 cert_jobs 行、指标与规则/证书日志。提交成功后调用；失败仅
// 审计留痕，不否决导入。
func (session *configImportSession) cleanupDisappearedRuleArtifacts() {
	if !session.replaceRuleArtifacts {
		return
	}
	currentIDs, err := currentRuleIDs(session.ctx)
	if err != nil {
		services.Logf("error", "导入清理：读取当前规则失败（跳过孤儿清理）: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理消失规则产物失败（读取规则集）：%v", err), "")
		return
	}
	current := make(map[string]struct{}, len(currentIDs))
	for _, id := range currentIDs {
		current[id] = struct{}{}
	}
	var disappeared []string
	for _, id := range session.existingRuleIDs {
		if _, alive := current[id]; !alive {
			disappeared = append(disappeared, id)
		}
	}
	if len(disappeared) == 0 {
		// 无消失规则仍可能有「规则仍在但失去证书材料」的清理（导入事务
		// 剪枝只动 DB 行）——跳过消失规则段，继续下方任务行与材料清理。
	} else {
		for _, id := range disappeared {
			if err := services.RemoveCertFiles(id); err != nil {
				services.Logf("warn", "导入清理：删除消失规则 %s 的证书文件失败: %v", id, err)
			}
			if db.MetricsDB != nil {
				if _, err := db.MetricsDB.ExecContext(session.ctx, "DELETE FROM metrics_history WHERE rule_id=?", id); err != nil {
					services.Logf("error", "导入清理：删除消失规则 %s 的指标失败: %v", id, err)
				}
			}
			removeImportRuleLogFiles(id)
			if err := removeImportCertJobLogFiles(id); err != nil {
				services.Logf("error", "导入清理：删除消失规则 %s 的证书日志失败: %v", id, err)
				services.RecordAuditLog("system", "清理失败", "证书日志", fmt.Sprintf("导入后清理规则 %s 的证书日志失败：%v", id, err), "")
			}
		}
	}
	// 与 v2 导入事务内的孤儿清理同语句（幂等重复无害）；覆盖 v1 路径与
	// 理论上的绕过路径。
	if _, err := db.DB.ExecContext(session.ctx,
		`DELETE FROM cert_jobs WHERE NOT EXISTS (SELECT 1 FROM lb_rules WHERE lb_rules.caddy_id = cert_jobs.rule_id)`); err != nil {
		services.Logf("error", "导入清理：删除孤儿证书任务失败: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书任务", fmt.Sprintf("导入后清理孤儿证书任务失败：%v", err), "")
		return
	}
	// 规则存在但已非 ACME 自动签发态的失效任务行——与
	// v2 导入事务内同谓词清理；覆盖 v1 路径与理论绕过路径。
	if _, err := db.DB.ExecContext(session.ctx,
		`DELETE FROM cert_jobs WHERE rule_id IN (SELECT caddy_id FROM lb_rules WHERE NOT (enable_tls=1 AND tls_source='acme_dns'))`); err != nil {
		services.Logf("error", "导入清理：删除失效证书任务失败: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书任务", fmt.Sprintf("导入后清理失效证书任务失败：%v", err), "")
		return
	}
	// 上述清理只动 DB——仍存在但已失去全部可用证书材料的规则（切 manual
	// 无证/关 TLS/导入行不再带 ACME 材料），其 ACME cert/key 文件会滞留
	// 数据卷（与 DeleteRule/orphanACME「失去材料即删私钥」约定不对称，
	// 卷读权限者可恢复管理员以为已丢弃的密钥）。按同一约定 best-effort 清理：
	// 失败仅 warn+审计，不否决已提交的导入。
	if cleaned := cleanupRulesWithoutUsableCertMaterial(session.ctx); cleaned > 0 {
		services.RecordAuditLog("system", "清理", "证书产物", fmt.Sprintf("导入后 %d 条规则已无任何可用证书材料，其残留证书文件已清理", cleaned), "")
	}
	if len(disappeared) > 0 {
		services.RecordAuditLog("system", "清理", "证书产物", fmt.Sprintf("导入移除 %d 条规则，已清理其证书文件、任务行、指标与日志", len(disappeared)), "")
	}
}

// cleanupRulesWithoutUsableCertMaterial 清理「仍存在但已无任何可用证书材料」
// 规则的 ACME 证书/私钥文件：手动证书材料在库（tls_source=manual 且
// cert/key 非空）或有域名适用的任务材料时跳过。返回实际执行了文件清理的规则数
// （幂等 best-effort，单规则失败仅告警留痕）。
//
// 查询面固定为两条（规则集 + 材料行集）并在内存中配对：原实现逐规则 2 次查询
// （域名 + 任务材料）是 N+1，千级规则导入在持 caddyOpMu 的提交窗口里放大 2N 次
// DB 往返，把配置写/重载全部阻塞在该窗口。
func cleanupRulesWithoutUsableCertMaterial(ctx context.Context) int {
	rows, err := db.DB.QueryContext(ctx,
		`SELECT caddy_id, COALESCE(tls_source,''), COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(domain,'') FROM lb_rules`)
	if err != nil {
		services.Logf("error", "导入清理：读取规则证书形态失败（跳过材料清理）: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理无材料规则证书文件失败（读取规则集）：%v", err), "")
		return 0
	}
	type ruleCertShape struct {
		id        string
		tlsSource string
		domain    string
		hasManual bool
	}
	var rules []ruleCertShape
	for rows.Next() {
		var rule ruleCertShape
		var tlsCert, tlsKey string
		if err := rows.Scan(&rule.id, &rule.tlsSource, &tlsCert, &tlsKey, &rule.domain); err != nil {
			services.Logf("error", "导入清理：读取规则行失败: %v", err)
			continue
		}
		rule.hasManual = rule.tlsSource == "manual" && strings.TrimSpace(tlsCert) != "" && strings.TrimSpace(tlsKey) != ""
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		services.Logf("error", "导入清理：遍历规则失败: %v", err)
	}
	rows.Close()

	// 一次取全部「持有可用材料」的任务行（谓词单源：非 disabled + PEM 非空，
	// 与渲染候选/启动物化/文件对账同语义）。
	materialByRule := make(map[string][]string)
	materialRows, err := db.DB.QueryContext(ctx, `SELECT rule_id, COALESCE(domain,'') FROM cert_jobs
		WHERE `+services.CertJobMaterialPredicateSQL(""))
	if err != nil {
		// 判定面不可读时不得按「无材料」清理（会误删仍在服务的证书文件）。
		services.Logf("error", "导入清理：查询任务材料失败（跳过材料清理）: %v", err)
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理无材料规则证书文件失败（读取任务材料集）：%v", err), "")
		return 0
	}
	for materialRows.Next() {
		var ruleID, jobDomain string
		if err := materialRows.Scan(&ruleID, &jobDomain); err != nil {
			continue
		}
		materialByRule[ruleID] = append(materialByRule[ruleID], jobDomain)
	}
	if err := materialRows.Err(); err != nil {
		services.Logf("error", "导入清理：遍历任务材料失败（跳过材料清理）: %v", err)
		materialRows.Close()
		services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理无材料规则证书文件失败（遍历任务材料集）：%v", err), "")
		return 0
	}
	materialRows.Close()

	cleaned := 0
	for _, rule := range rules {
		if rule.hasManual {
			continue
		}
		// 域名适用性复核（旧域残留行不算可用材料）——与 certJobRuleApplicable
		// 同语义：两侧均须可规范化且规范形式全等。
		usable := 0
		ruleCanonical, ruleErr := services.CanonicalACMEDomains(rule.domain)
		if ruleErr == nil {
			for _, jobDomain := range materialByRule[rule.id] {
				if jobCanonical, jobErr := services.CanonicalACMEDomains(jobDomain); jobErr == nil && jobCanonical == ruleCanonical {
					usable++
					break
				}
			}
		}
		if usable > 0 {
			continue
		}
		if err := services.RemoveCertFiles(rule.id); err != nil {
			services.Logf("warn", "导入清理：删除无材料规则 %s 的证书文件失败: %v", rule.id, err)
			services.RecordAuditLog("system", "清理失败", "证书产物", fmt.Sprintf("导入后清理规则 %s 的残留证书文件失败：%v", rule.id, err), "")
			continue
		}
		cleaned++
	}
	return cleaned
}
