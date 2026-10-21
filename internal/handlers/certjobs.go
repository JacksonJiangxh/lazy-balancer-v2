package handlers

import (
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var certJobOperationLocks [64]sync.Mutex

// retryCertJobPreEnqueueHook 是测试专用钩子：在 SELECT 状态之后、EnqueueIfActive
// 内 UPDATE 之前触发，用于模拟 worker 侧并发状态流转（历史问题 发现4 回归测试）。
var retryCertJobPreEnqueueHook func(jobID int)

// deleteCertJobPreDisableHook 是测试专用钩子：在 DeleteCertJob 的状态 SELECT/守卫
// 之后、disabled 翻转 UPDATE 之前触发，用于模拟 worker 侧并发状态流转（历史问题
// 回归测试）。
var deleteCertJobPreDisableHook func(jobID int)

// deleteCertJobPreRestoreHook 是测试专用钩子：DELETE 失败后、状态恢复 UPDATE
// 之前触发，用于模拟「行在删除窗口内被并发移离 disabled」（历史问题 回归测试）。
var deleteCertJobPreRestoreHook func(jobID int)

// certJobLogPathForRule 解析规则的任务日志路径（测试缝：镜像 cancelCertJob 的
// var 先例，测试可重定向到临时目录；生产恒为 services.CertJobLogPath）。
var certJobLogPathForRule = services.CertJobLogPath

var cancelCertJob = func(id int) {
	if qm := services.GetCAQueueManager(); qm != nil {
		qm.CancelJob(id)
	}
}

// certJobLogMaxRotatedBackups 对齐 services/certjoblog.go 的 maxRotatedFiles=5
// （.1 最新 → .5 最旧）；写侧未来扩大保留数时读侧须同步调整。
const certJobLogMaxRotatedBackups = logRotatedBackups

const maxCertJobPage int64 = 1_000_000

func certJobOperationLock(id int) *sync.Mutex {
	index := id % len(certJobOperationLocks)
	if index < 0 {
		index += len(certJobOperationLocks)
	}
	return &certJobOperationLocks[index]
}

func (h *Handlers) ListCertJobs(c *gin.Context) {
	ruleID := c.Query("rule_id")
	page, err := strconv.ParseInt(c.DefaultQuery("page", "1"), 10, 64)
	if err != nil || page < 1 || page > maxCertJobPage {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("page 必须为 1-%d 之间的整数", maxCertJobPage)})
		return
	}
	pageSize, err := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	if err != nil || pageSize < 1 || pageSize > 200 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "page_size 必须在 1-200 之间"})
		return
	}
	if page-1 > math.MaxInt64/int64(pageSize) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "page 超出可查询范围"})
		return
	}
	offset := (page - 1) * int64(pageSize)
	whereClause := ""
	var filterArgs []interface{}
	if ruleID != "" {
		whereClause = " WHERE j.rule_id = ?"
		filterArgs = append(filterArgs, ruleID)
	}
	var total int64
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM cert_jobs j"+whereClause, filterArgs...).Scan(&total); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务失败"})
		return
	}
	statusCounts := map[string]int64{}
	statusRows, err := db.DB.Query("SELECT j.status, COUNT(*) FROM cert_jobs j"+whereClause+" GROUP BY j.status", filterArgs...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务状态失败"})
		return
	}
	for statusRows.Next() {
		var status string
		var count int64
		if err := statusRows.Scan(&status, &count); err != nil {
			statusRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务状态失败"})
			return
		}
		statusCounts[status] = count
	}
	if err := statusRows.Err(); err != nil {
		statusRows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计证书任务状态失败"})
		return
	}
	statusRows.Close()
	var expiryDays int
	// 历史修复（历史）：字面量 30 → db.DefaultCertExpiryDays 绑定参数（caddy.go
	// 历史修复 形态，库值唯一真相单源）。
	if err := db.DB.QueryRow("SELECT COALESCE(cert_expiry_days,?) FROM global_config WHERE id=1", db.DefaultCertExpiryDays).Scan(&expiryDays); err != nil {
		// 历史问题（2026-09-05 证书域审计裁定）：展示阈值的读取失败不得放大为整个
		// 任务列表 500——降级治理默认并告警，对齐 历史问题 的
		// checkManualCertExpiration 口径。
		services.Logf("error", "ListCertJobs: read cert_expiry_days failed, using default %d: %v", db.DefaultCertExpiryDays, err)
		expiryDays = db.DefaultCertExpiryDays
	}
	// 历史问题(历史):cert_pem 只取首证书块——certificateIssuer 仅
	// 解析首块,全链(LE ~6KB)全量传输纯属浪费;INSTR 定位首个 END 边界,
	// 空串/单块形态 SUBSTR 原样返回(与全量读取行为一致)。
	query := `SELECT j.id, j.rule_id, j.domain, j.status, COALESCE(j.message,'') AS message,
		CASE WHEN INSTR(j.cert_pem,'-----END CERTIFICATE-----') > 0
		     THEN SUBSTR(j.cert_pem, 1, INSTR(j.cert_pem,'-----END CERTIFICATE-----') + 25)
		     ELSE COALESCE(j.cert_pem,'') END AS cert_pem,
		j.expires_at, j.created_at, j.updated_at, COALESCE(j.renewal_attempts,0) AS renewal_attempts, j.ca_available_after, COALESCE(j.last_error_code,'') AS last_error_code, COALESCE(j.ca_provider_id,0) AS ca_provider_id, COALESCE(p.name,'') AS ca_provider_name FROM cert_jobs j LEFT JOIN ca_providers p ON p.id = j.ca_provider_id`
	query += whereClause
	args := append([]interface{}{}, filterArgs...)
	query += " ORDER BY j.created_at DESC LIMIT ? OFFSET ?"
	args = append(args, pageSize, offset)

	rows, err := db.DB.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to query cert jobs"})
		return
	}
	defer rows.Close()

	type certJobListItem struct {
		ID                   int                 `json:"id"`
		RuleID               string              `json:"rule_id"`
		Domain               string              `json:"domain"`
		CAProviderID         int                 `json:"ca_provider_id"`
		CAProviderName       string              `json:"ca_provider_name,omitempty"`
		Status               string              `json:"status"`
		Message              string              `json:"message"`
		Issuer               string              `json:"issuer"`
		DaysRemaining        int                 `json:"days_remaining"`
		CertificateStatus    string              `json:"certificate_status"`
		RenewalAttempts      int                 `json:"renewal_attempts,omitempty"`
		CAAvailableAfter     models.JSONNullTime `json:"ca_available_after,omitempty"`
		LastErrorCode        string              `json:"last_error_code,omitempty"`
		ExpiresAt            models.JSONNullTime `json:"expires_at"`
		CreatedAt            time.Time           `json:"created_at"`
		UpdatedAt            models.JSONNullTime `json:"updated_at"`
		RetryCooldownSeconds *int64              `json:"retry_cooldown_seconds"`
	}
	jobs := make([]certJobListItem, 0, pageSize)
	now := time.Now()
	for rows.Next() {
		var j certJobListItem
		var certPEM string
		if err := rows.Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &certPEM,
			&j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.RenewalAttempts, &j.CAAvailableAfter, &j.LastErrorCode, &j.CAProviderID, &j.CAProviderName,
		); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
			return
		}
		if cooldown, retryable := certJobRetryCooldown(j.Status); retryable {
			seconds := int64(cooldown / time.Second)
			j.RetryCooldownSeconds = &seconds
		}
		j.Issuer = certificateIssuer(certPEM)
		j.CertificateStatus = "unknown"
		if j.ExpiresAt.Valid {
			// 历史：剩余天数收敛 CertDaysRemaining 单源；历史问题（历史）：
			// 状态判定收敛 CertificateExpiryStatus（天粒度——原 `<= days*24h`
			// 纳秒口径与 certinfo 截断天数在阈值 +1m 处结论分叉）。
			j.DaysRemaining = services.CertDaysRemaining(j.ExpiresAt.Time, now)
			j.CertificateStatus = services.CertificateExpiryStatus(j.ExpiresAt.Time, now, expiryDays)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
		return
	}
	c.Header("X-Page", strconv.FormatInt(page, 10))
	c.Header("X-Page-Size", strconv.Itoa(pageSize))
	c.Header("X-Total", strconv.FormatInt(total, 10))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"list": jobs, "total": total, "page": page, "page_size": pageSize, "status_counts": statusCounts}})
}

// GetCurrentCertJobs returns the latest non-disabled job per requested rule so
// polling does not depend on offset pagination (which drifts under inserts).
func (h *Handlers) GetCurrentCertJobs(c *gin.Context) {
	var req struct {
		RuleIDs []string `json:"rule_ids"`
	}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求格式错误: " + err.Error()})
		return
	}
	if len(req.RuleIDs) > 200 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "invalid_request：rule_ids 数量不能超过 200"})
		return
	}
	result := make(map[string]*models.CertJob, len(req.RuleIDs))
	for _, id := range req.RuleIDs {
		result[id] = nil
	}
	if len(req.RuleIDs) == 0 {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
		return
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(req.RuleIDs)), ",")
	args := make([]interface{}, len(req.RuleIDs))
	for i, id := range req.RuleIDs {
		args[i] = id
	}
	rows, err := db.DB.QueryContext(c.Request.Context(), `SELECT j.id, j.rule_id, j.domain, COALESCE(j.ca_provider_id,0), COALESCE(p.name,''), j.status, COALESCE(j.message,''), COALESCE(j.renewal_attempts,0), j.ca_available_after, COALESCE(j.last_error_code,''), j.expires_at, j.created_at, j.updated_at
		FROM cert_jobs j LEFT JOIN ca_providers p ON p.id = j.ca_provider_id
		WHERE j.rule_id IN (`+placeholders+`) AND j.status <> 'disabled'
		ORDER BY j.rule_id, j.created_at DESC, j.id DESC`, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "查询证书任务失败"})
		return
	}
	defer rows.Close()
	for rows.Next() {
		var job models.CertJob
		if err := rows.Scan(&job.ID, &job.RuleID, &job.Domain, &job.CAProviderID, &job.CAProviderName, &job.Status, &job.Message, &job.RenewalAttempts, &job.CAAvailableAfter, &job.LastErrorCode, &job.ExpiresAt, &job.CreatedAt, &job.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
			return
		}
		if result[job.RuleID] == nil {
			result[job.RuleID] = &job
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取证书任务失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: result})
}

func certificateIssuer(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ""
	}
	if len(cert.Issuer.Organization) > 0 && cert.Issuer.Organization[0] != "" {
		return cert.Issuer.Organization[0]
	}
	return cert.Issuer.CommonName
}

func (h *Handlers) RetryCertJob(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	h.retryCertJobByID(c, id)
}

// retryCertJobByID 重试入队核心（2026-10-11 抽取）：RetryCertJob 端点与
// TriggerSystemTask 的 cert-job 行触发分支共用——用户裁定 cert-job 行视为
// 触发任务（可自动调度即可手动调度，证书可重签发）。
func (h *Handlers) retryCertJobByID(c *gin.Context, id int) {
	// 历史问题-01（历史）：导入窗口门与任务监控 toggle/control 同源。
	// 导入会话持 db.DB 写事务直至 commit，且 CA 队列已 PauseAndDrain——此处的
	// UPDATE（部署窗推进/重入队）要么阻塞在 SQLite 写锁上到 busy_timeout 后
	// 500，要么提交后落到已被全量替换的 cert_jobs 行上，绕过导入的暂停/排空
	// 契约。409 fast-fail（拒绝重试是幂等可重试语义，不改变任何任务状态），
	// 两个入口（RetryCertJob / TriggerSystemTask 的 cert-job 分支）共用本核心。
	if configImportBusy() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "配置导入进行中，暂不能重试证书任务"})
		return
	}
	operationLock := certJobOperationLock(id)
	operationLock.Lock()
	defer operationLock.Unlock()
	var ruleID, domain, status string
	var caProviderID int
	var updatedAt, createdAt sql.NullTime
	err := db.DB.QueryRow("SELECT rule_id, domain, status, updated_at, created_at, COALESCE(ca_provider_id,0) FROM cert_jobs WHERE id=?", id).Scan(&ruleID, &domain, &status, &updatedAt, &createdAt, &caProviderID)
	if dbQueryNotFound(c, err, "任务不存在", "RetryCertJob query job") {
		return
	}

	if blocked, statusCode, message := certJobRetryBlocked(status, updatedAt, createdAt, time.Now()); blocked {
		c.JSON(statusCode, models.APIResponse{Code: statusCode, Message: message})
		return
	}

	// 历史问题（历史）：downloaded + 材料在库的任务停在部署窗口——转 queued
	// 会丢弃已签发证书并触发整轮重签（同 requeueCanceledJob / DeleteCertJob
	// 恢复 / requeueCertJobsSnapshot 的取向）。改为把部署窗口推到 now 并立即
	// 重排部署重试；仅「无材料」的 downloaded（历史脏行）才回落重新签发。
	if rescheduled, err := rescheduleDownloadedCertJobDeployment(id, ruleID, domain); err != nil {
		if errors.Is(err, services.ErrCertificateDeploymentRetryBusy) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "上一次部署回调仍在退出中，已登记自动部署，稍后自动执行"})
			return
		}
		if errors.Is(err, services.ErrCertificateQueueInactive) {
			status, message := certEnqueueErrorResponse("部署重试未触发", err)
			// 历史问题（历史）：失败响应必须点明 DB 真实状态——部署窗口已
			// 推进到 now，服务恢复后补扫会自动部署（不是「什么都没发生」）。
			message += "；已登记自动部署，恢复后自动执行"
			c.JSON(status, models.APIResponse{Code: status, Message: message})
			return
		}
		services.Logf("error", "Manual deployment retry failed for job %d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to enqueue retry; 已登记自动部署，稍后自动执行"})
		return
	} else if rescheduled {
		recordAudit(c, "重试", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status), services.AuditResultPart("deployment_retry")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Deployment retry triggered"})
		return
	}

	qm := services.GetCAQueueManager()
	if qm == nil {
		services.Logf("error", "Manual retry enqueue failed for job %d: CA queue manager not initialized", id)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA queue manager not initialized"})
		return
	}
	// cert_jobs.domain 按排序后的规范形式存储，而 lb_rules.domain 保留用户输入顺序，
	// 规则侧用 joined+reversed 双形式匹配（ACME 域名至多根域+www 两个）。
	reversedDomain := reversedCertJobDomain(domain) // 历史修复-新4:复用同文件 helper
	if retryCertJobPreEnqueueHook != nil {
		retryCertJobPreEnqueueHook(id)
	}
	_, changed, err := qm.EnqueueIfActive(caProviderID, id, ruleID, domain, func() (int, bool, error) {
		result, err := db.DB.Exec(`UPDATE cert_jobs
			SET status='queued', message='重新排队签发', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now')
			WHERE id=? AND status=? AND EXISTS (
				SELECT 1 FROM lb_rules
				WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
			)`, id, status, ruleID, domain, reversedDomain)
		if err != nil {
			return id, false, err
		}
		rowsAffected, err := result.RowsAffected()
		return id, rowsAffected != 0, err
	})
	if err != nil {
		services.Logf("error", "Manual retry enqueue failed for job %d: %v", id, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to enqueue retry"})
		return
	}
	if !changed {
		// SELECT(:254) 与 UPDATE 之间状态可能被 worker 流转（如 failed→creating_account），
		// 导致 0 行影响；此时归因是并发竞争而非规则禁用，重读当前状态区分文案（历史问题 发现4）。
		var currentStatus string
		scanErr := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&currentStatus)
		if errors.Is(scanErr, sql.ErrNoRows) {
			// 历史问题：行被并发删除（DeleteRule/DeleteCertJob）时归因 404 而非 500
			// （对齐 DeleteCertJob 历史问题 的三分归因）。
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
			return
		}
		if scanErr != nil {
			// 重读失败属瞬时 DB 错误（SQLITE_BUSY 等），归因为规则禁用会误导用户，
			// 显式区分 500（历史问题）。
			services.Logf("error", "RetryCertJob reread job %d status failed: %v", id, scanErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取任务状态失败"})
			return
		}
		if currentStatus != status {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务状态已变更，请刷新后重试"})
			return
		}
		// 历史问题：EnqueueIfActive 的在途命中（历史问题 发现2）同样走 !changed 且重读
		// 状态未变，需优先归因"任务正在队列中"，避免误导为规则禁用/配置变更。
		if qm.IsJobActive(id) {
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务正在签发队列中，请勿重复操作"})
			return
		}
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务关联规则已禁用、证书配置已变更或队列已暂停"})
		return
	}
	// 历史问题-05：手动重试入队成功=有在途证书工作——唤醒 cert-waiting-ca
	// （默认调度关闭，waiting_ca 冷却重排/滞留重入队的唯一属主；此前重试
	// 绕过单点唤醒，任务滞留至 cert-reconcile 周期至多 6h）。
	// 历史问题：入队成功即真实工作，唤醒入口不重查活跃态（队列可能已快速失败）。
	services.WakeCertWaitingCAForEnqueuedJob()
	recordAudit(c, "重试", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status), services.AuditResultPart("queued")))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Retry triggered"})
}

// rescheduleDownloadedCertJobDeployment 处理 downloaded 任务的「部署重排」快速
// 路径：仅当任务仍为 downloaded、证书材料在库且关联规则仍处自动签发状态时，
// 把部署窗口推到 now 并触发证书服务补扫（取消挂起的退避 timer → 立即部署）。
// 返回 false 表示不适用（无材料/状态已变/规则失效），调用方回落重新入队语义。
func rescheduleDownloadedCertJobDeployment(id int, ruleID, domain string) (bool, error) {
	reversedDomain := reversedCertJobDomain(domain)
	result, err := db.DB.Exec(`UPDATE cert_jobs
		SET deployment_available_after=datetime('now'), message='手动重试：等待恢复部署', updated_at=datetime('now')
		WHERE id=? AND status='downloaded'
		  AND COALESCE(cert_pem,'') <> '' AND COALESCE(key_pem,'') <> ''
		  AND EXISTS (
			SELECT 1 FROM lb_rules
			WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
		  )`, id, ruleID, domain, reversedDomain)
	if err != nil {
		return false, err
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if rowsAffected == 0 {
		return false, nil
	}
	// deployment_available_after=now 仍可供服务恢复后的补扫接管；但只有实际
	// 登记了立即 timer 才允许上层报告「已触发」，停止/忙状态必须返回 409。
	if err := services.RetryCertificateDeploymentNow(id, ruleID); err != nil {
		// 历史问题（历史）：立即 timer 登记失败时上方 UPDATE 已把消息写成
		// 「手动重试：等待恢复部署」，与 409/500 响应矛盾（报文说失败、DB 说
		// 已重排）。窗口推进保留（启动恢复/周期补扫会接手，可用性收益不变），
		// 文案改为如实描述自动接管；响应侧同步点明「已登记自动部署」。
		if _, updateErr := db.DB.Exec(`UPDATE cert_jobs SET message=?, updated_at=datetime('now') WHERE id=? AND status='downloaded'`, "手动重试未触发，等待自动部署", id); updateErr != nil {
			return true, errors.Join(err, updateErr)
		}
		return true, err
	}
	return true, nil
}

// certJobRetryCooldown 是重试冷却的唯一策略源；列表 API 直接下发该值，
// certJobRetryBlocked 复用同一判定执行服务端门禁。
func certJobRetryCooldown(status string) (time.Duration, bool) {
	switch status {
	case "disabled":
		return 0, false
	case "issued", "waiting_ca":
		return 0, true
	case "queued":
		return 15 * time.Minute, true
	case "failed":
		return 5 * time.Minute, true
	default:
		return 2 * time.Minute, true
	}
}

// certJobRetryBlocked 返回任务是否被重试门拦截，以及应返回的 HTTP 状态码。
// 429 =「稍后重试可成功」（执行中/冷却），409 =「永久条件不可重试」（已退役）。
func certJobRetryBlocked(status string, updatedAt, createdAt sql.NullTime, now time.Time) (bool, int, string) {
	cooldown, retryable := certJobRetryCooldown(status)
	if !retryable {
		// 历史问题（历史）：永久条件不得用 429（SDK/前端会按限流退避轮询）。
		return true, http.StatusConflict, "已退役的证书任务不能重试"
	}
	// 历史问题（历史）：cert_jobs.updated_at 在 DDL 中可空（历史行/带外插入可
	// 为 NULL），此前 NULL 直接放行冷却门（fail-open）——连点可连续绕过 15/5
	// 分钟冷却、放大 CA 配额消耗。回退 created_at 计算；两列都缺失时 fail-
	// closed（视为刚更新，按冷却拒绝），避免不可归因的即时重试。
	reference := updatedAt
	if !reference.Valid {
		reference = createdAt
	}
	if cooldown == 0 || (reference.Valid && now.Sub(reference.Time) >= cooldown) {
		return false, 0, ""
	}
	if status == "failed" {
		return true, http.StatusTooManyRequests, "失败后请等待 5 分钟再重试"
	}
	message := "任务正在执行中，请稍后重试"
	// 历史修复（历史）：downloaded 态签发已完成（证书在库），停在部署
	// 退避窗口——复用在途文案会误导用户以为签发流程卡住，单列部署口径。
	// 历史问题（历史）：冷却到期后再点重试 = 立即重排部署（不重签）。
	if status == "downloaded" {
		message = "证书已下载完成，正在等待部署生效；稍后可重试以立即重新部署（不会重新签发）"
	}
	return true, http.StatusTooManyRequests, message
}

// reversedCertJobDomain 交换双域名任务的域名顺序：cert_jobs.domain 存排序
// 规范形式，lb_rules.domain 保留用户输入顺序，匹配需同时覆盖两种排列。
// 历史修复（历史）：单源收敛至 services.ReversedCertJobDomain（与
// rules.reversedACMEDomainForm 同实现，两侧委托）。
func reversedCertJobDomain(domain string) string {
	return services.ReversedCertJobDomain(domain)
}

// certJobDeleteGuard 返回该状态任务在关联规则仍处自动签发状态时是否受 409
// 守卫及对应文案。disabled 是已退出自动签发链的唯一可删除状态；其余状态
// 一律默认受守卫，避免新增在途状态时再次形成断链旁路。
func certJobDeleteGuard(status string) (bool, string) {
	switch status {
	case "disabled":
		return false, ""
	case "issued", "downloaded":
		return true, "该任务持有有效证书且关联规则仍在自动签发状态，删除后自动续签将中断且无法自动恢复；请先禁用规则或切换证书来源后再删除"
	case "failed", "waiting_ca", "queued":
		return true, "该任务仍在自动签发链中（等待签发或等待重试），且关联规则仍在自动签发状态，删除后自动签发将中断且无法自动恢复；请先禁用规则或切换证书来源后再删除"
	default:
		return true, "该任务仍在自动签发链中（正在执行或清理 DNS），且关联规则仍在自动签发状态，删除后自动签发将中断且无法自动恢复；请先禁用规则或切换证书来源后再删除"
	}
}

func (h *Handlers) DeleteCertJob(c *gin.Context) {

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	// 历史问题 C-发现3 TOCTOU：历史修复 守卫读规则 enabled 状态后、删除前，EnableRule
	// （持 caddyOpMu）可完成启用并恢复任务，守卫放行被竞态绕过。caddyOpMu
	// 覆盖 查询→守卫→disabled 翻转→删除 全程（取消已移出，CERT 历史问题 见下），
	// 与 EnableRule 互斥：
	// 删除先完成则 EnableRule 查不到任务行，走 EnableCertJobCreate 重建
	// （续签链不断）；EnableRule 先完成则守卫读到 enabled=1 返回 409。
	// 不变量（历史问题 修正）：'disabled' 对 worker 是终态——所有 worker 侧
	// transitionJob 的 from 列表均排除 'disabled'，翻转后不会被周期路径复活。
	// caqueue.EnqueueIfActive 的调用方并非全部持锁：RetryCertJob 持
	// certJobOperationLock；本函数失败恢复、规则写路径与手工签发
	// （IssueCertificate，历史问题 起定向/批量两分支全程持 caddyOpMu）持
	// caddyOpMu；四个周期路径（requeueStrandedJobs/requeueWaitingCAJobs/
	// requeueNonTerminalCertJobs/renewExpiringCertificates）无锁调用——其
	// UPDATE 均按旧状态 CAS 或 from 列表排除 'disabled'，与翻转交错时命中
	// 0 行（先于翻转→翻转 CAS 失败；翻转后→0 行；删除后→行不存在），
	// 语义自洽。
	// CERT 历史问题（历史）：caddyOpMu 覆盖 查询→守卫→disabled 翻转
	// →删除 全程（历史问题 C-发现3 TOCTOU 不变量保持——与 EnableRule 互斥域不变，
	// 翻转与 DELETE 仍同一临界区）；在途取消等待（qm.CancelJob ≤30s）移出
	// 临界区（见下方取消点注释），本函数改手动配对解锁。
	h.caddyOpMu.Lock()
	operationLock := certJobOperationLock(id)
	operationLock.Lock()
	// 历史问题（历史）：per-job 锁改为手动配对——失败恢复分支必须在不持有
	// operationLock 的前提下重取 caddyOpMu（锁序铁律：先 caddyOpMu 后
	// operationLock，见恢复点注释），defer 只能通过本闭包释放。
	operationLockHeld := true
	releaseOperationLock := func() {
		if operationLockHeld {
			operationLock.Unlock()
			operationLockHeld = false
		}
	}
	defer releaseOperationLock()
	var ruleID, domain, status, certPEM, keyPEM string
	var caProviderID int
	if err := db.DB.QueryRow("SELECT rule_id, domain, status, COALESCE(ca_provider_id,0), COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs WHERE id = ?", id).Scan(&ruleID, &domain, &status, &caProviderID, &certPEM, &keyPEM); err != nil {
		h.caddyOpMu.Unlock()
		dbQueryNotFound(c, err, "Job not found", "DeleteCertJob query job")
		return
	}
	// 历史问题 + 历史问题 + 历史问题-02：规则仍在自动签发状态时，删除任何未退役
	// 任务都会让纯周期路径失去续签/签发入口（CreateOrRequeueCertJob 仅由规则
	// 写路径调用），因此 issued/downloaded、等待态、在途执行态与 cleanup_* 全部
	// 409 显式拒绝；运维可先禁用规则或切换证书来源后再删除。disabled 为退役
	// 终态，删除即清理。中断卡死尝试应使用重试/禁用规则流程，而不是删除唯一
	// 任务行。
	// 已知竞态（历史问题）：DeleteRule drain 超时后的后台补偿（不持
	// caddyOpMu）在退避窗口内按规则快照 DELETE+INSERT 恢复 cert_jobs，
	// 可能复活窗口内被本函数删除的行——恢复是保守选择（复活行来自规则自身
	// 快照时代，续签链保持完整；退避有界，窗口过后可再次删除）。
	if guarded, message := certJobDeleteGuard(status); guarded {
		var active int
		if err := db.DB.QueryRow(`SELECT COUNT(1) FROM lb_rules
			WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns'
			  AND lower(replace(domain,' ','')) IN (?,?)`,
			ruleID, domain, reversedCertJobDomain(domain)).Scan(&active); err != nil {
			h.caddyOpMu.Unlock()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to check rule state"})
			return
		}
		if active > 0 {
			h.caddyOpMu.Unlock()
			c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: message})
			return
		}
	}
	if deleteCertJobPreDisableHook != nil {
		deleteCertJobPreDisableHook(id)
	}
	result, err := db.DB.Exec("UPDATE cert_jobs SET status='disabled', updated_at=datetime('now') WHERE id=? AND status=?", id, status)
	if err != nil {
		h.caddyOpMu.Unlock()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to disable job"})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		h.caddyOpMu.Unlock()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to verify disabled job"})
		return
	}
	if rowsAffected != 1 {
		// 历史问题：SELECT/守卫与 disabled 翻转之间 worker 可能推进状态（历史修复 放行
		// 的在途态），CAS 命中 0 行属并发竞争而非服务器故障——重读区分归因（对齐
		// RetryCertJob 的 409+重读模式）：行仍在 → 409 刷新重试；行已消失 → 404
		// （与本函数 DELETE 后 0 行的缺失语义一致）；重读失败（瞬时 DB 错误）→ 500。
		var currentStatus string
		scanErr := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", id).Scan(&currentStatus)
		if errors.Is(scanErr, sql.ErrNoRows) {
			h.caddyOpMu.Unlock()
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
			return
		}
		if scanErr != nil {
			h.caddyOpMu.Unlock()
			services.Logf("error", "DeleteCertJob reread job %d status failed: %v", id, scanErr)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取任务状态失败"})
			return
		}
		h.caddyOpMu.Unlock()
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务状态已变更，请刷新后重试"})
		return
	}
	// CERT 历史问题（历史）：取消移出全局 CaddyOpLock 临界区——原顺序
	// 翻转→取消→删除使取消的在途等待（qm.CancelJob ≤30s）让全局 Caddy 写
	// 路径排队（与 rules.go:2027 域名迁移同型等待环）。临界区=守卫→翻转→
	// DELETE（历史问题 C-发现3 不变量保持：翻转与 DELETE 同一临界区与 EnableRule
	// 互斥）；顺序对调（删除→取消）依据：worker 全部状态迁移按旧态 CAS 且
	// from 列表排除 'disabled'，删除窗内在途执行不可能复活/改写行；取消先于
	// 失败恢复路径（CancelJob 会清 pending 并取消部署重试——先恢复后取消会把
	// 恢复重入队的条目清掉，恢复语义要求先取消）。per-job operationLock 在
	// 取消等待期间仍持有：等待期间同任务 Retry/重复 Delete 保持互斥；失败
	// 恢复点按 历史问题 锁序（先 caddyOpMu 后 operationLock）释放并按规范顺序重取。
	result, err = db.DB.Exec("DELETE FROM cert_jobs WHERE id = ?", id)
	h.caddyOpMu.Unlock()
	cancelCertJob(id)
	if err != nil {
		deleteErr := err
		// 失败恢复重取 caddyOpMu：恢复写与 EnableRule 的 EnableCertJobCreate
		//（无 CAS 写，历史问题）互斥需持锁；重取窗口内 EnableRule 可见 disabled
		// 行并 Resume——恢复 CAS（status='disabled'）0 行命中→「恢复已跳过」
		// 并入 deleteErr（500 如实呈现，删除本就失败；行存活+启用=一致终态）。
		// 历史问题（历史）：锁序铁律=先 caddyOpMu 后 operationLock（与入口
		// 同序）。此处若在持 operationLock 时反向取 caddyOpMu，与同 id 连点/同桶
		// （id%64）并发删除构成 AB-BA：对方先取到 caddyOpMu 后在桶锁排队 → 双向
		// 互等，且 caddyOpMu 被永久占用（规则/配置写、Caddy 启停、证书部署
		// reload 全部挂起，只能重启进程）。恢复写与 EnableRule 的
		// EnableCertJobCreate（无 CAS 写）互斥仍需 caddyOpMu：先释放 per-job 锁
		// 再按规范顺序重取——窗口内同任务 Retry 对 disabled 恒 409、重复 Delete
		// 走 CAS 0 行的「已被并发移离 disabled」归因，语义自洽。
		releaseOperationLock()
		h.caddyOpMu.Lock()
		operationLock.Lock()
		operationLockHeld = true
		if deleteCertJobPreRestoreHook != nil {
			deleteCertJobPreRestoreHook(id)
		}
		if status == "downloaded" && certPEM != "" && keyPEM != "" {
			// 历史问题（对齐 caqueue requeueCanceledJob 的 历史问题 口径）：持有证书
			// 材料的 downloaded 任务停在部署窗口——转 'queued' 会丢弃已签发证书
			// 并触发整轮重签（Issue 快速路径只认 issued/downloaded）。原地恢复
			// 'downloaded' 并把重试窗口推到 now，Resume 的
			// rescanDroppedDeploymentRetries 会统一重新调度部署。
			// 历史问题（历史）：恢复带 status='disabled' 守卫——行在删除窗口
			// 内被并发移离 disabled 时不得覆写其新状态；命中 0 行并入 deleteErr。
			if res, restoreErr := db.DB.Exec("UPDATE cert_jobs SET status='downloaded', deployment_available_after=datetime('now'), message='删除失败，等待恢复部署', updated_at=datetime('now') WHERE id=? AND status='disabled'", id); restoreErr != nil {
				deleteErr = errors.Join(deleteErr, restoreErr)
			} else if n, _ := res.RowsAffected(); n == 0 {
				deleteErr = errors.Join(deleteErr, fmt.Errorf("任务 %d 已被并发移离 disabled，恢复已跳过", id))
			}
		} else if status == "issued" || status == "failed" {
			// 历史问题：同上方守卫口径。
			if res, restoreErr := db.DB.Exec("UPDATE cert_jobs SET status=?, updated_at=datetime('now') WHERE id=? AND status='disabled'", status, id); restoreErr != nil {
				deleteErr = errors.Join(deleteErr, restoreErr)
			} else if n, _ := res.RowsAffected(); n == 0 {
				deleteErr = errors.Join(deleteErr, fmt.Errorf("任务 %d 已被并发移离 disabled，恢复已跳过", id))
			}
		} else if status == "disabled" {
			// disabled 是唯一「删除不受规则启用门守卫」的终态；删除失败时
			// 行必须保持 disabled（原本已退役），不得改写成 failed 制造幽灵
			// 失败行并触发额外签发（历史）。
		} else {
			qm := services.GetCAQueueManager()
			var restoreErr error
			changed := false
			if qm == nil {
				restoreErr = errors.New("CA queue manager not initialized")
			} else {
				_, changed, restoreErr = qm.EnqueueIfActive(caProviderID, id, ruleID, domain, func() (int, bool, error) {
					updateResult, updateErr := db.DB.Exec(`UPDATE cert_jobs SET status='queued', message='删除失败，重新排队签发', updated_at=datetime('now')
						WHERE id=? AND status='disabled' AND EXISTS (
							SELECT 1 FROM lb_rules WHERE caddy_id=? AND enabled=1 AND enable_tls=1 AND tls_source='acme_dns' AND lower(replace(domain,' ','')) IN (?,?)
						)`, id, ruleID, domain, reversedCertJobDomain(domain))
					if updateErr != nil {
						return id, false, updateErr
					}
					rows, rowsErr := updateResult.RowsAffected()
					return id, rows == 1, rowsErr
				})
			}
			if restoreErr != nil || !changed {
				if restoreErr == nil {
					restoreErr = errors.New("job was not restored to active queue")
				}
				if _, failErr := db.DB.Exec("UPDATE cert_jobs SET status='failed', message='删除失败且恢复队列失败', updated_at=datetime('now') WHERE id=?", id); failErr != nil {
					restoreErr = errors.Join(restoreErr, failErr)
				}
				deleteErr = errors.Join(deleteErr, restoreErr)
			} else {
				// 历史问题-05：删除失败恢复重入队成功=有在途证书工作——唤醒
				// cert-waiting-ca（与 RetryCertJob/CreateOrRequeueCertJobWithChange
				// 同族收敛：全部入队成功路径必须唤醒唯一属主）。
				// 历史问题：恢复重入队成功即真实工作，唤醒不重查活跃态。
				services.WakeCertWaitingCAForEnqueuedJob()
			}
		}
		services.Logf("error", "DeleteCertJob failed for job %d: %v", id, deleteErr)
		h.caddyOpMu.Unlock()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete job"})
		return
	}
	rowsAffected, err = result.RowsAffected()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to verify deleted job"})
		return
	}
	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Job not found"})
		return
	}
	recordAudit(c, "删除", "证书任务", services.FormatAuditDetail(services.AuditJobPart(id), services.AuditRulePart(ruleID), domain, fmt.Sprintf("原状态：%s", status)))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Job deleted"})
}

func (h *Handlers) GetCertJob(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}
	var j models.CertJob
	err = db.DB.QueryRow("SELECT id, rule_id, domain, status, COALESCE(message,'') AS message, expires_at, created_at, updated_at, ca_available_after FROM cert_jobs WHERE id=?", id).
		Scan(&j.ID, &j.RuleID, &j.Domain, &j.Status, &j.Message, &j.ExpiresAt, &j.CreatedAt, &j.UpdatedAt, &j.CAAvailableAfter)
	if dbQueryNotFound(c, err, "Job not found", "GetCertJob query job") {
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: j})
}

func (h *Handlers) GetCertJobLogs(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil || id <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid job ID"})
		return
	}

	var ruleID string
	if err := db.DB.QueryRow("SELECT rule_id FROM cert_jobs WHERE id=?", id).Scan(&ruleID); dbQueryNotFound(c, err, "Cert job not found", "GetCertJobLogs query job") {
		return
	}

	logPath := certJobLogPathForRule(ruleID)
	// 历史问题（2026-09-05 证书域审计裁定）：按旧→新拼接全部轮转备份再加当前文件
	//（.5 最旧 → .1 最新，对齐写侧 maxRotatedFiles=5），每文件保留 128KB/500 行
	// 截断；缺失的备份序号按空跳过。
	content := prependTaskLogRotations(logPath, readCertJobLogFile(logPath), certJobLogMaxRotatedBackups)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": content}})
}

// prependTaskLogRotations 按 maxBackups 把 .1～.N 逐代前置到活动日志
// 内容之前，最终顺序恒为最旧→最新→活动文件。普通任务写侧 keep=1，
// 证书任务 keep=5；调用方必须传本族真实保留数，禁止统一扫满证书代数。
func prependTaskLogRotations(path, content string, maxBackups int) string {
	for i := 1; i <= maxBackups; i++ {
		if backup := readCertJobLogFile(fmt.Sprintf("%s.%d", path, i)); backup != "" {
			content = backup + content
		}
	}
	return content
}

func readCertJobLogFile(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}

	const maxBytes = 128 * 1024
	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}

	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		return ""
	}

	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil {
		return ""
	}

	data = tailLogWindow(data, startOffset)

	const maxLines = 500
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	return strings.Join(lines, "\n")
}
