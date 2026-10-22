package services

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider"
	"lazy-balancer-v2/internal/models"

	xacme "golang.org/x/crypto/acme"
)

// CertIssuer coordinates ACME certificate issuance: creates/updates cert_jobs,
// runs the ACME flow, persists cert+key to DB, and triggers Caddy reload.
type CertIssuer struct {
	caddyReloader   func() error
	deploymentRetry func(int, issuedCertificate, time.Duration)
	dataDir         string
}

const maxCertificateDeploymentAttempts = 10

type issuedCertificate struct {
	ruleID            string
	certPEM           string
	keyPEM            string
	notAfter          time.Time
	providerID        int
	deploymentAttempt int
}

type certificateDeploymentError struct {
	err error
}

func (e *certificateDeploymentError) Error() string { return e.err.Error() }
func (e *certificateDeploymentError) Unwrap() error { return e.err }

// certificateRoleError marks post-issuance role confirmation failures. They
// are lifecycle/infrastructure interruptions, not CA failures, and must not
// consume renewal attempts when the queue classifies the returned error.
type certificateRoleError struct {
	err error
}

func (e *certificateRoleError) Error() string { return e.err.Error() }
func (e *certificateRoleError) Unwrap() error { return e.err }

func checkCertificateIssuanceRole(ctx context.Context) error {
	isMaster, err := RoleOf(ctx, db.DB)
	if err != nil {
		return &certificateRoleError{err: fmt.Errorf("读取主从角色失败: %w", err)}
	}
	if !isMaster {
		return &certificateRoleError{err: errors.New("节点已切换为从节点，停止保存签发结果")}
	}
	return nil
}

// CAProviderRateLimitError indicates the CA rejected the request with 429.
type CAProviderRateLimitError struct {
	RetryAfter time.Duration
	Reason     string
}

func (e *CAProviderRateLimitError) Error() string {
	return fmt.Sprintf("CA rate limited (429), retry after %v: %s", e.RetryAfter, e.Reason)
}

// parseRetryAfter parses an HTTP header value into a duration.
//
// 本函数与 internal/dnsprovider/internal/retry.After 是
// 同语义双实现（包边界所致：dnsprovider/internal 不可被 services 导入）。
// 两者都接受 delay-seconds 与 HTTP-date、不可解析/非正值（含零/负数秒）归零；
// 任一侧修改解析口径（例如支持毫秒、处理负值）MUST 同步另一侧并保持语义一致。
func parseRetryAfter(header string) time.Duration {
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		// 非正值显式归零（此前 "-5" 返回 -5s，仅靠下游 >0 判断
		// 才无害）——与 dnsprovider/retry.After 及本条契约注释同口径。
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if t, err := http.ParseTime(header); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// computeBackoff returns the cooling duration based on attempt count and CA.
// CA 提示分支与自有阶梯同封顶 3h——超大
// 提示值不再令冷却期越过证书过期点(attempts 停 1,maxAttempts 升级兜底
// 永不触发的形态闭合)。
func computeBackoff(attempts int, retryAfter time.Duration) time.Duration {
	const maxBackoff = 3 * time.Hour
	if retryAfter > 0 {
		return min(retryAfter, maxBackoff)
	}
	switch attempts {
	case 1:
		return time.Hour
	case 2:
		return 2 * time.Hour
	default:
		return 3 * time.Hour
	}
}

// NewCertIssuer creates a new CertIssuer. The reloader is called after a
// certificate is successfully issued so Caddy picks up the new cert.
// reloader 契约：全部调用点都在部署临界区内、已持
// CaddyOpLock（锁序 CaddyOpLock → DeployLock）——必须注入 InLock 变体
// （生产=GenerateAndApplyConfigForceInLock，cmd/server/main.go）；注入自取
// CaddyOpLock 的 Force 变体即重入死锁（非可重入锁）。nil=跳过重载。
func NewCertIssuer(reloader func() error, dataDir ...string) *CertIssuer {
	issuer := &CertIssuer{caddyReloader: reloader, deploymentRetry: scheduleCertificateDeploymentRetry}
	if len(dataDir) > 0 {
		issuer.dataDir = dataDir[0]
	}
	return issuer
}

func scheduleCertificateDeploymentRetry(jobID int, material issuedCertificate, delay time.Duration) {
	manager := GetCAQueueManager()
	if manager != nil && manager.IsRuleBlocked(material.ruleID) {
		return
	}
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service == nil {
		Logf("warn", "certificate deployment retry skipped for job %d: certificate service is not initialized", jobID)
		return
	}
	service.scheduleDeploymentRetry(jobID, material.ruleID, delay)
}

func signalCancelCertificateDeploymentRetriesForRule(ruleID string) []<-chan struct{} {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		return service.signalCancelDeploymentRetriesForRule(ruleID)
	}
	return nil
}

func cancelCertificateDeploymentRetry(jobID int) {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.cancelDeploymentRetry(jobID)
	}
}

func pauseCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.pauseDeploymentRetries()
	}
}

func resumeCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.resumeDeploymentRetries()
	}
}

// rescanDroppedCertificateDeploymentRetries 触发证书服务补扫被规则阻塞丢弃的
// 部署重试；供 caqueue 解锁后调用，与 resumeCertificateDeploymentRetries 同走
// 全局函数通道（避免服务层互相直接持有）。
func rescanDroppedCertificateDeploymentRetries() {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service != nil {
		service.rescanDroppedDeploymentRetries()
	}
}

// ErrCertificateDeploymentRetryBusy marks a manual retry refused because an
// earlier deployment callback for the same job is still unwinding; the service
// is running and reporting it as "stopped" would misdiagnose the condition.
var ErrCertificateDeploymentRetryBusy = errors.New("证书部署重试回调仍在退出中")

// RetryCertificateDeploymentNow 手动重试入口：把 downloaded
// 任务的部署重试立即重排（取消挂起的退避 timer 并在当前时刻执行一次部署）。
// 返回 nil 表示 timer 已登记；服务停止返回 ErrCertificateQueueInactive，旧回调
// 未退出返回 ErrCertificateDeploymentRetryBusy。deployment_available_after
// 已由调用方推到 now，启动恢复/周期补扫仍会接手，不会丢失。
func RetryCertificateDeploymentNow(jobID int, ruleID string) error {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service == nil {
		Logf("warn", "证书服务未运行：任务 %d 的部署重试将在服务启动/补扫时执行", jobID)
		return ErrCertificateQueueInactive
	}
	return service.scheduleDeploymentRetry(jobID, ruleID, 0)
}

func retryCertificateDeployment(ctx context.Context, jobID int, reloader func() error) error {
	var material issuedCertificate
	var expiresAt sql.NullTime
	// 部署重试须接受与 confirmCertificateDeployment 相同的可部署状态集：启动恢复把
	// cleanup_dns/cleanup_warning 任务调度到这里，若只收 'downloaded' 会因定时器静默
	// 吞掉 ErrNoRows 而永久卡死；放宽后重试循环才能推进（成功→issued，反复失败→failed）。
	if err := db.DB.QueryRowContext(ctx, `SELECT rule_id, COALESCE(cert_pem,''), COALESCE(key_pem,''), expires_at,
		COALESCE(ca_provider_id,0), COALESCE(deployment_attempts,0)
		FROM cert_jobs WHERE id=? AND status IN ('downloaded','cleanup_dns','cleanup_warning')`, jobID).Scan(
		&material.ruleID, &material.certPEM, &material.keyPEM, &expiresAt,
		&material.providerID, &material.deploymentAttempt,
	); err != nil {
		return fmt.Errorf("load downloaded certificate for deployment: %w", err)
	}
	material.notAfter = expiresAt.Time
	if !expiresAt.Valid {
		// 旧备份/导入可能携带 downloaded + 证书材料但 expires_at=NULL。
		// 从 PEM 恢复唯一权威有效期；成功部署会随材料回写该列，后续续期可见。
		notAfter, err := parseCertNotAfter(material.certPEM)
		if err != nil {
			return fmt.Errorf("load downloaded certificate expiry from PEM: %w", err)
		}
		material.notAfter = notAfter
	}
	manager := GetCAQueueManager()
	if manager != nil && manager.IsRuleBlocked(material.ruleID) {
		return context.Canceled
	}
	return NewCertIssuer(reloader).deployIssuedCertificate(ctx, jobID, material)
}

func (s *CertIssuer) deploymentFailed(jobID int, material issuedCertificate, message string, err error) error {
	var previousAttempt int
	// 使用 QueryRowContext 以响应 worker 取消信号（此处函数无 ctx，用 Background 兜底）。
	if queryErr := db.DB.QueryRowContext(context.Background(), "SELECT COALESCE(deployment_attempts,0) FROM cert_jobs WHERE id=? AND status IN ('issued','downloaded','cleanup_dns','cleanup_warning')", jobID).Scan(&previousAttempt); queryErr != nil {
		return &certificateDeploymentError{err: errors.Join(err, queryErr)}
	}
	if material.deploymentAttempt > previousAttempt {
		previousAttempt = material.deploymentAttempt
	}
	attempt := previousAttempt + 1
	// 封顶后不落 failed 终态。写文件/reload 连续失败时材料已在库、
	// expires_at 已前进；failed 会把任务从全部自动通道摘除（部署重试只收
	// downloaded/cleanup_*、启动恢复对 JobIsTerminal 直接 continue、文件对账
	// 只重建 issued/downloaded），而续期扫描按已前进的 expires_at 跳过 →
	// 旧证书到期后 TLS 长时间中断（DB 报新证有效）。保留可部署态并放慢为
	// 30 分钟慢速重试：磁盘/权限/重载恢复后自动收敛，材料不丢、不重签。
	const blockedDeploymentRetryDelay = 30 * time.Minute
	delay := certificateDeploymentBackoff(attempt)
	capped := attempt >= maxCertificateDeploymentAttempts
	if capped {
		delay = blockedDeploymentRetryDelay
	}
	storedMessage := fmt.Sprintf("部署失败 [attempt=%d/%d]: %s", attempt, maxCertificateDeploymentAttempts, message)
	if capped {
		storedMessage += fmt.Sprintf("；证书材料已保留，转入 %d 分钟慢速重试（磁盘/重载恢复后自动收敛）", int(blockedDeploymentRetryDelay.Minutes()))
	}
	storedMessage = truncateJobMessage(storedMessage)
	availableAfter := time.Now().UTC().Add(delay).Format("2006-01-02 15:04:05")
	// 材料随失败落库——首签发 confirm/persist 瞬时
	// 失败改走本重试链时,材料仅在内存;不落库则任务回 downloaded 但
	// 补扫 hasCertMaterial=0 跳过,永久不可达只能重签烧 CA 配额。
	// 已持久化场景(材料来自库读)同值重写,幂等无害。
	fields := map[string]any{
		"message":                    storedMessage,
		"deployment_attempts":        attempt,
		"deployment_available_after": availableAfter,
	}
	if material.certPEM != "" {
		fields["cert_pem"] = material.certPEM
		fields["key_pem"] = material.keyPEM
		fields["expires_at"] = material.notAfter
		fields["ca_provider_id"] = material.providerID
	}
	updateErr := transitionJob(db.DB, jobID, deploymentLifecycleJobStatuses, "downloaded", fields)
	// 部署失败必须落 certjob-*.log（此前部署链零 WriteCertJobLog，
	// 磁盘日志只剩签发阶段，排障需反查 DB）。ERROR 行业务行恒写；状态回写失败
	// （CAS 冲突/DB 故障）补 WARN 行，且不改变部署失败语义与签发结果。
	WriteCertJobLog(jobID, "ERROR", "deployment_failed", storedMessage)
	if updateErr != nil {
		Logf("warn", "cert job %d deployment status writeback failed (status=downloaded, attempt=%d): %v", jobID, attempt, updateErr)
		WriteCertJobLog(jobID, "WARN", "deployment_status_update_failed", fmt.Sprintf("部署失败状态回写失败 [attempt=%d/%d]: %v", attempt, maxCertificateDeploymentAttempts, updateErr))
	}
	if updateErr == nil && s.deploymentRetry != nil {
		material.deploymentAttempt = attempt
		// 异步再调度。此处常在部署回调 goroutine 内被同步调用——
		// 若同步进入 scheduleDeploymentRetry，会命中 的在途回调
		// 等待分支，等待对象恰是自己（done 只在本回调的 defer 关闭）→ 同
		// goroutine 自锁，重试链永久断裂并毒化 Resume/导入/启动恢复。起独立
		// goroutine 后等待变为跨 goroutine（回调返回即 done 关闭），「同
		// jobID 永不并发部署」不变量由该等待继续保证。
		go s.deploymentRetry(jobID, material, delay)
	}
	if updateErr == nil && attempt == maxCertificateDeploymentAttempts {
		// 封顶只留一条审计（后续每 30 分钟慢速重试不再刷屏）；结果码说明
		// 任务未终态、材料保留。
		RecordAuditLog("system", "部署失败", "证书任务", FormatAuditDetail(AuditJobPart(jobID), AuditResultPart("slow_retry")), "")
	}
	return &certificateDeploymentError{err: errors.Join(err, updateErr)}
}

func certificateDeploymentBackoff(attempt int) time.Duration {
	// 阶梯 = 1s×2^(attempt-1)，由循环守卫在跨过 5min 处停止加倍（上界 512s）。
	// 原实现在循环后还有一道 `> 5min → 5min` 钳制：调用方在 attempt≥
	// maxCertificateDeploymentAttempts 时已改用 30min 慢速重试，钳制对全部
	// 可达输入都不可达（死代码），删除。
	delay := time.Second
	for i := 1; i < attempt && delay < 5*time.Minute; i++ {
		delay *= 2
	}
	return delay
}

// jobLogger writes issuance progress to cert job log files and updates cert_jobs.status.
// from 是进度迁移的允许源态集合：主签发路径为 nonTerminalJobStatuses——
// 「终态不可逆」不能只靠队列在途+部署 CAS 运行时保证，进度写点必须有静态防线
// （并发部署回调先把行提交为 issued 时，进度日志不得把它拉回 in-flight）。
// 快速重部署路径（redeployDownloadedInLock）需要 issued→downloaded，构造时
// 显式换 {issued,downloaded} 白名单。
type jobLogger struct {
	jobID  int
	ruleID string
	file   *CertJobFileLogger
	from   []string
}

func (l *jobLogger) Log(stage, message string) {
	l.file.Log(stage, message)
	message = truncateJobMessage(message)
	from := l.from
	if len(from) == 0 {
		from = nonTerminalJobStatuses
	}
	if err := transitionJob(db.DB, l.jobID, from, stage, map[string]any{"message": message}); err != nil {
		Logf("error", "cert job %d status update failed: %v", l.jobID, err)
	}
}

// Issue obtains a certificate for the given rule and domains using the
// provided CA provider. The caller (queue manager) must pass a valid jobID.
func (s *CertIssuer) Issue(ctx context.Context, jobID int, ruleID, domains string, provider models.CAProvider) error {
	if jobID <= 0 {
		return fmt.Errorf("invalid job ID: %d", jobID)
	}

	domainList := normalizeAndValidateDomains(domains)
	if domainList == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}

	logger := &jobLogger{jobID: jobID, ruleID: ruleID, file: NewCertJobFileLogger(ruleID)}

	// Fast path: a previous attempt completed ACME issuance and persisted a
	// valid certificate, but file deployment failed. Redeploy instead of
	// re-issuing through the CA. Skipped when the job is disabled, the rule is
	// disabled, or the rule's CA provider changed since issuance (then the old
	// certificate is from the wrong CA and a fresh issuance is required).
	var jobStatus string
	var jobProviderID int
	var deploymentAttempt int
	var ruleEnabled bool
	var ruleProviderID int
	// 使用 QueryRowContext 以响应 worker 取消信号。
	if err := db.DB.QueryRowContext(ctx, `SELECT j.status, COALESCE(j.ca_provider_id,0), COALESCE(j.deployment_attempts,0), COALESCE(r.enabled,0), COALESCE(r.ca_provider_id,0)
		FROM cert_jobs j LEFT JOIN lb_rules r ON r.caddy_id = j.rule_id WHERE j.id = ?`, jobID).
		Scan(&jobStatus, &jobProviderID, &deploymentAttempt, &ruleEnabled, &ruleProviderID); err == nil &&
		(jobStatus == "issued" || jobStatus == "downloaded") && ruleEnabled {
		existingCert, existingKey, materialErr := readFastPathIssuedMaterial(ctx, jobID)
		if materialErr != nil && !errors.Is(materialErr, sql.ErrNoRows) {
			// 读失败（瞬时 DB 故障）不得静默回落完整签发：静默会白烧一张新 CA
			// 订单，而库里材料可能完好。按部署重试语义收敛——材料读不到就不写
			// 材料列（deploymentFailed 仅在 material.certPEM 非空时覆盖面），
			// 任务保持部署生命周期 + 退避窗口，补扫/重启接管重读。
			// 行不存在（ErrNoRows）维持既有回落语义（外层首查已存在性，此处
			// 只覆盖并发删除窗口）。
			Logf("warn", "证书任务 %d：快速路径读取已签发材料失败，转部署重试（不重签）: %v", jobID, materialErr)
			material := issuedCertificate{ruleID: ruleID, providerID: jobProviderID, deploymentAttempt: deploymentAttempt}
			return s.deploymentFailed(jobID, material, "读取已签发证书材料失败: "+materialErr.Error(), fmt.Errorf("read issued certificate material: %w", materialErr))
		}
		if materialErr == nil && existingCert != "" && existingKey != "" {
			// 告警 + 非正回退语义收敛于 GetCertRenewalDays。
			renewalDays := GetCertRenewalDays()
			if notAfter, perr := parseCertNotAfter(existingCert); perr == nil && time.Until(notAfter) > time.Duration(renewalDays)*24*time.Hour {
				// 规则 ca_provider_id=0（跟随默认）时不能拿 0 与任务中已解析的具体
				// 提供商 ID 直接比较而误判为"提供商已切换"；先解析出规则实际使用的
				// 提供商，只有真正切换才需要走完整签发流程。
				resolvedRuleProvider, resolveErr := ResolveCAProviderID(ruleProviderID)
				if resolveErr == nil && resolvedRuleProvider == jobProviderID {
					material := issuedCertificate{ruleID: ruleID, certPEM: existingCert, keyPEM: existingKey, notAfter: notAfter, providerID: jobProviderID, deploymentAttempt: deploymentAttempt}
					return s.redeployDownloadedInLock(ctx, jobID, material, logger)
				}
			}
		}
	}

	// check: verify the CA provider is reachable before starting the
	// real issuance flow. If the CA is down (e.g. ZeroSSL 504), fail fast and
	// let the retry scheduler handle the next attempt.
	// 预检（testCAProvider）内含 ZeroSSL EAB 自动获取（10s 界、持久化）与
	// 账户注册验证，返回的 client 携带 EAB 且账户已注册（KID 已缓存）——
	// 下方签发直接复用，Issuer 跳过重复注册（本路径此前自带
	// AutoProvisionZeroSSLEAB + 预检内再 provision + 预检/签发各注册一次，
	// 每次签发 EAB 双调用、ACME 账户双注册）。
	logger.Log("creating_account", fmt.Sprintf("测试 CA 提供商 %s (%s) 连通性", provider.Name, provider.Provider))
	preCheckedClient, err := NewCAProviderService(s.dataDir).testCAProvider(ctx, provider.ID)
	if err != nil {
		// CA 返回 429 时进入限流冷却（waiting_ca），与签发阶段的限流处理保持一致
		if raErr := detectRateLimit(err); raErr != nil {
			return raErr
		}
		// 队列暂停/节点 drain 取消在途执行：不得把取消写成终态 failed——
		// 外层 handleExecutionCancellation 会 requeue；先 failJob 会让终态无法回退。
		if ctx.Err() != nil {
			return fmt.Errorf("CA provider test canceled: %w", err)
		}
		// （复核修正）：审计报告称 from=creating_account 恒不命中，
		// 但上方 logger.Log("creating_account", …) 已先行迁移状态（from=全部
		// 非 disabled），原 CAS 实际可命中——报告前提证伪。改用 failJob（from=
		// 全部非终态）作为防御：若 logger.Log 的状态迁移因瞬时 DB 错误未落库，
		// 精确归因仍能写入，不被 execute 兜底的泛化文案覆盖。
		failJob(jobID, fmt.Sprintf("CA 提供商测试失败: %v", err))
		return fmt.Errorf("CA provider test failed: %w", err)
	}
	logger.Log("creating_account", "CA 提供商测试通过")

	// Reset the existing job row (queue manager already created/reused it).
	// from 集合不含终态——终态不可逆由写点静态保证，不只靠队列在途+CAS 运行时序。
	if err := transitionJob(db.DB, jobID, nonTerminalJobStatuses, "creating_account", map[string]any{"message": "开始申请证书"}); err != nil {
		return fmt.Errorf("update cert job status: %w", err)
	}

	// Resolve ACME config for the rule.
	var acmeConfigID int
	// 使用 QueryRowContext 以响应 worker 取消信号。
	err = db.DB.QueryRowContext(ctx, "SELECT COALESCE(acme_config_id,0) FROM lb_rules WHERE caddy_id=?", ruleID).Scan(&acmeConfigID)
	if err != nil {
		failJob(jobID, "读取规则 ACME 配置失败")
		return fmt.Errorf("read rule acme config: %w", err)
	}

	// ACME 邮箱由预检（phase=email）保证已配置——本路径不再重复读取/校验。

	// Load DNS credentials from the rule's selected provider.
	var dnsCredentialsJSON string
	if acmeConfigID > 0 {
		err = db.DB.QueryRowContext(ctx, "SELECT COALESCE(dns_credentials,'') FROM certificate_configs WHERE id=? AND enabled=1", acmeConfigID).Scan(&dnsCredentialsJSON)
		if err != nil && err != sql.ErrNoRows {
			failJob(jobID, "读取 DNS 凭证配置失败")
			return fmt.Errorf("read certificate config: %w", err)
		}
	}
	if dnsCredentialsJSON == "" {
		failJob(jobID, "未选择可用的 DNS 提供商，请先在规则中选择 DNS 凭证")
		return fmt.Errorf("no enabled DNS provider selected for rule")
	}

	dnsProvider, err := dnsprovider.NewPersistentProviderFromCredentials(dnsCredentialsJSON, s.dataDir)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}

	// ACME client 复用预检产物（已注册、KID 已缓存；ZeroSSL EAB 已随预检
	// provision 进 DB 并重载进 client）——不再新建 client 二次注册。
	// acmeEmail 已由预检保证非空（phase=email 先行拒绝）。
	issuer := &acme.Issuer{
		Client:               preCheckedClient,
		Provider:             dnsProvider,
		Logger:               logger,
		RequireRecursiveDNS:  provider.Provider == "zerossl",
		AccountPreRegistered: true,
	}

	// Run the ACME issuance flow
	certPEM, keyPEM, err := issuer.Issue(ctx, domainList)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("certificate issuance canceled: %w", ctx.Err())
		}
		if raErr := detectRateLimit(err); raErr != nil {
			return raErr
		}
		failJob(jobID, err.Error())
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("certificate issuance cancelled: %w", err)
	}

	// Parse certificate expiry
	notAfter, err := parseCertNotAfter(certPEM)
	if err != nil {
		failJob(jobID, err.Error())
		return err
	}
	// 区分 DB 错误与角色变化，避免误报"节点切换为从节点"。
	if err := checkCertificateIssuanceRole(ctx); err != nil {
		return err
	}

	if err := s.deployIssuedCertificate(ctx, jobID, issuedCertificate{
		ruleID: ruleID, certPEM: certPEM, keyPEM: keyPEM,
		notAfter: notAfter, providerID: provider.ID,
	}); err != nil {
		return err
	}

	RecordAuditLog("system", "签发成功", "证书任务", fmt.Sprintf("规则 %s 证书签发成功，过期时间 %s", ruleID, notAfter.Format("2006-01-02")), "")
	return nil
}

// readFastPathIssuedMaterial 读取快速路径复用的已签发材料（测试缝：var 而非
// 直接内联查询——注入读故障钉「读失败不得静默落全签」分支）。行不存在返回
// sql.ErrNoRows，调用方维持既有回落语义。
var readFastPathIssuedMaterial = func(ctx context.Context, jobID int) (certPEM, keyPEM string, err error) {
	err = db.DB.QueryRowContext(ctx, "SELECT COALESCE(cert_pem,''), COALESCE(key_pem,'') FROM cert_jobs WHERE id=?", jobID).Scan(&certPEM, &keyPEM)
	return certPEM, keyPEM, err
}

// redeployDownloadedInLock 在 CaddyOpLock → DeployLock 临界区内用库里已签发
// 材料重建部署（快速路径主体）。锁的获取/释放收敛在本 helper，作用域显式化：
// 调用方不得再取锁，临界区内的重载回调必须走 InLock 变体（见下方锁序注释）。
func (s *CertIssuer) redeployDownloadedInLock(ctx context.Context, jobID int, material issuedCertificate, logger *jobLogger) error {
	// 锁序：CaddyOpLock → DeployLock。恢复链
	//（UpdateRule/EnableRule 补偿全程持 caddyOpMu=CaddyOpLock →
	// RestoreCertJobsForRule 取 DeployLock）按此序持锁；旧序
	// DeployLock→（reloader 内）CaddyOpLock 与其双向互等成 AB-BA。
	// 本临界区内的重载回调以 InLock 语义调用——生产注入
	// GenerateAndApplyConfigForceInLock（cmd/server/main.go），自取
	// CaddyOpLock 的 Force 变体会重入死锁（非可重入锁）；持锁期间
	// 禁止再新增 CaddyOpLock 获取点。
	CaddyOpLock.Lock()
	unlock := DeployLock(material.ruleID)
	defer func() {
		unlock()
		CaddyOpLock.Unlock()
	}()
	ruleID := material.ruleID
	existingCert, existingKey := material.certPEM, material.keyPEM
	if err := confirmCertificateDeployment(ctx, jobID, material, true); err != nil {
		return err
	}
	// 快速路径改为文件内容比对：证书与私钥文件都与任务中的材料一致时
	// 无需重新部署/重载，直接确认签发任务状态即可。
	// 必须同时校验私钥文件——只比证书会在「cert 已 rename、key 未 rename」
	// 的崩溃窗口里持续跳过重部署，Caddy reload 因 key 不匹配失败且运行期
	// 不自愈（启动物化会修，窗口有界但无谓）。
	certPath, keyPath := CertFilePaths(ruleID)
	deployedCert, certReadErr := os.ReadFile(certPath)
	deployedKey, keyReadErr := os.ReadFile(keyPath)
	if certReadErr == nil && keyReadErr == nil && string(deployedCert) == existingCert && string(deployedKey) == existingKey {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := transitionJob(db.DB, jobID, []string{"downloaded", "issued"}, "issued", map[string]any{
			"message":                    "证书已部署，无需重新部署",
			"deployment_attempts":        0,
			"deployment_available_after": nil,
		}); err != nil {
			return fmt.Errorf("finalize already deployed certificate: %w", err)
		}
		RecordAuditLog("system", "签发成功", "证书任务", fmt.Sprintf("规则 %s 证书已部署，无需重新部署", ruleID), "")
		return nil
	}
	// 快速路径的进度迁移确实需要 issued→downloaded（任务已签发、材料在库），
	// 显式白名单替代全局含终态的 from 集合——主签发路径（Issue）保持
	// nonTerminalJobStatuses 静态防线。
	logger.from = []string{"issued", "downloaded"}
	logger.Log("downloaded", "检测到已签发的有效证书，直接重新部署文件")
	snapshot, snapshotErr := SnapshotCertFiles([]string{ruleID})
	if snapshotErr != nil {
		return s.deploymentFailed(jobID, material, "读取现有证书文件失败: "+snapshotErr.Error(), fmt.Errorf("snapshot existing certificate files: %w", snapshotErr))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := WriteCertFiles(ruleID, existingCert, existingKey); err != nil {
		return s.deploymentFailed(jobID, material, "已有证书重新部署失败: "+err.Error(), fmt.Errorf("redeploy existing certificate: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
	}
	if s.caddyReloader != nil {
		err := s.caddyReloader()
		// 2026-09-07 裁定：fast-path 重载与主路径（536/:539）统一留痕。
		s.auditFastPathReload(jobID, material, err)
		if err != nil {
			return s.deploymentFailed(jobID, material, "重新部署后重载 Caddy 失败: "+err.Error(), fmt.Errorf("reload Caddy after certificate redeploy: %w", err))
		}
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
	}
	// （cluster 审计，窄场景：运维手改证书文件或
	// 并发新化身分叉残留）：job 状态 "issued" + 磁盘不匹配
	// 的快速路径走到这里时，finalize 的 from-set 必须含 "issued"——
	// 否则 transitionJob CAS 失败 → errors.Join 恢复 → 磁盘回滚到
	// 不匹配状态 → 自愈路径断裂（job 保持 issued、磁盘永远错）。
	err := transitionJob(db.DB, jobID, []string{"downloaded", "issued"}, "issued", map[string]any{
		"message":                    "证书文件重新部署成功",
		"deployment_attempts":        0,
		"deployment_available_after": nil,
	})
	if err != nil {
		return errors.Join(fmt.Errorf("finalize certificate redeploy: %w", err), restoreCertificateDeployment(snapshot, s.caddyReloader))
	}
	RecordAuditLog("system", "签发成功", "证书任务", fmt.Sprintf("规则 %s 证书重新部署成功", ruleID), "")
	return nil
}

func (s *CertIssuer) deployIssuedCertificate(ctx context.Context, jobID int, material issuedCertificate) error {
	// 锁序：CaddyOpLock → DeployLock，与恢复链（持
	// caddyOpMu 的补偿路径 → RestoreCertJobsForRule）同序，消除
	// DeployLock→CaddyOpLock 旧序的 AB-BA 互等。s.caddyReloader 为 InLock
	// 语义（本临界区已持 CaddyOpLock），见 NewCertIssuer 契约。
	CaddyOpLock.Lock()
	unlock := DeployLock(material.ruleID)
	defer func() {
		unlock()
		CaddyOpLock.Unlock()
	}()
	if err := confirmCertificateDeployment(ctx, jobID, material, false); err != nil {
		// ErrNoRows(规则删除/禁用/角色翻转)保持 raw
		// ——材料已无意义,重试无益;其余(瞬时 DB)走 deploymentFailed 重试链,
		// 材料随失败落库(首签发材料仅内存,raw→failJob 终态会永久丢失)。
		if errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return s.deploymentFailed(jobID, material, "证书部署确认失败: "+err.Error(), fmt.Errorf("confirm certificate deployment: %w", err))
	}

	err := transitionJob(db.DB, jobID, []string{"downloaded", "cleanup_dns", "cleanup_warning"}, "downloaded", map[string]any{
		"cert_pem":                   material.certPEM,
		"key_pem":                    material.keyPEM,
		"expires_at":                 material.notAfter,
		"ca_provider_id":             material.providerID,
		"deployment_attempts":        0,
		"deployment_available_after": nil,
	})
	if err != nil {
		// 并发胜者(ErrJobTransitionConflict)保持 raw——对方已推进,
		// 本回调材料陈旧;其余(瞬时 DB)走 deploymentFailed,材料随失败落库。
		if errors.Is(err, ErrJobTransitionConflict) {
			return fmt.Errorf("persist downloaded certificate: %w", err)
		}
		return s.deploymentFailed(jobID, material, "证书部署落库失败: "+err.Error(), fmt.Errorf("persist downloaded certificate: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	snapshot, err := SnapshotCertFiles([]string{material.ruleID})
	if err != nil {
		return s.deploymentFailed(jobID, material, "读取现有证书文件失败: "+err.Error(), fmt.Errorf("snapshot existing certificate files: %w", err))
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := WriteCertFiles(material.ruleID, material.certPEM, material.keyPEM); err != nil {
		RecordAuditLog("system", "写入失败", "证书文件", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("io_error")), "")
		return s.deploymentFailed(jobID, material, "证书文件写入失败: "+err.Error(), fmt.Errorf("write certificate files: %w", err))
	}
	RecordAuditLog("system", "写入", "证书文件", FormatAuditDetail(AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
	if err := ctx.Err(); err != nil {
		return errors.Join(err, restoreCertificateDeployment(snapshot, s.caddyReloader))
	}

	if s.caddyReloader != nil {
		if err := s.caddyReloader(); err != nil {
			RecordAuditLog("system", "重载失败", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID)), "")
			return s.deploymentFailed(jobID, material, "Caddy 重载失败: "+err.Error(), fmt.Errorf("reload Caddy after certificate issuance: %w", err))
		}
		RecordAuditLog("system", "重载", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
	}

	tx, err := db.DB.BeginTx(ctx, nil)
	if err != nil {
		// 终段 DB 失败（如 SQLITE_BUSY）与文件写入失败同走
		// deploymentFailed 重试链（任务回 'downloaded'+退避，兼容 30s 部署
		// 补扫）。已写入的证书文件就是本次部署目标，重试会重新快照并收敛，
		// 回滚旧快照只会让首签发场景在重试成功前无证书可用。
		return s.deploymentFailed(jobID, material, "开启证书事务失败: "+err.Error(), fmt.Errorf("begin certificate transaction: %w", err))
	}
	defer func() { _ = tx.Rollback() }()
	err = transitionJob(tx, jobID, []string{"downloaded", "cleanup_dns", "cleanup_warning"}, "issued", map[string]any{
		"message":                    "签发成功",
		"renewal_attempts":           0,
		"ca_available_after":         nil,
		"last_error_code":            nil,
		"deployment_attempts":        0,
		"deployment_available_after": nil,
	})
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		rollbackErr := tx.Rollback()
		// 并发部署回调（在途回调 × 补扫重试）部署同 jobID 同一份
		// 证书时，CAS 败者的部署前快照可能早于胜者写入——无条件恢复会把磁盘
		// 回退到旧证书，与 DB('issued'+新 PEM)/Caddy 三方静默分叉，且
		// reconcileMissingCertFiles 不比对内容，分叉持续到下次续签。终态 CAS
		// 冲突（含任务中途被 disabled）保持既有补偿语义：胜者已提交且磁盘同
		// 物料时跳过恢复，否则恢复快照并由 failJob 归因（issued/disabled 为
		// 终态，failJob no-op）。
		if errors.Is(err, ErrJobTransitionConflict) {
			var cleanupErr error
			if deploymentCommittedByConcurrentWinner(jobID, material) {
				Logf("warn", "certificate job %d: finalization lost CAS race to a concurrent deployment of identical material; keeping winner's files, skipping snapshot restore", jobID)
			} else {
				cleanupErr = restoreCertificateDeployment(snapshot, s.caddyReloader)
			}
			failJob(jobID, "证书部署确认失败: "+err.Error())
			return errors.Join(fmt.Errorf("finalize issued certificate: %w", err), rollbackErr, cleanupErr)
		}
		// 真实 DB 失败（transition/提交出错，如 SQLITE_BUSY）不得走
		// 上面的 failJob——会把已签发落库证书搁浅为 failed，rescan 只扫
		// downloaded、续期只扫临期，自动恢复通道全部错过（首签发无证书最长
		// ~60 天，手动重试整轮重签烧配额）。改走与文件写入失败相同的
		// deploymentFailed 重试链（任务回 'downloaded'+退避，兼容 30s 补扫）。
		return errors.Join(s.deploymentFailed(jobID, material, "证书部署确认失败: "+err.Error(), fmt.Errorf("finalize issued certificate: %w", err)), rollbackErr)
	}
	s.noteFutureNotBefore(jobID, material)
	return nil
}

// certificateNotBeforeReloadMargin 是未来时钟证书「生效后延迟重载」的余量：
// 证书到 NotBefore 才被客户端接受，重载刻意错开生效点少许，避免时钟面
// 恰好压线时的边界抖动。
const certificateNotBeforeReloadMargin = time.Minute

// notBeforeReloadScheduler 生效后延迟重载登记通道（测试缝；生产=
// scheduleCertificateNotBeforeReload）。
var notBeforeReloadScheduler = scheduleCertificateNotBeforeReload

// noteFutureNotBefore 部署完成后检查未来时钟证书：NotBefore > now 时部署
// 本身照常生效（文件已写、已重载），但证书要被客户端接受须等到生效点——
// 告警留痕并登记一次 NotBefore+余量时刻的延迟重载（复用证书服务既有定时器
// 族，不新建调度器）。只告警不阻断：解析失败/服务未运行均降级为 warn 日志。
func (s *CertIssuer) noteFutureNotBefore(jobID int, material issuedCertificate) {
	if material.certPEM == "" {
		return
	}
	notBefore, err := parseCertNotBefore(material.certPEM)
	if err != nil {
		Logf("warn", "证书任务 %d：解析证书生效时间失败（NotBefore 未来时钟检查跳过）: %v", jobID, err)
		return
	}
	delay := time.Until(notBefore.Add(certificateNotBeforeReloadMargin))
	if delay <= 0 {
		return
	}
	effectiveAt := notBefore.UTC().Format("2006-01-02 15:04:05")
	Logf("warn", "证书任务 %d（规则 %s）：证书尚未生效（NotBefore=%s UTC），已登记生效后重载", jobID, material.ruleID, effectiveAt)
	RecordAuditLog("system", "警告", "证书任务", FormatAuditDetail(
		AuditJobPart(jobID), AuditRulePart(material.ruleID),
		fmt.Sprintf("证书尚未生效（生效时间 %s UTC），已登记生效后重载", effectiveAt)), "")
	if notBeforeReloadScheduler != nil {
		notBeforeReloadScheduler(jobID, material.ruleID, delay)
	}
}

// scheduleCertificateNotBeforeReload 生产通道：经证书服务既有定时器族登记
// 一次性生效后重载；服务未运行（队列停用/测试环境）时降级为 warn——证书文件
// 已随本次部署生效，缺的只是生效点的一次补充重载。
// 收敛路径（不登记时）：重启时的配置物化/重载、下一次任意配置写触发的重载、
// 以及服务恢复后新登记的延迟重载定时器——「补扫」不会重渲染配置，不构成
// 收敛路径。边界：暂停期跳过登记不在恢复时补登（一次性定时器无持久化），
// 生效点前若全程无任何写操作且不重启，则本次补充重载缺失（证书文件与配置
// 均已生效，仅少一次重载）。
func scheduleCertificateNotBeforeReload(jobID int, ruleID string, delay time.Duration) {
	certificateServiceMu.Lock()
	service := certificateService
	certificateServiceMu.Unlock()
	if service == nil {
		Logf("warn", "证书服务未运行：任务 %d（规则 %s）的生效后重载跳过登记（证书文件已随部署生效；收敛路径=重启物化/下一次配置写触发的重载/服务运行时的延迟重载定时器）", jobID, ruleID)
		return
	}
	service.scheduleDelayedReload(jobID, ruleID, delay)
}

// deploymentCommittedByConcurrentWinner 报告终态 CAS 冲突是否源于并发部署回调
// 已提交同一份证书：任务状态已推进到终态 issued 且磁盘证书内容与本次部署材料
// 一致。仅用于冲突分支的恢复快照跳过判定 纵深防御）。
func deploymentCommittedByConcurrentWinner(jobID int, material issuedCertificate) bool {
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil || status != "issued" {
		return false
	}
	certPath, _ := CertFilePaths(material.ruleID)
	deployed, err := os.ReadFile(certPath)
	return err == nil && bytes.Equal(deployed, []byte(material.certPEM))
}

// confirmCertificateDeployment 校验任务与规则的当前状态仍允许落盘这份签发
// 材料。刻意不过滤 r.enable_tls/r.tls_source：与扫描/物化路径
// （certificates.go 的 rescan/renew 查询、certstore.go 的启动物化）统一附加
// `enable_tls=1 AND tls_source='acme_dns'` 的口径不同，本函数只把关「任务与
// 规则是否仍对得上」——已签发材料写盘后不被 manual 渲染消费，保留材料便于
// 规则切回 acme_dns 时直接复用。材料保留取向为有意设计，勿对齐过滤口径。
func confirmCertificateDeployment(ctx context.Context, jobID int, material issuedCertificate, allowIssued bool) error {
	var status, jobDomains, ruleDomains string
	err := db.DB.QueryRowContext(ctx, `SELECT j.status, j.domain, r.domain FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		JOIN global_config g ON g.id=1
		WHERE j.id=? AND j.rule_id=?
		  AND r.enabled=1 AND COALESCE(g.is_master,1)=1
	`, jobID, material.ruleID).Scan(&status, &jobDomains, &ruleDomains)
	if err != nil {
		return fmt.Errorf("confirm certificate deployment: %w", err)
	}
	canonicalJobDomains, err := CanonicalACMEDomains(jobDomains)
	if err != nil {
		return fmt.Errorf("confirm certificate job domains: %w", err)
	}
	canonicalRuleDomains, err := CanonicalACMEDomains(ruleDomains)
	if err != nil {
		return fmt.Errorf("confirm certificate rule domains: %w", err)
	}
	if canonicalJobDomains != canonicalRuleDomains {
		return fmt.Errorf("certificate job %d domains no longer match rule", jobID)
	}
	deployable := status == "downloaded" || status == "cleanup_dns" || status == "cleanup_warning"
	if allowIssued {
		deployable = status == "issued" || status == "downloaded"
	}
	if !deployable {
		return fmt.Errorf("certificate job %d is no longer deployable", jobID)
	}
	return nil
}

func restoreCertificateDeployment(snapshot CertFilesSnapshot, reloader func() error) error {
	if err := RestoreCertFiles(snapshot); err != nil {
		return fmt.Errorf("restore previous certificate files: %w", err)
	}
	if reloader != nil {
		err := reloader()
		// 2026-09-07 裁定：回滚重载同口径留痕（成功回滚=DB 态重渲染；失败=旧配置保留）。
		recordSystemReloadAudit("certificate_issued", err)
		if err != nil {
			return fmt.Errorf("reload Caddy after certificate rollback: %w", err)
		}
	}
	return nil
}

func detectRateLimit(err error) *CAProviderRateLimitError {
	if err == nil {
		return nil
	}
	// Check for structured ACME 429 error first. golang.org/x/crypto/acme
	// returns *acme.Error with StatusCode and response headers for CA errors.
	var acmeErr *xacme.Error
	if errors.As(err, &acmeErr) && acmeErr.StatusCode == http.StatusTooManyRequests {
		retryAfter := time.Duration(0)
		if ra := acmeErr.Header.Get("Retry-After"); ra != "" {
			retryAfter = parseRetryAfter(ra)
		}
		return &CAProviderRateLimitError{RetryAfter: retryAfter, Reason: err.Error()}
	}

	// Fallback: string matching for providers/wrappers that don't surface the
	// structured *acme.Error. Bare "429" substrings are NOT evidence of rate
	// limiting: domains are embedded in error text (e.g. acme/issuer.go
	// "present dns for 429.example.com") and would misroute the job into the
	// 1-3h waiting_ca cooldown instead of the 30min failure retry. Real CA
	// 429s carry the structured StatusCode above or rate-limit wording.
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "rate limit") && !strings.Contains(msg, "too many") {
		return nil
	}

	// Try to extract a hint from the error text. The ACME library
	// sometimes includes it as "retry after 2026-01-02 03:04:05 +0000 UTC"
	// (Go time.Time.String()) or "retry after 3600s".
	retryAfter := time.Duration(0)
	if d := extractRetryAfterFromError(err.Error()); d > 0 {
		retryAfter = d
	}
	return &CAProviderRateLimitError{RetryAfter: retryAfter, Reason: err.Error()}
}

// extractRetryAfterFromError attempts to pull a duration out of a
// CA error message. It is a best-effort fallback because golang.org/x/crypto/acme
// does not expose the HTTP response directly.
func extractRetryAfterFromError(errText string) time.Duration {
	lower := strings.ToLower(errText)
	if idx := strings.Index(lower, "retry after"); idx != -1 {
		suffix := errText[idx+len("retry after"):]
		suffix = strings.TrimSpace(suffix)
		// Strip a trailing period or comma （此前只剥句点，注释与
		// 行为不符——逗号结尾的 "3600s," 会整段落入解析失败)。
		suffix = strings.TrimRight(suffix, ".,")
		// Try parsing as seconds if it looks like "3600s".
		if strings.HasSuffix(suffix, "s") {
			if sec, err := strconv.Atoi(strings.TrimSuffix(suffix, "s")); err == nil && sec > 0 {
				return time.Duration(sec) * time.Second
			}
		}
		// Try parsing as an RFC3339 timestamp.
		if t, err := time.Parse(time.RFC3339, suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
		// Try parsing as HTTP date.
		if t, err := time.Parse(http.TimeFormat, suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
		// Try parsing as Go time.Time.String()（"2006-01-02 15:04:05 -0700 MST"，
		// 即上方注释文档化的形态）。此前只试 RFC3339/HTTP-date，该
		// 文档化分支永不命中，退化为自有阶梯（1–3h，偏长）；Go 解析布局虽无
		// 小数秒字段，但解析器接受任意长度的小数秒（标准库特例）。
		if t, err := time.Parse("2006-01-02 15:04:05 -0700 MST", suffix); err == nil {
			if d := time.Until(t); d > 0 {
				return d
			}
		}
	}
	return 0
}

// ValidateACMEDomains returns an error if the domains string is not a valid
// ACME certificate request (single domain or root+www).
func ValidateACMEDomains(domains string) error {
	if normalizeAndValidateDomains(domains) == nil {
		return fmt.Errorf("ACME证书仅支持单域名或根域+www二级域名: %s", domains)
	}
	return nil
}

func CanonicalACMEDomains(domains string) (string, error) {
	list := normalizeAndValidateDomains(domains)
	if list == nil {
		return "", fmt.Errorf("invalid ACME domains: %s", domains)
	}
	return strings.Join(list, ","), nil
}

// ReversedCertJobDomain 返回双域名集合的逆序形式（"a.com,www.a.com"→
// "www.a.com,a.com"）；非双元素集（单域名/多段/空）原样返回。cert_jobs.domain
// 存排序规范形式，而 lb_rules.domain 保留用户输入顺序，任务匹配需同时覆盖两种
// 排列（lower+replace 归一后按 IN (canonical, reversed) 命中）。
// handlers.rules.reversedACMEDomainForm 与
// handlers.certjobs.reversedCertJobDomain 双份同实现收敛至此唯一源，两侧委托。
func ReversedCertJobDomain(domain string) string {
	if parts := strings.Split(domain, ","); len(parts) == 2 {
		return parts[1] + "," + parts[0]
	}
	return domain
}

// normalizeAndValidateDomains returns a cleaned domain list if it is either
// a single domain or a root domain plus its www subdomain. Otherwise nil.
func normalizeAndValidateDomains(domains string) []string {
	parts := strings.Split(domains, ",")
	var list []string
	seen := make(map[string]struct{})
	for _, p := range parts {
		d := strings.TrimSpace(strings.ToLower(p))
		if d == "" {
			continue
		}
		if _, ok := seen[d]; ok {
			continue
		}
		seen[d] = struct{}{}
		list = append(list, d)
	}
	if len(list) == 0 || len(list) > 2 {
		return nil
	}
	for _, d := range list {
		if !isValidACMEIssuerDomain(d) {
			return nil
		}
	}
	if len(list) == 1 {
		return list
	}
	// Must be root + www.root (either ordering)
	a, b := list[0], list[1]
	if b == "www."+a || a == "www."+b {
		sort.Strings(list)
		return list
	}
	return nil
}

// isValidACMEIssuerDomain rejects wildcards, IP addresses, empty labels and
// labels longer than 63 bytes.
func isValidACMEIssuerDomain(d string) bool {
	if d == "" {
		return false
	}
	if strings.Contains(d, "*") {
		return false
	}
	if net.ParseIP(d) != nil {
		return false
	}
	if strings.HasPrefix(d, ".") || strings.HasSuffix(d, ".") || strings.Contains(d, "..") {
		return false
	}
	if len(d) > 253 {
		return false
	}
	for _, label := range strings.Split(d, ".") {
		if label == "" {
			return false
		}
		if len(label) > 63 {
			return false
		}
	}
	return true
}

// parseCertNotAfter extracts the NotAfter time from a PEM certificate chain.
func parseCertNotAfter(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotAfter, nil
}

// parseCertNotBefore extracts the NotBefore time from a PEM certificate chain.
func parseCertNotBefore(certPEM string) (time.Time, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return time.Time{}, fmt.Errorf("invalid certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse certificate: %w", err)
	}
	return cert.NotBefore, nil
}

// auditFastPathReload 修正：fast-path 重载审计带 job/rule 归因（对齐主路径粒度）。
func (s *CertIssuer) auditFastPathReload(jobID int, material issuedCertificate, err error) {
	if err != nil {
		RecordAuditLog("system", "重载失败", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID)), "")
		return
	}
	RecordAuditLog("system", "重载", "Caddy服务", FormatAuditDetail(AuditSourcePart("certificate_issued"), AuditJobPart(jobID), AuditRulePart(material.ruleID), AuditResultPart("success")), "")
}
