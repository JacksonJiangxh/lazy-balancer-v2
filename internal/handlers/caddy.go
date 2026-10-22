package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

var caddyRunCommand = func() *exec.Cmd {
	return exec.Command("caddy", "run", "--config", "/app/config/Caddyfile", "--adapter", "caddyfile")
}

// caddyAdminTransport 是 admin API 探针/读取的共享 Transport：连接池跨请求
// 复用（此前每个调用点 `&http.Client{Timeout: …}` 每请求新建客户端——Transport
// 要么落到共享 DefaultTransport 与其他组件抢池，要么每次新建即每次新连接）。
// 每请求超时语义由 context 承载（覆盖到 body 读取，与 client.Timeout 等价）。
var caddyAdminTransport = func() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.MaxIdleConnsPerHost = 8
	return transport
}()

var caddyAdminHTTPClient = &http.Client{Transport: caddyAdminTransport}

// caddyAdminCancelBody 在 Body.Close 时释放请求 context 的超时计时器——
// 请求超时用 context 表达后，计时器必须随响应体关闭回收（否则每个请求按
// 最长 timeout 持有计时器）。
type caddyAdminCancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *caddyAdminCancelBody) Close() error {
	err := b.ReadCloser.Close()
	b.cancel()
	return err
}

// caddyAdminGet 以共享客户端 GET admin API 路径，timeout 为单请求超时
// （旧形态 client.Timeout 的等价语义）。
func caddyAdminGet(ctx context.Context, adminURL, path string, timeout time.Duration) (*http.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, strings.TrimRight(adminURL, "/")+path, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	resp, err := caddyAdminHTTPClient.Do(req)
	if err != nil {
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		cancel()
		return resp, err
	}
	if resp.Body == nil {
		cancel()
		return resp, nil
	}
	resp.Body = &caddyAdminCancelBody{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}

var caddyStopCommand = func(adminURL string) *exec.Cmd {
	address := adminURL
	if parsed, err := url.Parse(adminURL); err == nil && parsed.Host != "" {
		address = parsed.Host
	}
	return exec.Command("caddy", "stop", "--address", address)
}

// caddyPauseFile 与 docker-entrypoint.sh 的 Caddy 监督器协调
// stopCaddy 建文件 → 监督器见文件不重启(admin 停止是用户意图);
// startCaddy 删文件 → 监督器 ≤1s 检测并启动;handler 等 admin 就绪。
// 改为包级 var 作测试注入缝（caddyProcRoot 同模式）。
var caddyPauseFile = "/tmp/lazy-balancer-caddy-paused"

// caddySupervisorPidFile 是监督器在位标记(entrypoint 父壳在后台化监督器
// 子 shell 后立即写入——$!=子 shell pid）——
// startCaddy 仅在标记在场时走监督器委托路径;测试环境(无监督器)直启不等待。
var caddySupervisorPidFile = "/tmp/lazy-balancer-caddy-supervisor.pid"

// caddySupervisorWaitTimeout 是监督器委托的 admin 就绪等待上限（生产 5s；
// 测试调小）。测试注入缝。
var caddySupervisorWaitTimeout = 5 * time.Second

// caddyStartupReplayMarkerFile 是监督器「启动回放阶段完成」标记（启动
// 竞态修复；与 docker-entrypoint.sh 的 CADDY_STARTUP_REPLAY_DONE 同一路径）：
// 监督器 reapply_last_good 尾部写（LKG 缺失/回放失败也写——标记语义是
// 「admin 就绪+回放阶段已了结」，不是「回放成功」），app 启动配置载入等标记
// 后再应用。包级 var 作测试注入缝（caddyPauseFile 同模式）。
var caddyStartupReplayMarkerFile = "/tmp/lazy-balancer-caddy-startup-replayed"

// startupReplayWaitTimeout 是启动载入等待回放标记的上限（生产 30s；测试调小）。
// 有界放行：监督器夭折（标记永不出现）时退化语义=修复前（app 直接应用），
// 不得挂死启动。测试注入缝。
var startupReplayWaitTimeout = 30 * time.Second

// waitStartupReplayDone 启动竞态修复：监督器首启 last-good 回放与
// app BootSync 配置载入各等 admin 就绪即写，先后为硬币——app 渲染先落时，
// 监督器回放的旧 LKG 快照覆盖新配置（v2.3.7-beta 发版实锤：新配置被盖到手动
// 重载才生效）。协议：监督器回放阶段尾部写标记，app 启动载入等标记后再应用，
// 时序构造性定死为「回放→标记→应用」。supervisorAlive 不在场（测试/裸跑）
// 协议关闭立即返回；标记永不出现（监督器夭折）等满超时后 WARN 放行；
// 手动重载/caddy-restart 到场时标记必已存在（本容器生命周期内监督器首启
// 必写过），首轮探测即返回。
//
// 超时放行路径的收敛兜底在监督器侧——admin 就绪逾 10
// 探针时 slow-start 后台环补写 /tmp/caddy-restarted（绕过首启豁免），
// caddy-restart watcher 随后走与启动同源的 DB 渲染→校验→应用强制重收敛；
// 本函数的超时是有界的面板可用性保障，不因拉高等待上限换取就绪竞态收窄
// （docker-entrypoint.sh slow-start 块 Ruling 注释）。
func waitStartupReplayDone() {
	if !supervisorAlive() {
		return
	}
	deadline := time.Now().Add(startupReplayWaitTimeout)
	for {
		if _, err := os.Stat(caddyStartupReplayMarkerFile); err == nil {
			return
		}
		if time.Now().After(deadline) {
			services.Logf("warn", "等待 Caddy 监督器启动回放标记超时（%s），继续启动配置载入（监督器可能未按协议写标记，last-good 回放存在乱序覆盖风险）", startupReplayWaitTimeout)
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// caddyProcRoot 是进程状态读取的根目录（生产=/proc；测试指向临时伪 /proc 目录）。
var caddyProcRoot = "/proc"

// caddyProcessRunning 纯 /proc 实现：遍历 /proc/*/stat，存在任一 comm=caddy 且
// 状态非 Z（僵尸）的进程即为运行中。Z=僵尸——entrypoint 孵化、父进程未回收的
// caddy 子进程死后会永久滞留（Go 不回收非 exec 子进程），其 comm 仍为 caddy、
// 进程仍在，但已 dead 不能服务，必须排除在「运行中」之外（否则 stop/restart 的
// 完成判定在该僵尸存在期间永远失败——2026-08-28 生产复现）。不用 ps：busybox ps
// 不支持 -p 选项（alpine 容器内 GNU 语法的 ps -o stat= -p 直接报
// "unrecognized option"），/proc 是唯一可靠来源。
func caddyProcessRunning() bool {
	return caddyLivePID() > 0
}

// parseProcStat 解析 /proc/<pid>/stat 行，返回 comm 与状态字节。stat 格式：
// pid (comm) state ...；comm 可含空格与右括号，取最后一个 ')' 之后的单字符
// 状态（R/S/D/T/Z…）。畸形行返回 ok=false。caddyLivePID 与 supervisorAlive
// 共用本解析（监督器存活判定与 caddy 存活判定同口径排 Z）。
func parseProcStat(line string) (comm string, state byte, ok bool) {
	open := strings.Index(line, "(")
	close := strings.LastIndex(line, ")")
	if open < 0 || close <= open || close+2 >= len(line) {
		return "", 0, false
	}
	return line[open+1 : close], line[close+2], true
}

// caddyLivePID 返回首个存活（非 Z 状态）caddy 进程的 pid，无存活进程时返回 0。
// 与 caddyProcessRunning 共用同一 /proc 遍历（仪表盘「运行中（pid）」展示）。
func caddyLivePID() int {
	entries, err := os.ReadDir(caddyProcRoot)
	if err != nil {
		return 0
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		content, err := os.ReadFile(filepath.Join(caddyProcRoot, entry.Name(), "stat"))
		if err != nil {
			continue // 进程可能刚退出，stat 已消失——视为非运行候选，跳过
		}
		comm, state, ok := parseProcStat(string(content))
		if !ok || comm != "caddy" {
			continue
		}
		if state != 'Z' {
			if pid, err := strconv.Atoi(entry.Name()); err == nil {
				return pid
			}
		}
	}
	return 0
}

func caddyAdminReady(adminURL string) bool {
	response, err := caddyAdminGet(context.Background(), adminURL, "/config/", 250*time.Millisecond)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode < http.StatusInternalServerError
}

// supervisorAlive：监督器在位判定——pid 标记在场且
// 所记 pid 仍存活。存活校验从「/proc/<pid> 目录在场」
// 升级为读 /proc/<pid>/stat 状态字节——监督器 kill -9 后父进程（PID1 app，
// Go 不回收非 exec 子进程）未回收期间僵尸滞留 /proc（目录在场、状态字节
// Z），目录判定恒活会让 startCaddy 恒委托空等 5s 超时、直启兜底永不可达；
// Z 视死（与 caddyLivePID 同口径，共用 parseProcStat 与 caddyProcRoot 注入
// 缝）。comm 不校验——pid 标记是权威记录，监督器 subshell 的 comm 形态
// 不稳定。标记内容非正整数（旧格式/损坏）视为陈旧；stat 缺失/畸形视为死
// （宁可直启不空等）。
func supervisorAlive() bool {
	data, err := os.ReadFile(caddySupervisorPidFile)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return false
	}
	content, err := os.ReadFile(filepath.Join(caddyProcRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return false // /proc/<pid>/stat 不在场=进程已退出
	}
	_, state, ok := parseProcStat(string(content))
	return ok && state != 'Z'
}

func startCaddy(adminURL string) error {
	// 监督器在场(标记文件)时优先委托(删 pause → 监督器 ≤1s 启动),
	// 等 admin 就绪;标记不在场(测试环境/监督器死亡)直接 spawn。
	// 在场判定升级为 pid 存活校验——标记文件在但
	// pid 已死（监督器被杀/容器异常重启残留）时，委托只会空等超时后报错；
	// 落直启（与标记不在场同语义；标记留存不删，由存活判定消化）。
	if supervisorAlive() {
		_ = os.Remove(caddyPauseFile)
		supervisorDeadline := time.Now().Add(caddySupervisorWaitTimeout)
		for time.Now().Before(supervisorDeadline) {
			if caddyAdminReady(adminURL) {
				return nil
			}
			time.Sleep(200 * time.Millisecond)
		}
		// 委托超时不落直启——监督器活着但慢启动时
		// 直启会双启抢 admin/监听端口，败者触发监督器崩溃重拉 churn（或
		// 假 500：监督器实例其实已正常服务）。pause 已解除，监督器仍在
		// 重试，返回明确错误即可。
		return fmt.Errorf("Caddy 监督器在场但 %s 内未拉起就绪的 Caddy（pause 已解除，监督器仍在重试，请稍后复查或检查容器日志）", caddySupervisorWaitTimeout)
	}
	// 直启路径不再删 pid 标记——app 检查
	// supervisorAlive 之后、监督器子 shell 首写标记之前，Remove 会误删刚
	// 写入的在位标记（永久失标 → 下次直启与监督器拉起双启抢口）。陈旧
	// 标记（死 pid）留存无害：supervisorAlive 按 pid 存活判定消化；标记
	// 不在场时 Remove 本是 no-op。僵尸误报半边由 状态字节判定承接。
	cmd := caddyRunCommand()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-exited:
			if err == nil {
				err = errors.New("Caddy 在 Admin API 就绪前退出")
			}
			return err
		case <-ticker.C:
			if caddyAdminReady(adminURL) {
				return nil
			}
		case <-deadline.C:
			if cmd.Process != nil {
				_ = cmd.Process.Kill()
				<-exited
			}
			return errors.New("Caddy Admin API 未就绪")
		}
	}
}

func stopCaddy(adminURL string) error {
	// 先建 pause 再停——防监督器在 admin stop 与进程退出之间竞态重启
	_ = os.WriteFile(caddyPauseFile, nil, 0o644)
	if err := caddyStopCommand(adminURL).Run(); err != nil {
		_ = os.Remove(caddyPauseFile) // 停止失败回滚 pause(监督器继续看护)
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if !caddyAdminReady(adminURL) && !caddyProcessRunning() {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return errors.New("停止后 Caddy Admin API 仍可达")
}

// ImportSecurityPolicyCustomOnlyModeSQL 供导入路径与测试共用的归一 SQL；
// 唯一事实源在 db.SecurityPolicyCustomOnlyModeNormalizationSQL。
const ImportSecurityPolicyCustomOnlyModeSQL = db.SecurityPolicyCustomOnlyModeNormalizationSQL

func (h *Handlers) GetConfig(c *gin.Context) {
	var cfg models.GlobalConfig
	// 治理默认值列的读路径 SQL 字面量是默认值的第三次复制
	//（DDL DEFAULT+启动回填+此处）——改参数绑定 db.Default* 常量单源化，
	// 常量变更不再需要三处同步。非治理列（log 级别/布尔/保留期等）字面量
	// 原状（不在库值唯一真相治理批次内）。
	// threat_traffic_sample_n/security_events_retention_days/
	// security_events_row_cap 三处兜底字面量与 DDL DEFAULT+迁移回填对齐
	//（自此改为绑定 db.Default* 常量，含 threat_screen_mode；均 NOT NULL+
	// 回填，兜底实际不可达）。
	err := db.DB.QueryRow(`
		SELECT id, caddy_config, dns_provider,
		       COALESCE(acme_email,'') as acme_email, COALESCE(cert_expiry_days,?) as cert_expiry_days,
		       COALESCE(cert_renewal_days,?) as cert_renewal_days,
		       COALESCE(cert_renewal_attempts,?) as cert_renewal_attempts,
		       COALESCE(default_ca_provider_id,0) as default_ca_provider_id,
		       log_level,

		       COALESCE(caddy_log_level,'info') as caddy_log_level,
		       COALESCE(caddy_log_size_mb,?) as caddy_log_size_mb,
		       CASE WHEN COALESCE(request_body_max_size_mb,0)>0 THEN request_body_max_size_mb ELSE ? END as request_body_max_size_mb,
		       COALESCE(http_read_timeout,?) as http_read_timeout,
		       COALESCE(http_write_timeout,?) as http_write_timeout,
		       COALESCE(http_idle_timeout,?) as http_idle_timeout,
		       COALESCE(upstream_keepalive_timeout,0) as upstream_keepalive_timeout,
		       COALESCE(proxy_dial_timeout,0) as proxy_dial_timeout,
		       COALESCE(proxy_response_header_timeout,0) as proxy_response_header_timeout,
		       COALESCE(proxy_read_timeout,0) as proxy_read_timeout,
		       COALESCE(proxy_write_timeout,0) as proxy_write_timeout,
		       COALESCE(proxy_stream_timeout,0) as proxy_stream_timeout,
		       COALESCE(proxy_flush_interval,0) as proxy_flush_interval,
		       COALESCE(proxy_stream_close_delay,0) as proxy_stream_close_delay,
		       COALESCE(server_tokens_hidden,FALSE) as server_tokens_hidden,
		       COALESCE(task_log_size_mb,10) as task_log_size_mb,
		       COALESCE(audit_log_size_mb,10) as audit_log_size_mb,
		       COALESCE(runtime_log_size_mb,100) as runtime_log_size_mb,
		       COALESCE(access_log_json,TRUE) as access_log_json,
	       COALESCE(access_log_format,'') as access_log_format,
	       COALESCE(audit_retention_months,3) as audit_retention_months,
	       COALESCE(jwt_expire_minutes,20) as jwt_expire_minutes,
	       COALESCE(timezone,?) as timezone,
	       COALESCE(github_proxy_url,'https://v4.gh-proxy.org/') as github_proxy_url,
	       COALESCE(github_token,'') as github_token,
	       COALESCE(mfa_write_guard,0) as mfa_write_guard,
	       COALESCE(mfa_lockout_enabled,0) as mfa_lockout_enabled,
	       COALESCE(trusted_proxy_enabled,0) as trusted_proxy_enabled,
	       COALESCE(trusted_proxy_ranges,'[]') as trusted_proxy_ranges,
	       COALESCE(trusted_proxy_range_refs,'[]') as trusted_proxy_range_refs,
	       COALESCE(trusted_proxy_headers,'[]') as trusted_proxy_headers,
	       COALESCE(trusted_proxy_strict,1) as trusted_proxy_strict,
	       COALESCE(server_map_lat,0) as server_map_lat,
	       COALESCE(server_map_lon,0) as server_map_lon,
	       COALESCE(threat_screen_mode,?) as threat_screen_mode,
	       COALESCE(threat_traffic_sample_n,?) as threat_traffic_sample_n,
	       COALESCE(security_events_retention_days,?) as security_events_retention_days,
	       COALESCE(security_events_row_cap,?) as security_events_row_cap,
	       COALESCE(is_master,1) as is_master, COALESCE(master_url, '') as master_url, sync_interval,
	       last_sync, updated_at
		FROM global_config WHERE id = 1
	`,
		// 占位符序=cert_expiry_days/cert_renewal_days/cert_renewal_attempts/
		// caddy_log_size_mb/request_body_max_size_mb/http_read_timeout/http_write_timeout/
		// http_idle_timeout；追加大屏/安全事件四列。
		db.DefaultCertExpiryDays, db.DefaultCertRenewalDays, db.DefaultCertRenewalAttempts,
		db.DefaultCaddyLogSizeMB, db.DefaultRequestBodyMaxSizeMB,
		db.DefaultHTTPReadTimeout, db.DefaultHTTPWriteTimeout, db.DefaultHTTPIdleTimeout,
		db.DefaultTimezone,
		db.DefaultThreatScreenMode, db.DefaultThreatTrafficSampleN,
		db.DefaultSecurityEventsRetentionDays, db.DefaultSecurityEventsRowCap,
	).Scan(
		&cfg.ID, &cfg.CaddyConfig, &cfg.DNSProvider,
		&cfg.ACMEEmail, &cfg.CertExpiryDays, &cfg.CertRenewalDays, &cfg.CertRenewalAttempts, &cfg.DefaultCAProviderID,
		&cfg.LogLevel,
		&cfg.CaddyLogLevel, &cfg.CaddyLogSizeMB,
		&cfg.RequestBodyMaxSizeMB, &cfg.HTTPReadTimeout, &cfg.HTTPWriteTimeout, &cfg.HTTPIdleTimeout,
		&cfg.UpstreamKeepaliveTimeout, &cfg.ProxyDialTimeout, &cfg.ProxyResponseHeaderTimeout, &cfg.ProxyReadTimeout, &cfg.ProxyWriteTimeout, &cfg.ProxyStreamTimeout, &cfg.ProxyFlushInterval, &cfg.ProxyStreamCloseDelay,
		&cfg.ServerTokensHidden, &cfg.TaskLogSizeMB, &cfg.AuditLogSizeMB, &cfg.RuntimeLogSizeMB, &cfg.AccessLogJSON, &cfg.AccessLogFormat, &cfg.AuditRetentionMonths, &cfg.JWTExpireMinutes, &cfg.Timezone, &cfg.GitHubProxyURL, &cfg.GitHubToken, &cfg.MFAWriteGuard, &cfg.MFALockoutEnabled,
		&cfg.TrustedProxyEnabled, &cfg.TrustedProxyRanges, &cfg.TrustedProxyRangeRefs, &cfg.TrustedProxyHeaders, &cfg.TrustedProxyStrict,
		&cfg.ServerMapLat, &cfg.ServerMapLon, &cfg.ThreatScreenMode, &cfg.ThreatTrafficSampleN,
		&cfg.SecurityEventsRetentionDays, &cfg.SecurityEventsRowCap,
		&cfg.IsMaster, &cfg.MasterURL, &cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt)

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取全局配置失败: " + err.Error()})
		return
	}
	// 展示口径与运行时 clamp 对齐(<10 → 60)。
	// 钳位移到 err 判定之后——err 非 nil 时 cfg 为零值
	// 废弃对象，先行钳位是对废弃对象的无意义写（顺序误导读者）。
	if cfg.SyncInterval < 10 {
		cfg.SyncInterval = 60
	} else if cfg.SyncInterval > 86400 {
		// 与运行时/节点状态阈值同界，存量脏数据不得原样展示。
		cfg.SyncInterval = 86400
	}
	// （2026-09-05 证书域审计裁定）：global_config.dns_credentials 为遗留字段
	// （签发链唯一凭证来源是 certificate_configs.dns_credentials，前端零消费，
	// v1/v2 导入走 DB 直读不受影响），GET /config 不再返回其值，恒为空串。
	// UpdateConfig 写路径与集群快照同步保留不动（v1 导入兼容）。

	cfg.HasGitHubToken = cfg.GitHubToken != ""
	// 自定义 Caddy 配置可能内联私钥或敏感 header；与规则 tls_key 同口径，
	// 非管理员及只读 API Key 不返回原文，管理员 JWT/读写 Key 保持可读。
	if c.GetString("role") != "admin" || (c.GetString("auth_type") == "api_key" && c.GetBool("api_key_read_only")) {
		cfg.CaddyConfig = ""
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: cfg})
}

func (h *Handlers) GetUpstreamHealth(c *gin.Context) {
	healthStatus, err := h.caddyService.GetUpstreamHealthDetailed()
	if err != nil {
		services.Logf("error", "collect upstream health: %v", err)
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: http.StatusBadGateway, Message: "收集上游健康状态失败"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: healthStatus})
}

// validateUpdateConfigRequest 全局配置保存/预览共用的入参校验与归一
// 此前 preview 仅共用受信代理校验，可对保存必 400
// 的载荷给出「可变更」的清单。现保存与预览调用同一实现——数值范围、日志级别
// 枚举归一、时区、采样契约、安全事件保留值域、代理 URL 白名单全部同一组校验。
func validateUpdateConfigRequest(req *models.UpdateConfigRequest) error {
	if err := validateTrustedProxyFields(req); err != nil {
		return err
	}

	if req.LogLevel != nil {
		level := strings.ToLower(strings.TrimSpace(*req.LogLevel))
		switch level {
		case "debug", "info", "warn", "error":
			*req.LogLevel = level
		default:
			return errors.New("无效的应用日志级别")
		}
	}

	// (2026-09-10 审计):与 LogLevel 同口径归一(ToLower+TrimSpace 后回写)
	// ——此前仅校验不归一,"DEBUG"/" info " 形态 400 或原样落库,两字段口径漂移。
	if req.CaddyLogLevel != nil {
		level := strings.ToLower(strings.TrimSpace(*req.CaddyLogLevel))
		switch level {
		case "debug", "info", "warn", "error":
			*req.CaddyLogLevel = level
		default:
			return errors.New("无效的 Caddy 日志级别")
		}
	}

	if req.AccessLogFormat != nil {
		if err := validateAccessLogFormat(*req.AccessLogFormat); err != nil {
			return err
		}
		// 写侧归一强制携带 X-API-Key 脱敏行（渲染层另有恒等
		// 不变量兜底旧库/直接改库/导入形态）——落库值即所见，UI 不再需要
		// 猜测渲染层偷偷追加了什么。空格式保持为空（=「不裁剪原生字段」，
		// 渲染层仍注入脱敏行）。
		*req.AccessLogFormat = normalizeAccessLogRedaction(*req.AccessLogFormat)
	}

	// 补上限与 UI:max=10240(CaddyGlobalSettings.vue)对齐——
	// 此前仅 ≥100 下限,天文值可落库使轮转实效、日志无限增长。
	if req.CaddyLogSizeMB != nil && (*req.CaddyLogSizeMB < 100 || *req.CaddyLogSizeMB > 10240) {
		return errors.New("Caddy 日志大小需在 100-10240MB 之间")
	}

	if req.DNSProvider != nil {
		switch *req.DNSProvider {
		case "dnspod":
		default:
			return errors.New("无效的 DNS 提供商")
		}
	}

	if req.CertRenewalDays != nil && (*req.CertRenewalDays < 0 || *req.CertRenewalDays > 90) {
		return errors.New("cert_renewal_days 必须在 0-90 之间")
	}

	if req.CertRenewalAttempts != nil && (*req.CertRenewalAttempts < 1 || *req.CertRenewalAttempts > 10) {
		return errors.New("cert_renewal_attempts 必须在 1-10 之间")
	}

	// cert_expiry_days 与另两个续签数值同边界（导入侧已按
	// [1,365] 钳制）——写侧缺校验会让 0/负值落库，续期窗口计算漂移。
	if req.CertExpiryDays != nil && (*req.CertExpiryDays < 1 || *req.CertExpiryDays > 365) {
		return errors.New("cert_expiry_days 必须在 1-365 之间")
	}

	if req.DefaultCAProviderID != nil {
		if err := services.ValidateDefaultCAProvider(*req.DefaultCAProviderID); err != nil {
			return err
		}
	}

	// 上限 4096MB——无上限时天文数字在渲染侧 int64 乘法（MB→字节）
	// 回绕可正可负。库值唯一真相（批 1+2）：request_body_max_size_mb 为类型①
	// 值型列（0 无效，1-4096），0 不再是「跟随全局/不限」——落库值恒有效，
	// 渲染直读零兜底。
	if req.RequestBodyMaxSizeMB != nil && (*req.RequestBodyMaxSizeMB < 1 || *req.RequestBodyMaxSizeMB > 4096) {
		return errors.New("request_body_max_size_mb 必须在 1-4096 MB 之间")
	}
	// 库值唯一真相（批 1+2）：http_read/write/idle_timeout 为类型①值型列
	// （NOT NULL DEFAULT 60/60/120+启动回填），>=1 合法——0 的「省略=引擎默认」
	// 语义废除（渲染无条件发射库值）。upstream_keepalive_timeout 保持类型②
	// 省略型（0=继承 Caddy/Go Transport 默认 2 分钟，用户裁定），仅拒负数。
	if req.HTTPReadTimeout != nil && *req.HTTPReadTimeout < 1 {
		return errors.New("http_read_timeout 必须大于 0")
	}
	if req.HTTPWriteTimeout != nil && *req.HTTPWriteTimeout < 1 {
		return errors.New("http_write_timeout 必须大于 0")
	}
	if req.HTTPIdleTimeout != nil && *req.HTTPIdleTimeout < 1 {
		return errors.New("http_idle_timeout 必须大于 0")
	}
	if req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout < 0 {
		return errors.New("Keepalive超时不能为负数")
	}
	if (req.ProxyDialTimeout != nil && *req.ProxyDialTimeout < 0) ||
		(req.ProxyResponseHeaderTimeout != nil && *req.ProxyResponseHeaderTimeout < 0) ||
		(req.ProxyReadTimeout != nil && *req.ProxyReadTimeout < 0) ||
		(req.ProxyWriteTimeout != nil && *req.ProxyWriteTimeout < 0) ||
		(req.ProxyStreamTimeout != nil && *req.ProxyStreamTimeout < 0) {
		return errors.New("代理超时时间不能为负数")
	}
	if req.ProxyFlushInterval != nil && *req.ProxyFlushInterval < -1 {
		return errors.New("代理刷新间隔不能小于 -1")
	}
	if req.ProxyStreamCloseDelay != nil && *req.ProxyStreamCloseDelay < 0 {
		return errors.New("代理流关闭延迟不能为负数")
	}

	// 与 caddy_log_size_mb同族补上限——此前仅 >0
	// 下限,天文值落库使轮转实效、日志无限增长。2026-09-25 用户裁定：上限收
	// 窄为 1024（原 10240 过宽），与 UI :max=1024 同口径。
	if req.TaskLogSizeMB != nil && (*req.TaskLogSizeMB <= 0 || *req.TaskLogSizeMB > 1024) {
		return errors.New("任务日志大小需在 1-1024MB 之间")
	}
	if req.RuntimeLogSizeMB != nil && (*req.RuntimeLogSizeMB <= 0 || *req.RuntimeLogSizeMB > 1024) {
		return errors.New("运行日志大小需在 1-1024MB 之间")
	}
	// 审计日志轮转大小上限 512MB（主节点侧校验；从节点经集群
	// 同步照单全收，配置源始终为主节点）。
	if req.AuditLogSizeMB != nil && *req.AuditLogSizeMB <= 0 {
		return errors.New("审计日志轮转大小必须大于 0")
	}
	if req.AuditLogSizeMB != nil && *req.AuditLogSizeMB > 512 {
		return errors.New("审计日志轮转大小上限 512MB")
	}
	if req.JWTExpireMinutes != nil && (*req.JWTExpireMinutes <= 0 || *req.JWTExpireMinutes > 1440) {
		return errors.New("jwt_expire_minutes 必须在 1-1440 之间")
	}
	// audit_retention_months 服务端范围校验（UI 口径 1-12）——超大值使
	// 年龄裁剪的 datetime('now', '-N days') 越出 SQLite 年份范围返回 NULL，
	// 年龄 DELETE 恒假静默失效（仅剩条数兜底）。
	if req.AuditRetentionMonths != nil && (*req.AuditRetentionMonths < 1 || *req.AuditRetentionMonths > 12) {
		return errors.New("日志保留月数必须在 1-12 之间")
	}
	// 威胁大屏本站坐标（v3）：纬度 ±90、经度 ±180，越界 400 不改库值
	// （fail-visible——静默钳位会让用户以为坐标已生效）。
	if err := validateServerMapCoordinates(req.ServerMapLat, req.ServerMapLon); err != nil {
		return err
	}
	// 威胁大屏模式（v2.3.8）：枚举白名单，非法值 400（fail-visible）
	if req.ThreatScreenMode != nil && *req.ThreatScreenMode != "map" && *req.ThreatScreenMode != "globe" {
		return errors.New("威胁大屏模式仅支持 map 或 globe")
	}
	// 大屏逐请求流量采样：仅 -1=自适应（内部从全量起步，按事件速率在 1/4/8
	// 档间滞回）、0=关闭。全量档已退役（自适应低流量等价全量）；存量 1 与
	// 固定 2..64 由启动迁移归一为 -1，写侧不再接受。
	if req.ThreatTrafficSampleN != nil {
		switch *req.ThreatTrafficSampleN {
		case -1, 0:
		default:
			return errors.New("大屏流量采样仅支持 -1（自适应）或 0（关闭）")
		}
	}
	// 安全事件保留：0=自动的旧语义废除——写侧只接受
	// 显式值（天数 1-3650、行数上限 1-1 亿）。此前接受 0 但启动迁移每次把 0
	// 改写成 90/1000000，用户显式保存的 0 重启即被静默改写（库值不再反映输入）。
	// 存量 0/NULL 由 SVC 的一次性 marker 迁移收敛，服务层保留 legacy 防御。
	if req.SecurityEventsRetentionDays != nil && (*req.SecurityEventsRetentionDays < 1 || *req.SecurityEventsRetentionDays > db.MaxSecurityEventsRetentionDays) {
		return fmt.Errorf("安全事件保留天数必须在 1 到 %d 之间", db.MaxSecurityEventsRetentionDays)
	}
	if req.SecurityEventsRowCap != nil && (*req.SecurityEventsRowCap < 1 || *req.SecurityEventsRowCap > db.MaxSecurityEventsRowCap) {
		return fmt.Errorf("安全事件行数上限必须在 1 到 %d 之间", db.MaxSecurityEventsRowCap)
	}
	if req.Timezone != nil {
		// 空串必须显式拒绝（time.LoadLocation("") 是合法特殊值=UTC）：否则
		// 落库后读侧 COALESCE 只兜 NULL，全站展示/审计窗口静默切 UTC。
		if err := services.ValidateLocationName(*req.Timezone); err != nil {
			return err
		}
	}

	// GitHub 加速代理仅允许内置选项（防 SSRF），CRS/IP2Region 下载共用。
	if req.GitHubProxyURL != nil {
		if err := services.ValidateGitHubProxyURL(*req.GitHubProxyURL); err != nil {
			return err
		}
	}

	return nil
}

func (h *Handlers) PreviewConfigUpdate(c *gin.Context) {
	var req models.UpdateConfigRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	if err := validateUpdateConfigRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	// 与 UpdateConfig 同门：preview 200 后 PUT 不应因存量规则聚合校验变 400
	if err := validateEnabledStoredRuleConfigs(c.Request.Context()); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	old, err := loadConfigSnapshot()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前配置失败"})
		return
	}
	plan := planConfigChanges(req, old)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: plan})
}

// isPureConfigValidationError 展开 errors.Join 树，判定全部叶子均为
// *configValidationError（含 fmt.Errorf %w 包装的配置错误）。
func isPureConfigValidationError(err error) bool {
	if err == nil {
		return false
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		for _, child := range joined.Unwrap() {
			if !isPureConfigValidationError(child) {
				return false
			}
		}
		return true
	}
	var validationErr *configValidationError
	return errors.As(err, &validationErr)
}

// writeConfigValidationFailure 映射聚合预校验错误。新发现4：纯配置错误
// 保持 400 且展示全部规则问题；一旦混入非配置类错误（DB 故障
// 等），改映射 500 通用文案并记日志——否则 400 消息携带底层 DB 错误文本，
// 客户端会把服务端故障误判为配置问题。
func writeConfigValidationFailure(c *gin.Context, err error) {
	var validationErr *configValidationError
	if !errors.As(err, &validationErr) {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败: " + err.Error()})
		return
	}
	if !isPureConfigValidationError(err) {
		services.Logf("error", "更新全局配置的规则预校验混入非配置类错误：%v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "预校验规则配置失败"})
		return
	}
	c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
}

func (h *Handlers) UpdateConfig(c *gin.Context) {
	// global_config 全量替换的写者：导入窗口内提交会被导入静默覆盖，事务开启
	// 后则排队至导入结束（客户端早已超时但请求仍在导入后落库）——与同族
	// settings 写者同口径 409 fast-fail，且必须在取 caddyOpMu 之前早退。
	if rejectWriteDuringImport(c, "保存基础设置（配置导入进行中）") {
		return
	}
	var req models.UpdateConfigRequest
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}

	// 与规则写路径同一锁序：先 caddyOpMu，DB 写入与 Caddy 应用全程持锁
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if err := validateUpdateConfigRequest(&req); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	old, err := loadConfigSnapshot()
	if err != nil {
		// 保存端点服务端失败分支留痕（操作者归因 + 错误详情），
		// 此前仅成功路径写审计；动作复用既有 danger 词条「更新失败」。
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("读取当前配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取当前配置失败"})
		return
	}
	// access_log_json=false 时 access_log_format 不生效（渲染层
	// buildAccessLogEncoder 仅在 json=true 时消费自定义映射）。同一请求显式
	// 携带非空格式 → 400（不静默丢弃用户输入）；json 关闭后的存量残留格式 →
	// 归一清空并在响应披露（配置变更审计的 access_log_format 字段变更同时留痕）。
	formatCleared := false
	effectiveAccessLogJSON := old.AccessLogJSON
	if req.AccessLogJSON != nil {
		effectiveAccessLogJSON = *req.AccessLogJSON
	}
	if !effectiveAccessLogJSON {
		if req.AccessLogFormat != nil && strings.TrimSpace(*req.AccessLogFormat) != "" {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "访问日志 JSON 输出已关闭，自定义字段映射不生效：请先开启 JSON 输出，或清空访问日志格式"})
			return
		}
		storedFormat := old.AccessLogFormat
		if req.AccessLogFormat != nil {
			storedFormat = *req.AccessLogFormat
		}
		if storedFormat != "" {
			emptyFormat := ""
			req.AccessLogFormat = &emptyFormat
			formatCleared = true
		}
	}
	plan := planConfigChanges(req, old)
	if !plan.Changed {
		recordAudit(c, "更新", plan.Section, "无修改")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置无变化", Data: plan})
		return
	}

	if err := validateEnabledStoredRuleConfigs(c.Request.Context()); err != nil {
		writeConfigValidationFailure(c, err)
		return
	}

	// 2026-09-07 裁定：撤 pre-tx /load 探针（与 ④'「探针已撤除」对齐）——
	// 候选合法性由 applyFromTxNote 内 CLI 真 validate-only + 事务内应用承担；
	// 探针曾使 SQL 失败分支面临「运行配置已换候选但 DB 未提交」的分叉，
	// 撤除后该窗口不存在。只读快照保留，仅供提交失败回弹使用。
	oldRuntimeConfig, err := h.caddyService.GetConfig()
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("获取当前 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取当前 Caddy 配置失败"})
		return
	}

	// Validation passed — write in a transaction; Caddy applies the uncommitted
	// state and the transaction only commits after a successful apply, so a
	// failed apply leaves DB and env unchanged.
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("开启配置事务失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启配置事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "UpdateConfig rollback failed: %v", rollbackErr)
			}
		}
	}()
	// 可空列（dns_credentials/acme_email/access_log_format/default_ca_provider_id）需支持
	// 清空：传空值即置 NULL（COALESCE 无法区分“未传”与“清空”）。其余列保留 COALESCE 语义
	// —— 未传(nil) 保持原值。CASE WHEN ? IS NULL 用于区分 nil 与空字符串。
	res, err := tx.Exec(`
			UPDATE global_config SET
				dns_provider = COALESCE(?, dns_provider),
				dns_credentials = CASE WHEN ? IS NULL THEN dns_credentials ELSE NULLIF(?, '') END,
				acme_email = CASE WHEN ? IS NULL THEN acme_email ELSE NULLIF(?, '') END,
				cert_expiry_days = COALESCE(?, cert_expiry_days),
				cert_renewal_days = COALESCE(?, cert_renewal_days),
				cert_renewal_attempts = COALESCE(?, cert_renewal_attempts),
				default_ca_provider_id = CASE WHEN ? IS NULL THEN default_ca_provider_id ELSE NULLIF(?, 0) END,
				log_level = COALESCE(?, log_level),
				caddy_log_level = COALESCE(?, caddy_log_level),
				caddy_log_size_mb = COALESCE(?, caddy_log_size_mb),
				request_body_max_size_mb = COALESCE(?, request_body_max_size_mb),
				http_read_timeout = COALESCE(?, http_read_timeout),
				http_write_timeout = COALESCE(?, http_write_timeout),
				http_idle_timeout = COALESCE(?, http_idle_timeout),
				upstream_keepalive_timeout = COALESCE(?, upstream_keepalive_timeout),
				proxy_dial_timeout = COALESCE(?, proxy_dial_timeout),
				proxy_response_header_timeout = COALESCE(?, proxy_response_header_timeout),
				proxy_read_timeout = COALESCE(?, proxy_read_timeout),
				proxy_write_timeout = COALESCE(?, proxy_write_timeout),
				proxy_stream_timeout = COALESCE(?, proxy_stream_timeout),
				proxy_flush_interval = COALESCE(?, proxy_flush_interval),
				proxy_stream_close_delay = COALESCE(?, proxy_stream_close_delay),
				server_tokens_hidden = COALESCE(?, server_tokens_hidden),
				task_log_size_mb = COALESCE(?, task_log_size_mb),
				audit_log_size_mb = COALESCE(?, audit_log_size_mb),
				runtime_log_size_mb = COALESCE(?, runtime_log_size_mb),
				access_log_json = COALESCE(?, access_log_json),
				access_log_format = CASE WHEN ? IS NULL THEN access_log_format ELSE NULLIF(?, '') END,
			audit_retention_months = COALESCE(?, audit_retention_months),
			jwt_expire_minutes = COALESCE(?, jwt_expire_minutes),
				timezone = COALESCE(?, timezone),
				github_proxy_url = COALESCE(?, github_proxy_url),
				github_token = CASE WHEN ? IS NULL THEN github_token ELSE ? END,
				mfa_write_guard = COALESCE(?, mfa_write_guard),
				mfa_lockout_enabled = COALESCE(?, mfa_lockout_enabled),
				trusted_proxy_enabled = COALESCE(?, trusted_proxy_enabled),
				trusted_proxy_ranges = COALESCE(?, trusted_proxy_ranges),
				trusted_proxy_range_refs = COALESCE(?, trusted_proxy_range_refs),
				trusted_proxy_headers = COALESCE(?, trusted_proxy_headers),
				trusted_proxy_strict = COALESCE(?, trusted_proxy_strict),
				server_map_lat = COALESCE(?, server_map_lat),
				server_map_lon = COALESCE(?, server_map_lon),
				threat_screen_mode = COALESCE(?, threat_screen_mode),
				threat_traffic_sample_n = COALESCE(?, threat_traffic_sample_n),
				security_events_retention_days = COALESCE(?, security_events_retention_days),
				security_events_row_cap = COALESCE(?, security_events_row_cap),
				updated_at = datetime('now')
			WHERE id = 1
		`, req.DNSProvider, req.DNSCredentials, req.DNSCredentials, req.ACMEEmail, req.ACMEEmail, req.CertExpiryDays, req.CertRenewalDays, req.CertRenewalAttempts, req.DefaultCAProviderID, req.DefaultCAProviderID, req.LogLevel,
		req.CaddyLogLevel, req.CaddyLogSizeMB,
		req.RequestBodyMaxSizeMB, req.HTTPReadTimeout, req.HTTPWriteTimeout, req.HTTPIdleTimeout,
		req.UpstreamKeepaliveTimeout, req.ProxyDialTimeout, req.ProxyResponseHeaderTimeout, req.ProxyReadTimeout, req.ProxyWriteTimeout, req.ProxyStreamTimeout, req.ProxyFlushInterval, req.ProxyStreamCloseDelay,
		req.ServerTokensHidden, req.TaskLogSizeMB, req.AuditLogSizeMB, req.RuntimeLogSizeMB, req.AccessLogJSON, req.AccessLogFormat, req.AccessLogFormat, req.AuditRetentionMonths, req.JWTExpireMinutes, req.Timezone, req.GitHubProxyURL, req.GitHubToken, req.GitHubToken, req.MFAWriteGuard, req.MFALockoutEnabled,
		req.TrustedProxyEnabled, req.TrustedProxyRanges, req.TrustedProxyRangeRefs, req.TrustedProxyHeaders, req.TrustedProxyStrict,
		req.ServerMapLat, req.ServerMapLon, req.ThreatScreenMode, req.ThreatTrafficSampleN, req.SecurityEventsRetentionDays, req.SecurityEventsRowCap)
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败"})
		return
	}
	rows, err := res.RowsAffected()
	if err != nil {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置写入数据库失败"})
		return
	}
	if rows != 1 {
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("配置写入数据库失败", fmt.Sprintf("影响记录数为 %d", rows), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("配置写入数据库失败: 影响记录数为 %d", rows)})
		return
	}
	// 主节点坐标是未单独配置坐标的从节点的默认值：变化时必须 bump 集群版本，
	// 否则从节点 304 继续使用旧默认值；server_map 仍不进入 global_config
	// 通用同步列/触发器（按节点 node_sites 下发）。
	siteChanged := (req.ServerMapLat != nil && *req.ServerMapLat != old.ServerMapLat) ||
		(req.ServerMapLon != nil && *req.ServerMapLon != old.ServerMapLon)
	if siteChanged {
		if err := services.BumpClusterVersion(c.Request.Context(), tx); err != nil {
			recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("递增集群版本失败", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "递增集群版本失败"})
			return
		}
	}

	// rulesWrittenInTx=false：本事务只写 global_config（lb_rules 视图与已提交
	// 视图恒一致），ACME 谓词 miss 补查在本路径无意义（逐 acme 规则空查）。
	reloadNote, applyErr := h.applyFromTxNote(c, tx, "保存配置后自动重载", false)
	if applyErr != nil {
		// CLI 预检/事务内应用两轮渲染已按未提交内容重写
		// 投影（tp.txt 等）——tx 回滚的同时把磁盘回退到已提交态（零 /load）。
		h.caddyService.RollbackIPListProjectionsToCommittedInLock()
		restoreErr := h.caddyService.ApplyConfig(oldRuntimeConfig)
		applyErr = errors.Join(applyErr, restoreErr)
		// 回弹也可能失败（Caddy 不可达/超时）——运行
		// 配置可能停留候选态而 DB 已回滚，仅响应+审计会在重启后消失。先显式
		// 回滚事务释放写锁，再持久化横幅（recordCaddyApplyResult 写主库）。
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			applyErr = errors.Join(applyErr, rbErr)
		}
		h.recordCaddyApplyResult(applyErr)
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail("Caddy 配置应用失败", applyErr.Error(), services.AuditResultPart("failure")))
		// 2026-09-07：与规则域统一——配置拒绝→400，传输/系统→500。
		if services.IsConfigRejected(applyErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过，配置未保存: " + applyErr.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置应用失败，配置未保存: " + applyErr.Error()})
		}
		return
	}
	if err := tx.Commit(); err != nil {
		// +: apply 已把未提交事务视图的投影/证书写盘并把
		// 该内容写入 LKG；commit 失败统一走已提交视图恢复（回滚事务 + 重渲染
		// /load + 回退 LKG——恢复 /load 失败时仍把已提交字节写回 LKG）。
		restoreErr := h.recoverCommittedViewAfterCommitFailure(tx)
		err = errors.Join(err, restoreErr)
		// 提交失败后的回弹同样可能失败——持久化横幅（事务已回滚）。
		h.recordCaddyApplyResult(err)
		recordAudit(c, "更新失败", "全局配置", services.FormatAuditDetail(commitUncertainLabel+"："+err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: commitUncertainLabel + "：" + err.Error()})
		return
	}
	committed = true
	// 成功清横幅由 reloadNote 单收口；此处重复 UPDATE
	// 只增加写放大且违反「note 唯一收口」约定。
	services.ApplyLogLevel()
	// task_log_size_mb 经本端点写库，服务端 5 分钟 TTL
	// 缓存此前零失效点——改设置后最长 5 分钟仍按旧阈值滚动任务日志。无条件
	// 失效（幂等、零成本；其余写入口已在各自域补齐）。
	services.InvalidateTaskLogSizeCache()
	if req.Timezone != nil {
		if _, err := services.ConfigureLocation(*req.Timezone); err != nil {
			// 时区已在写库前经 time.LoadLocation 预校验，
			// 此分支仅可能为环境级异常；配置已提交并应用，宣告 500 更新失败会
			// 误导客户端（重试=重复写同一已生效值）。降级为错误日志，响应保持成功。
			services.Logf("error", "配置已提交并应用，但运行时应用时区失败（提交前已预校验，疑似环境异常）: %v", err)
		}
	}

	if len(plan.SectionChanges) > 0 {
		for section, fields := range plan.SectionChanges {
			recordAudit(c, "更新", section, fmt.Sprintf("修改了: %s", strings.Join(fields, ", ")))
		}
	}

	reloadNote()

	message := "配置已更新并应用"
	if formatCleared {
		message += "（访问日志 JSON 已关闭，自定义格式已清空：该格式不生效）"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: message, Data: plan})
}

func (h *Handlers) ValidateConfig(c *gin.Context) {
	// 先读请求体再取写锁（UpdateConfig/PutCaddyConfig 同序）——
	// 已认证客户端的慢速/chunked 上传此前在持有 caddyOpMu 时读 body，会阻塞
	// 全部规则/配置写与后台强制重载。全局 body 上限可配到 4096MB，窗口可观。
	var configData map[string]interface{}
	if !guardConfiguredJSONBody(c) {
		return
	}
	if err := c.ShouldBindJSON(&configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的配置 JSON"})
		return
	}
	rendered, err := json.Marshal(configData)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的配置 JSON"})
		return
	}
	// CLI 不可用回退路径仍执行真实 /load，保持与其他写
	// 端点共享 caddyOpMu。
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	// 2026-09-06 裁定 ④' 收口：真 validate-only（caddy CLI，零运行时扰动），
	// 与 apidocs「不触发 Caddy」的既有承诺对齐；CLI 不可用回退 -c
	// 的 load+回弹口径。
	if err := h.caddyService.ValidateJSONViaCLI(rendered); err == nil {
		recordAudit(c, "校验成功", "Caddy配置", services.FormatAuditDetail("配置校验", services.AuditResultPart("success")))
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置有效"})
		return
	} else if !errors.Is(err, services.ErrCLIValidatorUnavailable) {
		recordAudit(c, "校验失败", "Caddy配置", services.FormatAuditDetail("配置校验", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败", Data: err.Error()})
		return
	}
	// CLI 校验器不可用回退：-c——/load 无 validate-only 语义，候选
	// 载荷会成为运行配置。候选可能已被 Caddy 加载后请求才
	// 断连/超时（客户端看到传输错误），因此**无论 ValidateConfig 成功或
	// 失败**都必须回弹 DB 权威全量配置；只有回弹成功才允许把错误归类为
	// 「配置无效」（400），传输/系统错误映射 500，回弹失败一律 500 并
	// join 双错误（与 UpdateConfig/PutCaddyConfig 的失败快照恢复同口径）。
	validateErr := h.caddyService.ValidateConfig(configData)
	restoreErr := h.caddyService.ApplyConfig(services.GenerateCaddyConfig())
	if restoreErr != nil {
		joined := errors.Join(validateErr, restoreErr)
		recordAudit(c, "校验失败", "Caddy配置", services.FormatAuditDetail(
			"校验回退加载后恢复权威配置失败，运行配置可能停留为校验载荷", joined.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置校验后恢复运行配置失败: " + joined.Error()})
		return
	}
	if validateErr != nil {
		recordAudit(c, "校验失败", "Caddy配置", services.FormatAuditDetail("配置校验", validateErr.Error(), services.AuditResultPart("failure")))
		if services.IsConfigRejected(validateErr) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "配置验证失败", Data: validateErr.Error()})
			return
		}
		// 传输/超时等系统故障不得伪装成「配置无效」——候选是否被拒未知，
		// 但运行配置已回弹权威值。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "配置校验请求失败（运行配置已恢复）: " + validateErr.Error()})
		return
	}

	recordAudit(c, "校验成功", "Caddy配置", services.FormatAuditDetail("配置校验", services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置有效"})
}

func (h *Handlers) ReloadCaddy(c *gin.Context) {
	if err := h.applyCaddyConfigE(); err != nil {
		// 手动重载恰是最需要留痕的操作——失败分支记录
		// 操作者归因 + 错误详情（recordCaddyApplyResult 的系统级「应用失败」
		// 不带用户身份，不能替代本条）。
		recordAudit(c, "重载失败", "Caddy服务", services.FormatAuditDetail("手动重载 Caddy 配置", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置重载失败: " + err.Error()})
		return
	}
	// 手动重载成功同样需要留痕（69d809b4 曾误删本行）。
	recordAudit(c, "重载", "Caddy服务", "手动重载 Caddy 配置")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 配置已重载"})
}

func (h *Handlers) GetCaddyStatus(c *gin.Context) {
	applyError := ""
	if db.DB != nil {
		// 读取失败不再静默吞——apply_error 缺失会让
		// 状态接口丢失真实失败横幅,需 warn 留痕。
		if err := db.DB.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&applyError); err != nil {
			services.Logf("warn", "GetCaddyStatus: 读取 caddy_apply_error 失败(状态接口 apply_error 字段为空): %v", err)
		}
	}
	drift := services.CurrentConfigDrift()
	pid := caddyLivePID()
	// 审计项：后台数据类重载失败面（证书部署/CRS/IP2Region/威胁库/自动封禁）
	// 与 handler 写路径的 caddy_apply_error 分开呈现——后者是「保存失败」，
	// 前者是「库已更新但运行配置未收敛」。
	backgroundApplyError := services.BackgroundApplyFailureBanner()
	statusData := func(state string) map[string]string {
		return map[string]string{
			"status":                 state,
			"pid":                    strconv.Itoa(pid),
			"apply_error":            applyError,
			"background_apply_error": backgroundApplyError,
			"config_consistent":      strconv.FormatBool(drift.Consistent),
			"config_drift":           driftBannerText(drift),
			"config_drift_since":     driftSinceText(drift),
		}
	}
	resp, err := caddyAdminGet(c.Request.Context(), h.cfg.CaddyAdminURL, "/config/", 2*time.Second)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("running")})
			return
		}
	}
	// /config/ 不可达时按 /proc 判定进程存活（替换 GNU ps 管线：busybox ps 不支持 -p，
	// 原实现 'ps -o state= -p' 在容器内恒判 stopped）。
	if caddyProcessRunning() {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("running")})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: statusData("stopped")})
}

// driftBannerText 生成前端全局横幅的主文案（一致时为空串；检测时间
// 拆出到 driftSinceText 供 meta 次行展示，不再内嵌正文）。
func driftBannerText(drift services.ConfigDriftStatus) string {
	if drift.Consistent {
		return ""
	}
	return formatDriftBanner(drift.Missing, drift.Extra)
}

// driftSinceText 漂移首次检测时间（一致时为空串）。
func driftSinceText(drift services.ConfigDriftStatus) string {
	if drift.Consistent {
		return ""
	}
	return drift.Since
}

func formatDriftBanner(missing, extra []string) string {
	// 文案与长度上限单源在 services（看门狗审计同源）——此处
	// 仅保留 handler 层命名供既有调用/测试使用。
	return services.FormatDriftRoutes(missing, extra)
}

func (h *Handlers) GetCaddyConfig(c *gin.Context) {
	// 原始运行配置可能含经 PUT /caddy/config 逃生口写入的内联私钥
	// 或敏感 header——与 GetConfig 的 caddy_config 脱敏同口径：非管理员及
	// 只读 API Key 一律拒绝（路由已收敛到 admin 组，此处为纵深防御）。
	if c.GetString("role") != "admin" || (c.GetString("auth_type") == "api_key" && c.GetBool("api_key_read_only")) {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "仅管理员可读取原始 Caddy 配置"})
		return
	}
	// 与 GetCaddyStatus 同源取 cfg.CaddyAdminURL——此前硬编码
	// localhost:2019，自定义 admin 地址的部署读到的是错误端点。
	resp, err := caddyAdminGet(c.Request.Context(), h.cfg.CaddyAdminURL, "/config/", 5*time.Second)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "连接 Caddy 失败: " + err.Error()})
		return
	}
	defer resp.Body.Close()
	// 状态分类 + 32MB+1 探测统一走 services.ReadAdminConfigBody（裸 LimitReader
	// 静默截断会把「超限」误报为下游「解析失败」，排障误导）。
	body, err := services.ReadAdminConfigBody(resp)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 Caddy 配置失败: " + err.Error()})
		return
	}
	var configData interface{}
	if err := json.Unmarshal(body, &configData); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "解析 Caddy 配置失败: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: configData})
}

// caddyLogPaths 四份 Caddy 日志的固定路径（写入端写死 /app/logs，与 LOG_FILE
// 无关——见 logstats.go logPaths 注释）。包级 var 支持测试注入
// （wafAuditLogFile/defaultRuntimeLogPath 同模式）。
var caddyLogPaths = map[string]string{
	"runtime": "/app/logs/caddy.log",
	"tls":     "/app/logs/caddy-tls.log",
	"server":  "/app/logs/caddy-server.log",
	"proxy":   "/app/logs/caddy-proxy.log",
}

// caddyLogsStatHook 是测试专用钩子（生产恒 nil）：在 Stat 成功之后、打开并
// 读取之前触发，用于模拟「Stat 与 Read 之间日志增长」的窗口（回归测试
// 读取必须受 128KB 窗口上限约束，不得随增长无界放大）。
var caddyLogsStatHook func()

func (h *Handlers) GetCaddyLogs(c *gin.Context) {
	logType := c.DefaultQuery("type", "runtime")
	logPath, ok := caddyLogPaths[logType]
	if !ok {
		logPath = caddyLogPaths["runtime"]
	}

	const maxBytes = 128 * 1024
	const maxLines = 500

	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": ""}})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "日志文件不可访问: " + err.Error()})
		return
	}

	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}
	// 测试专用钩子（生产恒 nil）：在 Stat 与读取之间模拟日志增长，钉住
	// 「读取严格受窗口上限约束」的不变量。
	if caddyLogsStatHook != nil {
		caddyLogsStatHook()
	}

	f, err := os.Open(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "打开日志文件失败: " + err.Error()})
		return
	}
	defer f.Close()

	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志文件失败: " + err.Error()})
		return
	}

	// 与 certjobs.readCertJobLogFile 同源形态——
	// Stat 与 Read 之间日志增长（高流量 + 轮转滞后）时，裸 ReadAll 会突破
	// 128KB 尾窗上限；LimitReader 把读取严格钉在窗口大小。
	data, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志文件失败: " + err.Error()})
		return
	}
	// 尾窗首行残段截断统一走 tailLogWindow
	// 口径——窗口内无 '\n' 时整窗为同一巨行中段，输出为空；此前此处分叉
	// 返回原始中段，多字节 rune 切断处 U+FFFD 污染）。
	data = tailLogWindow(data, startOffset)

	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	content := convertLogTimezone(strings.Join(lines, "\n"))

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": content}})
}

var logTimeRe = regexp.MustCompile(`^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}\.\d+)`)

func convertLogTimezone(content string) string {
	var tzStr string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,?) FROM global_config WHERE id=1", db.DefaultTimezone).Scan(&tzStr); err != nil {
		return content
	}
	loc, err := time.LoadLocation(tzStr)
	if err != nil || loc.String() == "UTC" {
		return content
	}
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		m := logTimeRe.FindString(line)
		if m == "" {
			continue
		}
		t, err := time.ParseInLocation("2006/01/02 15:04:05.000", m, time.UTC)
		if err != nil {
			continue
		}
		lines[i] = t.In(loc).Format("2006/01/02 15:04:05.000") + line[len(m):]
	}
	return strings.Join(lines, "\n")
}

func (h *Handlers) PutCaddyConfig(c *gin.Context) {
	// 限制请求体大小防止超大 JSON 全量缓冲（与 CreateRule
	// maxCreateRuleBodyBytes 同口径）。
	const maxPutCaddyConfigBytes int64 = 1 << 20 // 1MB
	if c.Request.ContentLength > maxPutCaddyConfigBytes {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxPutCaddyConfigBytes)

	// 先读请求体再取写锁（ValidateConfig
	// 同序）——已认证客户端的慢速/chunked 上传在持锁期间读 body 会阻塞全部
	// 规则/配置写与后台强制重载。
	var req struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		// MaxBytesReader 超限（chunked/未知 ContentLength）映射 413，与导入路径口径一致
		if isRequestBodyTooLarge(err) {
			c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "请求体过大"})
			return
		}
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}

	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	var configData map[string]interface{}
	if err := json.Unmarshal([]byte(req.Content), &configData); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的 JSON 配置"})
		return
	}

	// 2026-09-06 裁定 ④' 边界补齐：逃生口同样过 Caddy CLI 校验层——校验输入
	// 即将应用的原始 JSON。校验器不可用放行（下方 ApplyConfig 拒绝即回滚）。
	if err := h.caddyService.ValidateJSONViaCLI([]byte(req.Content)); err != nil {
		if !errors.Is(err, services.ErrCLIValidatorUnavailable) {
			recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("Caddy 配置校验未通过", err.Error(), services.AuditResultPart("failure")))
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置校验未通过: " + err.Error()})
			return
		}
		services.Logf("error", "caddy CLI 校验器不可用，跳过逃生口预检（应用拒绝仍回滚）: %v", err)
	}

	runtimeSnapshot, err := h.snapshotImportRuntime(nil)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("备份当前 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "备份当前 Caddy 配置失败: " + err.Error()})
		return
	}
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("开启 Caddy 配置事务失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启 Caddy 配置事务失败: " + err.Error()})
		return
	}
	committed := false
	defer func() {
		if !committed {
			if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
				services.Logf("error", "PutCaddyConfig rollback failed: %v", rollbackErr)
			}
		}
	}()
	result, err := tx.ExecContext(c.Request.Context(), "UPDATE global_config SET caddy_config=?, updated_at=datetime('now') WHERE id=1", req.Content)
	if err != nil {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("保存 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败: " + err.Error()})
		return
	}
	rowsAffected, err := result.RowsAffected()
	if err != nil || rowsAffected == 0 {
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("保存 Caddy 配置失败", fmt.Sprintf("影响记录数为 %d", rowsAffected), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "保存 Caddy 配置失败"})
		return
	}
	loaded, applyErr := h.caddyService.ApplyConfigReporting(configData)
	if err := applyErr; err != nil {
		rollbackErr := tx.Rollback()
		if errors.Is(rollbackErr, sql.ErrTxDone) {
			rollbackErr = nil
		}
		restoreErr := h.restoreImportRuntime(runtimeSnapshot)
		err = errors.Join(err, rollbackErr, restoreErr)
		// 回弹失败持久化横幅（事务已显式回滚）。
		h.recordCaddyApplyResult(err)
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("Caddy 配置应用失败", err.Error(), services.AuditResultPart("failure")))
		// 2026-09-07：与统一——配置拒绝→400，传输/系统→500。
		if services.IsConfigRejected(err) {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 拒绝配置: " + err.Error()})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 配置应用失败，配置未保存: " + err.Error()})
		}
		return
	}
	if err := tx.Commit(); err != nil {
		// commit 失败统一走已提交视图恢复（回滚事务 + 重渲染
		// /load + 回退 LKG/投影/证书物化——恢复 /load 失败时仍把已提交字节
		// 写回 LKG，运行配置不停留在一次性逃生口载荷上）。
		restoreErr := h.recoverCommittedViewAfterCommitFailure(tx)
		err = errors.Join(err, restoreErr)
		h.recordCaddyApplyResult(err)
		recordAudit(c, "更新失败", "Caddy配置", services.FormatAuditDetail("提交 Caddy 配置失败", err.Error(), services.AuditResultPart("failure")))
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交 Caddy 配置失败: " + err.Error()})
		return
	}
	committed = true
	// 2026-09-07 裁定：同 UpdateConfig——成功后清除既往失败标记。
	h.recordCaddyApplyResult(nil)

	recordAudit(c, "更新", "Caddy配置", "保存 Caddy 全局配置")
	// 事务型路径重载审计（69d809b4 曾误删，2026-09-06 恢复）。
	// 2026-09-25 审计真实性裁定：仅在真实 /load 发生时落笔——自定义配置与
	// 运行配置同字节时短路零 provision，记「重载」即虚假事件。
	if loaded {
		recordAudit(c, "重载", "Caddy服务", "保存配置后自动重载")
	}
	// （裁决：保留逃生口 + 明示后果）：自定义 Caddy 配置是
	// 一次性逃生口，数据库生成器从不消费 caddy_config 列——任何后续规则/
	// 配置变更或集群同步都会以权威生成配置覆盖它。保存成功即明示。
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "配置已保存（注意：自定义配置为一次性逃生口，任何后续规则/配置变更或集群同步都会以数据库生成的权威配置覆盖它）"})
}

func (h *Handlers) StartCaddy(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// `caddy run` boots with the bare Caddyfile (welcome page); re-apply the
	// database-generated config so every rule survives a Caddy restart.
	// caddyApplyNoteLocked: caller already holds caddyOpMu (applyCaddyConfigE
	// would re-lock the non-reentrant mutex and deadlock).
	if note := h.caddyApplyNoteLocked(); note != "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 已启动但配置应用失败: " + note})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已启动"})
}

func (h *Handlers) StopCaddy(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已停止"})
}

func (h *Handlers) RestartCaddy(c *gin.Context) {
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()

	if err := stopCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	if err := startCaddy(h.cfg.CaddyAdminURL); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	// Same as StartCaddy: caller holds caddyOpMu, use the locked variant.
	if note := h.caddyApplyNoteLocked(); note != "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Caddy 已重启但配置应用失败: " + note})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Caddy 已重启"})
}

// accessLogRedactionLine 恒脱敏行的规范形态（与 services 渲染层同一路径，
// 此处是该契约的写入侧视图）。
const accessLogRedactionLine = "request>headers>X-API-Key -> delete"

// normalizeAccessLogRedaction 把脱敏行归一为规范形态
// 移除任何既有的 X-API-Key 映射行（rename 会让头改道，delete 可能写在中间
// 被后续行覆盖），再追加唯一的 delete 行——幂等。解析单源
// services.ParseAccessLogFormat（按行号定位脱敏行，其余行原文保留）；
// 非法行由写侧 validateAccessLogFormat 先行 400，本函数不重复拒绝。
// 空白格式原样返回（默认形态：不裁剪原生字段，渲染层注入脱敏行）。
func normalizeAccessLogRedaction(format string) string {
	if strings.TrimSpace(format) == "" {
		return format
	}
	const path = "request>headers>X-API-Key"
	redactLines := make(map[int]bool)
	for _, r := range services.ParseAccessLogFormat(format).Rules {
		if r.Path == path {
			redactLines[r.Line] = true
		}
	}
	out := make([]string, 0, 8)
	for i, line := range strings.Split(format, "\n") {
		if redactLines[i+1] {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(append(out, accessLogRedactionLine), "\n")
}

// validateAccessLogFormat enforces the fields the log stats feature relies
// on: a client IP and a request URI must survive the format (present natively
// or renamed, never deleted). 非法行（非 `路径 -> 动作` 形态）400 点名行号
// ——解析单源 services.ParseAccessLogFormat，与渲染层零口径差。
func validateAccessLogFormat(format string) error {
	if strings.TrimSpace(format) == "" {
		return nil
	}
	parsed := services.ParseAccessLogFormat(format)
	if len(parsed.Invalid) > 0 {
		return fmt.Errorf("日志格式第 %d 行无效：需要 `路径 -> delete/新名` 形式", parsed.Invalid[0])
	}
	type rule struct {
		path   string
		action string
	}
	var rules []rule
	for _, r := range parsed.Rules {
		rules = append(rules, rule{r.Path, r.Action})
	}
	fieldKept := func(paths ...string) bool {
		for _, p := range paths {
			for _, r := range rules {
				if r.action != "delete" {
					continue
				}
				// 祖先路径同样致命——删除 request 整树会连带抹掉
				// remote_ip/uri/headers 全部统计字段；精确相等或 r.path 是
				// 受保护路径的祖先前缀（request 是 request>remote_ip 的前缀）
				// 均视为删除。
				if r.path == p || strings.HasPrefix(p, r.path+">") {
					return false
				}
			}
		}
		return true
	}
	if !fieldKept("request>remote_ip", "request>client_ip") {
		return fmt.Errorf("日志格式不能删除客户端 IP 字段（request>remote_ip / request>client_ip），日志统计依赖该字段")
	}
	if !fieldKept("request>uri") {
		return fmt.Errorf("日志格式不能删除 URI 字段（request>uri），日志统计依赖该字段")
	}
	if !fieldKept("request>headers") {
		return fmt.Errorf("日志格式不能删除请求头（request>headers），UA 统计依赖该字段")
	}
	if !fieldKept("request>headers>User-Agent") {
		return fmt.Errorf("日志格式不能删除 User-Agent 字段（request>headers>User-Agent），UA 统计依赖该字段")
	}
	renameAlias := func(paths []string, allowed []string) error {
		for _, p := range paths {
			for _, r := range rules {
				if r.action == "delete" || r.action == "" {
					continue
				}
				// 父级改名同样移走子树（request>headers 改名会把
				// 一并带走）——祖先前缀视为命中。
				if r.path != p && !strings.HasPrefix(p, r.path+">") {
					continue
				}
				ok := false
				for _, a := range allowed {
					if r.action == a {
						ok = true
						break
					}
				}
				if !ok {
					return fmt.Errorf("字段 %s 重命名为 %s 后统计将无法识别，仅支持：%s", p, r.action, strings.Join(allowed, " / "))
				}
			}
		}
		return nil
	}
	if err := renameAlias([]string{"request>remote_ip", "request>client_ip"}, []string{"src", "src_ip"}); err != nil {
		return err
	}
	if err := renameAlias([]string{"request>uri"}, []string{"uri_path"}); err != nil {
		return err
	}
	// 祖先前缀同样命中——request>headers 或 request
	// 整树改名会连带移走 （与:1082-1088 fieldKept 的祖先删除、
	// :1111-1114 renameAlias 的祖先前缀同口径）。
	for _, r := range rules {
		if r.action == "" || r.action == "delete" {
			continue
		}
		const uaPath = "request>headers>User-Agent"
		if r.path == uaPath || strings.HasPrefix(uaPath, r.path+">") {
			return fmt.Errorf("User-Agent 字段不能重命名（%s），UA 统计依赖固定字段名", r.path)
		}
	}
	return nil
}
