package services

// 任务引擎接线（v2.0 四类型标准）：Kind 决定调度/记录/日志——零 flag。
// 定时(4)：NextSlotFn 排程槽驱动，Run 纯业务（无到期检查）
// 常驻(3)：Run 阻塞自管理循环，引擎仅管生命周期
// 循环(8)：IntervalFn 固定间隔，每轮独立执行+记录
// 触发(1)：仅手动/代码触发
// cert-waiting-ca：默认调度关闭——cert-renewal-scan 入队时唤醒，全部终态自动停。

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

var taskEngine *taskengine.Engine

// configLoadRerun 系统配置载入手动重载钩子（main 注入：DB 渲染→强制应用）。
var configLoadRerun func() error

// SetConfigLoadRerun 注入手动重载实现。
func SetConfigLoadRerun(fn func() error) { configLoadRerun = fn }

// TaskEngine 返回全局引擎实例（未初始化返回 nil——测试环境）。
func TaskEngine() *taskengine.Engine { return taskEngine }

// parseUTCSlot 解析 DB 存的 UTC 排程串为 time.Time（crsTimeLayout 与
// RFC3339 双形态——与 localDisplayUTC 同口径）。
func parseUTCSlot(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{crsTimeLayout, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// InitTaskEngine 建引擎、恢复孤儿运行、注册全部 17 任务并启动默认循环。幂等。
func InitTaskEngine(watchdogAdminURL, runtimeLogFile string) *taskengine.Engine {
	taskEngine = taskengine.NewEngine(taskengine.Options{})
	// 角色种子（v2.0 角色门前置）：按 DB 角色初始化——从节点不瞬启
	// master-only daemon（否则 boot 行噪音：启动→SetRole 停止）
	var roleMaster int
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&roleMaster); err == nil {
		taskEngine.SetRole(roleMaster == 1)
	}
	_ = taskEngine.RecoverOrphans()
	taskengine.SetLocation(CurrentLocation())
	logsDir := "/app/logs"
	if runtimeLogFile != "" {
		logsDir = filepath.Dir(runtimeLogFile)
	}
	tasksLogDir := filepath.Join(logsDir, "tasks")
	_ = os.MkdirAll(tasksLogDir, 0755)
	taskengine.SetLogDir(tasksLogDir)
	taskEngine = taskengine.NewEngine(taskengine.Options{})
	_ = taskEngine.RecoverOrphans()

	// ============ 循环（8）============

	// 看门狗：60s 一致性检查（每轮记录——60s 非高频，日志有大小限制）
	watchdogAdminURLValue = watchdogAdminURL
	taskEngine.Register(taskengine.Descriptor{
		ID:          "config-watchdog",
		Family:      "system",
		Name:        "配置漂移看门狗",
		Description: "每 60 秒比对运行中 Caddy 配置与数据库期望配置，漂移时面板横幅告警并触发对账",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 60 * time.Second },
		Run: func(rc taskengine.RunContext) error {
			WatchdogCheckOnce()
			return nil
		},
	})

	// 运行日志清理：每日
	logFile := runtimeLogFile
	taskEngine.Register(taskengine.Descriptor{
		ID:          "log-cleanup",
		Family:      "system",
		Name:        "日志清理与轮转",
		Description: "清理超保留期的应用日志轮转副本（app.log.*）；统一清理任务日志（tasks/*.log：超保留期删除、超大小上限轮转保一份）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			if logFile != "" {
				removed := RuntimeLogCleanupOnce(logFile)
				months := 3
				if database := db.GetDB(); database != nil {
					var m int
					if err := database.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&m); err == nil && m >= 1 {
						months = m
					}
				}
				TaskLogf("log-cleanup", "cleanup", "日志清理完成：删除 %d 个过期副本（保留 %d 月，无过期为 0）；任务日志超期删除/超限轮转", removed, months)
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID:          "audit-retention",
		Family:      "system",
		Name:        "审计日志保留清理",
		Description: "按「审计保留月数」配置删除 audit 库过期操作日志（基础设置可调）；并清理 90 天前的任务运行历史（task_runs）",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			auditDeleted := CleanupAuditLogs()
			runsDeleted := taskengine.PurgeTaskRuns(90)
			TaskLogf("audit-retention", "cleanup", "清理完成：审计日志 %d 条、任务运行历史 %d 行（无过期数据时为 0）", auditDeleted, runsDeleted)
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID:          "security-events-retention",
		Family:      "system",
		Name:        "安全事件保留清理",
		Description: "按保留期配置删除 metrics 库中过期的安全事件记录",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			deleted := SecurityEventsRetentionCleanupOnce()
			TaskLogf("security-events-retention", "cleanup", "安全事件保留清理完成：删除 %d 条（保留期与条数上限，无过期为 0）", deleted)
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-renewal-scan", Family: "certificates", Name: "证书续期扫描",
		Description: "扫描全部证书配置的到期时间，临期证书自动入队续签；入队时唤醒 CA 等待补扫",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			CertRenewalScanOnce()
			// 入队即唤醒 CA 等待补扫（默认调度关闭——有活自动开启）
			if certJobsActive() {
				taskEngine.StartLoop("cert-waiting-ca")
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-reconcile", Family: "certificates", Name: "证书状态对账",
		Description: "核对证书文件与数据库状态一致性，修复中断任务残留的中间态",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 6 * time.Hour },
		Run:        func(rc taskengine.RunContext) error { CertReconcileOnce(); return nil },
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-manual-poll", Family: "certificates", Name: "手动证书任务轮询",
		Description: "处理手工触发或重试的证书任务",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 10 * time.Minute },
		Run:        func(rc taskengine.RunContext) error { CertManualCheckOnce(); return nil },
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "cert-waiting-ca", Family: "certificates", Name: "CA 等待补扫",
		Description: "证书任务在途时的兜底补扫：CA 冷却到期重排、滞留 queued 重入队、断链部署重试重建。默认调度关闭——续期扫描入队时自动开启，全部终态自动停止",
		Category:    "证书", Kind: taskengine.KindPeriodic, RunsOn: taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 30 * time.Second },
		StatusFn: func() string {
			if certJobsActive() {
				return "running"
			}
			if te := TaskEngine(); te != nil && te.IsRunning("cert-waiting-ca") {
				return "idle"
			}
			return "stopped"
		},
		NextSlotFn: func() time.Time { // 有等待任务时展示最近 CA 可用时间
			var at string
			if err := db.DB.QueryRow(`SELECT COALESCE(MIN(NULLIF(ca_available_after,'')),'') FROM cert_jobs WHERE status='waiting_ca'`).Scan(&at); err != nil {
				return time.Time{}
			}
			return parseUTCSlot(at)
		},
		Run: func(rc taskengine.RunContext) error {
			if !certJobsActive() {
				// 全部终态——自动关闭调度（回到默认关闭态）
				taskEngine.StopLoop("cert-waiting-ca")
				TaskLogf("cert-waiting-ca", "idle", "证书任务全部终态，自动停止补扫")
				return nil
			}
			CertWaitingCATickOnce()
			return nil
		},
	})

	// ============ 常驻（3）============

	// 安全事件摄取：自管理 2s 尾读循环（引擎仅管生命周期）
	taskEngine.Register(taskengine.Descriptor{
		ID:          "security-events-ingestion",
		Family:      "system",
		Name:        "安全事件采集",
		Description: "尾读 coraza WAF 审计日志并摄取为安全事件（安全总览/事件页的数据源），含审计日志轮转跟随",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run:         func(rc taskengine.RunContext) error { return runIngestionLoop(rc.Ctx) },
	})

	// 证书签发：被动守护（CAQueueManager 自管理——Run 阻塞保持运行态）。
	// RunsOn=MasterOnly：从节点禁签发——daemon 不在从节点启动（promote 经
	// SetRole 自动拉起），状态显示实态（从节点=空闲）。
	taskEngine.Register(taskengine.Descriptor{
		ID:          "cert-issuance",
		Family:      "certificates",
		Name:        "证书签发",
		Description: "ACME 证书签发队列——含新签发与续签（由证书任务队列调度，活跃任务显示为动态行；仅主节点运行，从节点只读镜像）",
		Category:    "证书",
		Kind:        taskengine.KindDaemon,
		RunsOn:      taskengine.RoleMasterOnly,
		Run: func(rc taskengine.RunContext) error {
			<-rc.Ctx.Done() // CAQueueManager 由 main 启动——此处仅承载运行态
			return nil
		},
		StatusFn: func() string {
			var n int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE status NOT IN ('issued','failed','disabled')`).Scan(&n); err == nil && n > 0 {
				return "running"
			}
			return ""
		},
	})

	// 集群同步：被动守护（SyncService 自管理——Run 阻塞保持运行态）。
	// 无 StatusFn：状态由 daemon 实际运行态呈现——主节点（快照签发/接收
	// 从节点注册）与从节点（轮询回放）都是服务在跑=运行中（2026-10-01
	// 用户裁定：主节点显示空闲不合理）。
	taskEngine.Register(taskengine.Descriptor{
		ID:          "cluster-sync",
		Family:      "cluster",
		Name:        "集群同步",
		Description: "集群同步服务：从节点按配置间隔轮询主节点快照并增量回放；主节点签发快照并接收从节点注册",
		Category:    "集群",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			<-rc.Ctx.Done() // SyncService 由 main 启动——此处仅承载运行态
			return nil
		},
	})

	// ============ 定时（4）============

	taskEngine.Register(taskengine.Descriptor{
		ID: "threat", Family: "security", Name: "威胁情报库更新",
		Description: "每日从 USTC/FireHOL/ET 三源下载恶意 IP 名单，聚合去重后写入威胁库文件并同步从节点——引用名单的安全策略据此拦截",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			if !ThreatAutoUpdateEnabled() {
				return time.Time{}
			}
			return parseUTCSlot(earliestThreatNextUpdate())
		},
		EnabledFn: func() bool { return ThreatAutoUpdateEnabled() }, // 业务开关联动展示（关=已暂停）
		StatusFn: func() string {
			if m := GetThreatUpdateManager(); m != nil && m.StatusSnapshot().Running {
				return "running"
			}
			return ""
		},
		MasterOnly: true,
		CancelHook: func() bool { return GetThreatUpdateManager() != nil && GetThreatUpdateManager().CancelRunning() },
		ToggleFn:   SetThreatAutoUpdate,
		ToggleName: "威胁情报库自动更新",
		Run: func(rc taskengine.RunContext) error {
			m := GetThreatUpdateManager()
			if m == nil {
				return nil
			}
			// 引擎已在排程槽调用——直接执行（manager 内部自带总闸/单飞/到期源筛选）
			return m.RunUpdate(rc.Trigger, &rc)
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "crs", Family: "security", Name: "CRS 规则库更新",
		Description: "检查并更新 OWASP CoreRuleSet 规则集到最新版本（保留用户 overrides），供 WAF 拦截模式消费",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			m := GetCRSUpdateManager()
			if m == nil || !m.AutoUpdateEnabled() {
				return time.Time{}
			}
			return parseUTCSlot(m.NextScheduledSlot())
		},
		EnabledFn: func() bool { // 业务开关联动展示（关=已暂停；DB 直读——manager 未初始化窗口也正确）
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_crs_version WHERE id=1").Scan(&en); err != nil {
				return true
			}
			return en == 1
		},
		StatusFn: func() string {
			m := GetCRSUpdateManager()
			if m == nil {
				return ""
			}
			st := m.StatusSnapshot().Status
			if st == string(CRSStatusIdle) || st == string(CRSStatusSuccess) || st == "" {
				return ""
			}
			return "running"
		},
		MasterOnly: true,
		CancelHook: func() bool { m := GetCRSUpdateManager(); return m != nil && m.CancelRunning() },
		ToggleFn:   SetCRSAutoUpdate,
		ToggleName: "CRS 自动更新",
		Run: func(rc taskengine.RunContext) error {
			m := GetCRSUpdateManager()
			if m == nil {
				return nil
			}
			done, err := m.StartUpdate(rc.Trigger, &rc)
			if err != nil {
				return err
			}
			<-done
			if snap := m.StatusSnapshot(); snap.Status == string(CRSStatusFailed) {
				return fmt.Errorf("CRS 更新失败: %s", snap.Message)
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "ip2region", Family: "security", Name: "IP2Region 地理库更新",
		Description: "更新 IP 地理位置离线库（xdb），供 GeoIP 地域拦截与归属地展示使用",
		Category:    "安全防护", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly, Cancelable: true,
		NextSlotFn: func() time.Time {
			m := GetIP2RegionUpdateManager()
			if m == nil || !m.AutoUpdateEnabled() {
				return time.Time{}
			}
			return parseUTCSlot(m.NextScheduledSlot())
		},
		EnabledFn: func() bool { // 业务开关联动展示（关=已暂停；DB 直读）
			var en int
			if err := db.DB.QueryRow("SELECT COALESCE(auto_update,1) FROM security_ip2region_version WHERE id=1").Scan(&en); err != nil {
				return true
			}
			return en == 1
		},
		StatusFn: func() string {
			var status string
			_ = db.DB.QueryRow("SELECT COALESCE(update_status,'') FROM security_ip2region_version WHERE id=1").Scan(&status)
			if status == "" || status == "idle" || status == "success" {
				return ""
			}
			return "running"
		},
		MasterOnly: true,
		CancelHook: func() bool { return GetIP2RegionUpdateManager() != nil && GetIP2RegionUpdateManager().CancelRunning() },
		ToggleFn:   SetIP2RegionAutoUpdate,
		ToggleName: "IP2Region 自动更新",
		Run: func(rc taskengine.RunContext) error {
			m := GetIP2RegionUpdateManager()
			if m == nil {
				return nil
			}
			done, err := m.StartUpdate(rc.Trigger, &rc)
			if err != nil {
				return err
			}
			<-done
			if snap := m.StatusSnapshot(); snap.Status == string(IP2RegionStatusFailed) {
				return fmt.Errorf("IP2Region 更新失败: %s", snap.Message)
			}
			return nil
		},
	})

	taskEngine.Register(taskengine.Descriptor{
		ID: "auto-backup", Family: "backup", Name: "自动备份",
		Description: "按排程把全量配置打包为 lbbak 落盘 backup 目录（含 CRS/IP2Region/威胁库数据文件），保留份数自动清理",
		Category:    "备份", Kind: taskengine.KindScheduled, RunsOn: taskengine.RoleMasterOnly,
		NextSlotFn: func() time.Time {
			if t, ok := nextAutoBackupSlot(time.Now()); ok {
				return t
			}
			return time.Time{}
		},
		EnabledFn: func() bool { // 业务开关联动展示（备份未启用=已暂停）
			row, err := loadAutoBackupSettings()
			return err != nil || row.enabled
		},
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger == "manual" {
				exec := currentAutoBackupExecutor()
				if exec == nil {
					return errors.New("备份执行器未就绪")
				}
				return exec("manual", rc.Operator, rc.RunID)
			}
			return runAutoBackupScheduled(rc.RunID)
		},
	})

	// ============ 触发（1）============

	taskEngine.Register(taskengine.Descriptor{
		ID:          "startup:config-load",
		Family:      "startup",
		Name:        "系统配置载入",
		Description: "启动时从数据库装载运行态：规则库（CRS 种子/对账）→ 证书文件物化 → Caddy 配置渲染与应用（失败回退最后已知正确配置）。完成前面板不监听",
		Category:    "系统",
		Kind:        taskengine.KindOneshot,
		ManualRun:   true,
		Run: func(rc taskengine.RunContext) error {
			if rc.Trigger != "manual" {
				return nil // 启动执行由 main startupPhase 记录——引擎 Run 仅承载手动重载
			}
			if configLoadRerun == nil {
				return errors.New("配置重载未接线")
			}
			return configLoadRerun()
		},
	})

	// ============ 手动触发语义 + 默认调度启动 ============

	// 手动触发（定时/循环/触发允许；常驻无「立即执行」——启停即可）
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup", "log-cleanup", "audit-retention", "security-events-retention", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca", "startup:config-load"} {
		taskEngine.SetManualRun(id, true)
	}

	// 默认调度启动：
	// - 循环 8 个全启动（cert-waiting-ca 除外——默认关闭，续期扫描唤醒）
	// - 常驻 3 个全启动（系统启动即运行；关闭调度=启动也不运行）
	// - 定时 4 个启动排程（EnabledFn/NextSlotFn 内含开关判断）
	for _, id := range []string{
		"config-watchdog", "log-cleanup", "audit-retention", "security-events-retention",
		"cert-renewal-scan", "cert-reconcile", "cert-manual-poll",
		"security-events-ingestion", "cert-issuance", "cluster-sync",
		"threat", "crs", "ip2region", "auto-backup",
	} {
		taskEngine.StartLoop(id)
	}
	return taskEngine
}

// StopTaskEngine 进程退出收尾。
func StopTaskEngine() {
	if taskEngine != nil {
		taskEngine.Stop()
		taskEngine = nil
	}
}
