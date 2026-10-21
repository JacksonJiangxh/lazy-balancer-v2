package db

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/models"

	_ "github.com/glebarez/sqlite"
	"golang.org/x/net/idna"
)

var (
	DB            *sql.DB
	currentDB     atomic.Value
	MetricsDB     *sql.DB
	AuditDB       *sql.DB
	openDatabase  = sql.Open
	domainProfile = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.VerifyDNSLength(true))
)

// 库值唯一真相（批 1+2，2026-10-14 用户裁定）类型①值型列默认值——渲染层
// 写死兜底废除后，默认值的唯一入口：fresh DDL DEFAULT、启动迁移回填
// （defaultUpdates，幂等 UPDATE WHERE IS NULL OR <=0）、导入/快照/传输归一
// 门。语义约定：这些列 0 无效（库恒有效），渲染直读，无效即显性报错。
// 反向钉测：db_truth_defaults_test.go 断言 DDL DEFAULT 与本组常量逐项一致；
// 渲染侧 fail-visible 见 render_db_truth_test.go。
const (
	DefaultRequestBodyMaxSizeMB          = 128
	DefaultHTTPReadTimeout               = 60
	DefaultHTTPWriteTimeout              = 60
	DefaultHTTPIdleTimeout               = 120
	DefaultCaddyLogSizeMB                = 100
	DefaultHealthCheckInterval           = 10
	DefaultHealthCheckTimeout            = 2
	DefaultHealthCheckHealthyThreshold   = 2
	DefaultHealthCheckUnhealthyThreshold = 3
	DefaultTCPTryInterval                = 250
	DefaultCertExpiryDays                = 30
	// 历史问题（历史）：cert_renewal_days/cert_renewal_attempts 与
	// cert_expiry_days 同族——DDL DEFAULT + 启动回填 + 读侧直读零兜底三件套。
	DefaultCertRenewalDays     = 30
	DefaultCertRenewalAttempts = 5
	// DefaultAnomalyThreshold（历史修复，历史）：security_policies.anomaly_threshold
	// 类型①值列默认值——fresh CREATE 的 security_policies.anomaly_threshold
	// DDL DEFAULT + 启动归一（security_normalize.go legacySecurityEnumBackfills）
	// + DB 侧钉测三处单源。
	DefaultAnomalyThreshold = 5
	// 安全事件保留 / 威胁大屏口径默认值（历史问题单源化）：
	// 此前 90 天 / 100 万行 / 采样 -1 / 模式 'map' 在 DDL（newColumns）、启动
	// 迁移、读侧 COALESCE、导入归一四处各写一份字面量，改默认值需同步 4+ 处
	// （request_body 多年漏检同族）。现以本组常量为唯一事实源：DDL/回填/
	// 读侧绑定参数/导入归一全部引用，db_truth_defaults_test 双向钉死。
	DefaultSecurityEventsRetentionDays = 90
	DefaultSecurityEventsRowCap        = 1000000
	DefaultThreatTrafficSampleN        = -1 // -1=自适应/0=关闭（全量与固定档已废除）
	DefaultThreatScreenMode            = "map"
	// DefaultTimezone 是 global_config.timezone 的治理默认（fresh DDL DEFAULT
	// 与启动归一单源）。空串不是合法库值：time.LoadLocation("") 是 Go 的
	// 特殊值（返回 UTC），读侧 COALESCE 只兜 NULL——空串落库会让全站展示/
	// 审计窗口静默切 UTC，故写侧拒绝、启动归一、DDL DEFAULT 三处同口径。
	DefaultTimezone = "Asia/Shanghai"
)

// certJobStatuses 是 cert_jobs.status 的规范枚举（历史问题，历史单源化）。
// 唯一声明点在此：fresh CREATE 的 CHECK 枚举、迁移重建 DDL、迁移拷贝的
// CASE WHEN 白名单全部由 strings.Join 生成；services 侧的任务状态机
// （jobstate.go 的 allJobStatuses/withoutJobStatuses）经 CertJobStatuses()
// 派生——services 依赖 db 而 db 不能反向 import services（import 环），故
// 真源落在 db，对外 API 仍由 services.AllJobStatuses() 提供。
var certJobStatuses = []string{
	"queued", "pending", "processing", "creating_account", "creating_order", "order_created",
	"cleanup_dns", "cleanup_warning", "presenting_dns", "waiting_propagation", "dns_propagated",
	"accepting_challenge", "validating", "validated", "finalizing", "finalized", "downloading",
	"downloaded", "issued", "failed", "waiting_ca", "disabled", "waiting_order_ready", "order_ready",
	"waiting_order_valid", "order_valid",
}

// CertJobStatuses 返回 cert_jobs.status 规范枚举的副本（防调用方篡改全局）。
func CertJobStatuses() []string {
	return slices.Clone(certJobStatuses)
}

// certJobStatusListSQL 返回单引号包裹、逗号连接的枚举，制式与既有 DDL 一致
// （无空格）——hasExactStatusConstraint 的存量形态判定依赖该制式。
func certJobStatusListSQL() string {
	quoted := make([]string, len(certJobStatuses))
	for i, status := range certJobStatuses {
		quoted[i] = "'" + status + "'"
	}
	return strings.Join(quoted, ",")
}

// certJobStatusCheckSQL 是 fresh/重建 DDL 共用的 CHECK 子句。
func certJobStatusCheckSQL() string {
	return "CHECK (status IN (" + certJobStatusListSQL() + "))"
}

// TaskRunsLatestPerTaskQuery 是「每任务最新运行」查询的唯一事实源：生产消费方
// = taskengine.Engine.RunOverview（services 层任务视图），索引服务对象 =
// idx_task_runs_task_latest(task_id, id)。常量落在 db 包是因为索引 DDL 与
// EXPLAIN 查询计划钉测同包（db 不可 import taskengine：反向会成环），
// 历史问题（历史）以此消除测试「按反引号切片生产源码文本」的脆性——
// 查询重构不再假红，查询与索引列序漂移仍由计划钉测拦截。
const TaskRunsLatestPerTaskQuery = `SELECT id, task_id, family, trigger, COALESCE(operator,''), status, started_at,
			COALESCE(finished_at,''), COALESCE(duration_ms,0), COALESCE(message,'')
			FROM task_runs WHERE id IN (SELECT MAX(id) FROM task_runs GROUP BY task_id)`

func CanonicalDomains(value string) (string, error) {
	seen := make(map[string]struct{})
	domains := make([]string, 0)
	for _, rawDomain := range strings.Split(value, ",") {
		domain := strings.TrimSpace(strings.ToLower(rawDomain))
		domain = strings.TrimSuffix(domain, ".")
		if domain == "" {
			continue
		}
		ascii, err := domainProfile.ToASCII(domain)
		if err != nil {
			return "", fmt.Errorf("invalid domain %q: %w", rawDomain, err)
		}
		ascii = strings.TrimSuffix(strings.ToLower(ascii), ".")
		if ascii == "" || net.ParseIP(ascii) != nil {
			return "", fmt.Errorf("invalid domain %q", rawDomain)
		}
		if _, exists := seen[ascii]; exists {
			continue
		}
		seen[ascii] = struct{}{}
		domains = append(domains, ascii)
	}
	if len(domains) == 0 {
		return "", fmt.Errorf("domain is empty")
	}
	return strings.Join(domains, ","), nil
}

// SetDB registers the handle background goroutines should use; tests that
// swap DB directly should call this too so refresh loops follow.
func SetDB(d *sql.DB) {
	if current := GetDB(); current != nil && current != d {
		if err := FlushAPIKeyLastUsed(); err != nil {
			logDBError("flush API key usage before database swap", err)
		}
	}
	currentDB.Store(d)
}

func logDBError(operation string, err error) {
	log.Printf("ERROR: %s: %v", operation, err)
}

// GetDB returns the handle registered via Initialize/SetDB, safe for
// concurrent background readers.
func GetDB() *sql.DB {
	if v, ok := currentDB.Load().(*sql.DB); ok {
		return v
	}
	return nil
}

func Initialize(dataDir string) (err error) {
	if err := secureDataDirectory(dataDir); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "lazy-balancer.db")
	if err := prepareSQLiteDatabase(dbPath); err != nil {
		return fmt.Errorf("failed to secure database file: %w", err)
	}

	// glebarez 仅识别 _pragma/_txlock/_time_format 三类 DSN 参数；_pragma 会在
	// 每条新建连接上执行（applyQueryParams），正适合 busy_timeout 这类连接级参数。
	// journal_mode 是文件级（一次迁移持久生效），放这里仅为幂等兜底。
	database, err := openDatabase("sqlite", dbPath+"?_txlock=immediate&_pragma=journal_mode(WAL)&_pragma=busy_timeout(30000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	var metricsDB, auditDB *sql.DB
	defer func() {
		if err == nil {
			return
		}
		if auditDB != nil && auditDB != oldAuditDB {
			err = errors.Join(err, auditDB.Close())
		}
		if metricsDB != nil && metricsDB != oldMetricsDB {
			err = errors.Join(err, metricsDB.Close())
		}
		err = errors.Join(err, database.Close())
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	}()

	database.SetMaxOpenConns(10)
	database.SetMaxIdleConns(5)
	// 连接最长存活 30 分钟：Begin/Commit 歧义（客户端超时取消）可能在池中留下
	// SQLite 层事务未关闭的「中毒连接」（表现为 cannot start a transaction within
	// a transaction / 持锁不放）；定期换血把最坏影响面限制在半个生命周期内。
	database.SetConnMaxLifetime(30 * time.Minute)

	if err := database.Ping(); err != nil {
		return fmt.Errorf("failed to ping database: %w", err)
	}
	if err := applySQLiteRuntimePragmas(database); err != nil {
		return fmt.Errorf("failed to apply database pragmas: %w", err)
	}

	DB = database

	// Initialize metrics database
	if err := InitializeMetricsDB(dataDir); err != nil {
		return fmt.Errorf("failed to initialize metrics database: %w", err)
	}
	metricsDB = MetricsDB

	// Create tables
	if err := createTables(); err != nil {
		return fmt.Errorf("failed to create tables: %w", err)
	}

	// Ensure default config row exists
	var configCount int
	if err := DB.QueryRow("SELECT COUNT(*) FROM global_config").Scan(&configCount); err != nil {
		return fmt.Errorf("failed to count global config rows: %w", err)
	}
	if configCount == 0 {
		if _, err := DB.Exec("INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')"); err != nil {
			return fmt.Errorf("failed to insert global config singleton: %w", err)
		}
	}

	// Run migrations
	if err := runMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}
	if err := migrateSyncSwitches(); err != nil {
		return fmt.Errorf("failed to migrate sync switches: %w", err)
	}
	if err := migrateNodesDropMasterID(); err != nil {
		return fmt.Errorf("failed to migrate nodes master_id removal: %w", err)
	}
	// 历史问题-1(历史):存量从节点库修复——历史 apply 把空白名单落为
	// 字面量 "null"(中间件守卫据非空串判为已配置白名单→全来源 403);幂等
	// 归一为 ''。主端库不受影响(encodeMCPIPWhitelist 本就落 '')。
	if _, err := DB.Exec("UPDATE api_keys SET mcp_ip_whitelist='' WHERE mcp_ip_whitelist='null'"); err != nil {
		return fmt.Errorf("failed to normalize null mcp_ip_whitelist: %w", err)
	}
	// 历史问题(历史):回收存量库冗余索引——UNIQUE(token_hash) 的
	// 隐式唯一索引已覆盖查询,显式索引为纯维护噪音;历史仅删了 CREATE
	// 行,存量库索引持久于库文件。幂等 DROP。
	if _, err := DB.Exec("DROP INDEX IF EXISTS idx_cluster_register_tokens_hash"); err != nil {
		return fmt.Errorf("failed to drop legacy register-token hash index: %w", err)
	}
	if err := ensureClusterAppliedSections(); err != nil {
		return fmt.Errorf("failed to ensure cluster_applied_sections: %w", err)
	}

	if initErr := InitializeAuditDB(dataDir); initErr != nil {
		auditDB = AuditDB
		return fmt.Errorf("failed to initialize audit database: %w", initErr)
	}
	auditDB = AuditDB
	if err := secureSQLiteArtifacts(dbPath); err != nil {
		return fmt.Errorf("failed to secure database artifacts: %w", err)
	}
	SetDB(database)
	startAPIKeyLastUsedFlusher()

	log.Println("Database initialized successfully")
	return nil
}

func createTables() error {
	schema := `
	-- Users table
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(50) UNIQUE NOT NULL,
		password_hash VARCHAR(255) NOT NULL,
		role VARCHAR(20) NOT NULL DEFAULT 'user',
		display_name VARCHAR(100),
		is_enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	);

	-- users/api_keys/lb_rules 等表的存量库补列统一由 runMigrations 的
	-- newColumns 通道承担（历史修复 收敛后唯一登记点，见该处注释）。

	-- API Keys table
	CREATE TABLE IF NOT EXISTS api_keys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		key_hash VARCHAR(255) NOT NULL,
		key_prefix VARCHAR(20) NOT NULL,
		created_by INTEGER NOT NULL,
		last_used DATETIME,
		expires_at DATETIME,
		is_enabled BOOLEAN DEFAULT TRUE,
		mcp_enabled INTEGER DEFAULT 0,
		read_only INTEGER DEFAULT 0,
		mcp_ip_whitelist TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (created_by) REFERENCES users(id)
	);
	CREATE INDEX IF NOT EXISTS idx_api_keys_prefix_hash ON api_keys(key_prefix, key_hash);

	-- LB Rules table (caddy_id is now the primary key)
	CREATE TABLE IF NOT EXISTS lb_rules (
		id INTEGER,
		name VARCHAR(100) NOT NULL,
		description VARCHAR(300),
		protocol VARCHAR(10) NOT NULL,
		domain VARCHAR(255),
		listen_port INTEGER NOT NULL,
		strategy VARCHAR(20) DEFAULT 'weighted_round_robin',
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enable_dns_server BOOLEAN DEFAULT FALSE,
		dns_server VARCHAR(255) DEFAULT '',
		dns_family VARCHAR(20) DEFAULT 'ipv4',
		health_check_path VARCHAR(255),
		-- 库值唯一真相（批 1+2）：健康检查族值型列 NOT NULL+DEFAULT，渲染直读
		-- 无兜底（0 无效→启动回填/写侧 400 拦截）。存量库 ALTER 无法补 NOT NULL
		--（SQLite 限制），由每启动回填 defaultUpdates 收敛 NULL/<=0。
		health_check_interval INTEGER NOT NULL DEFAULT 10,
		-- 历史问题: schema 默认仅新库/重建生效（SQLite 不支持 ALTER COLUMN DEFAULT）；
		-- 存量行 health_check_timeout 值不变；全部生产 INSERT 显式带值，DEFAULT 惰性。
		-- 批 1+2：DEFAULT 5→2——与写侧（CreateRule 校验边界）/读取/渲染三方统一
		-- （历史问题-1/历史修复），5 为从未生效的陈旧默认。
		health_check_timeout INTEGER NOT NULL DEFAULT 2,
		health_check_unhealthy_threshold INTEGER NOT NULL DEFAULT 3,
		health_check_healthy_threshold INTEGER NOT NULL DEFAULT 2,
		enable_active_health_check BOOLEAN DEFAULT FALSE,
		tcp_health_check_port INTEGER DEFAULT 0,
		tcp_proxy_protocol BOOLEAN DEFAULT 0,
		tcp_try_duration INTEGER DEFAULT 0,
		tcp_try_interval INTEGER NOT NULL DEFAULT 250,
		request_body_max_size_mb INTEGER DEFAULT 0,
		upstream_keepalive_timeout INTEGER DEFAULT 0,
		server_tokens_hidden INTEGER DEFAULT 0,
		-- 规则级 NTLM 兼容开关（2026-10-12）：仅 HTTP 语义，1=按 NTLM 兼容形态
		-- 渲染（保存门强制 strategy=cookie）；TCP 规则携带即 400。
		ntlm_compatible INTEGER NOT NULL DEFAULT 0,
		-- 上游强制 HTTP/1.1（通用列）：1=对 https 上游禁 ALPN h2（transport.versions）。
		upstream_force_http1 INTEGER NOT NULL DEFAULT 0,
		custom_routes_enabled BOOLEAN NOT NULL DEFAULT 0,
		proxy_dial_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_response_header_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_read_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_write_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_stream_timeout INTEGER NOT NULL DEFAULT 0,
		proxy_flush_interval INTEGER NOT NULL DEFAULT 0,
		proxy_stream_close_delay INTEGER NOT NULL DEFAULT 0,
	host_header VARCHAR(255),
	-- 逐上游回源域名特性（2026-10-10）：健康检查域名（probe Host 头），空=跟随 host_header。
	health_check_host TEXT NOT NULL DEFAULT '',
		enable_tls BOOLEAN DEFAULT FALSE,
		tls_cert TEXT,
		tls_key TEXT,
		tls_http_redirect BOOLEAN DEFAULT FALSE,
		tls_source VARCHAR(20) DEFAULT 'manual',
		acme_config_id INTEGER DEFAULT 0,
		ca_provider_id INTEGER DEFAULT 0,
		enable_compress BOOLEAN DEFAULT FALSE,
		compress_types VARCHAR(100) DEFAULT 'gzip',
		enabled BOOLEAN NOT NULL DEFAULT 1,
		log_enabled BOOLEAN DEFAULT 0,
		-- 历史修复（历史）：阶段拦截页四列——此前仅靠 newColumns 启动补列，
		-- fresh DDL 滞后于存量库 ALTER 通道。
		block_page_stage1_id INTEGER NOT NULL DEFAULT 0,
		block_page_stage1_status INTEGER NOT NULL DEFAULT 0,
		block_page_stage3_id INTEGER NOT NULL DEFAULT 0,
		block_page_stage3_status INTEGER NOT NULL DEFAULT 0,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME,
		updated_by INTEGER,
		caddy_id VARCHAR(20) PRIMARY KEY
	);

	-- CA Providers table for ACME certificate issuance
	CREATE TABLE IF NOT EXISTS ca_providers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		provider VARCHAR(50) NOT NULL,
		directory_url VARCHAR(255) NOT NULL,
		credentials TEXT,
		max_concurrent INTEGER DEFAULT 1,
		min_interval_ms INTEGER DEFAULT 2000,
		enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	-- Upstreams table (rule_id now references caddy_id)
	CREATE TABLE IF NOT EXISTS upstreams (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		weight INTEGER DEFAULT 1,
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		protocol VARCHAR(10) DEFAULT 'http',
		max_connections INTEGER DEFAULT 0,
		-- 逐上游回源域名（2026-10-10）：驱动该上游回源 Host 头与 HTTPS SNI，空=跟随规则后端域名。
		origin_domain TEXT NOT NULL DEFAULT '',
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_upstreams_rule_enabled_id ON upstreams(rule_id, enabled, id);

	CREATE TABLE IF NOT EXISTS path_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		sort_order INTEGER NOT NULL DEFAULT 0,
		match_type TEXT NOT NULL DEFAULT 'prefix',
		path TEXT NOT NULL,
		upstream_path TEXT NOT NULL DEFAULT '',
		upstreams_json TEXT,
		-- 自定义路由静态响应/301 跳转（2026-10-10 用户裁定）：response_mode ''=转发
		-- 上游（现状）/static=静态响应/redirect=301 跳转；后四列按模式消费。
		response_mode TEXT NOT NULL DEFAULT '',
		response_status INTEGER NOT NULL DEFAULT 200,
		response_body TEXT NOT NULL DEFAULT '',
		response_content_type TEXT NOT NULL DEFAULT '',
		redirect_to TEXT NOT NULL DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME,
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_path_rules_rule_order ON path_rules(rule_id, sort_order, id);

	-- Certificate Configs table for ACME DNS providers
	CREATE TABLE IF NOT EXISTS certificate_configs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		dns_provider VARCHAR(50) DEFAULT 'dnspod',
		dns_credentials TEXT,
		enabled BOOLEAN DEFAULT TRUE,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);

	-- Certificate Jobs table for ACME issuance tracking
	CREATE TABLE IF NOT EXISTS cert_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id VARCHAR(20) NOT NULL,
		domain VARCHAR(255) NOT NULL,
		status VARCHAR(20) NOT NULL DEFAULT 'queued' ` + certJobStatusCheckSQL() + `,
		message TEXT,
		expires_at DATETIME,
		cert_pem TEXT,
		key_pem TEXT,
		ca_provider_id INTEGER DEFAULT 0,
		renewal_attempts INTEGER DEFAULT 0,
		ca_available_after DATETIME,
		last_error_code VARCHAR(20),
		deployment_attempts INTEGER DEFAULT 0,
		deployment_available_after DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME
	);

	-- Global Config table
	CREATE TABLE IF NOT EXISTS global_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		caddy_config TEXT DEFAULT '{}',
		dns_provider VARCHAR(50) DEFAULT 'dnspod',
		dns_credentials TEXT,
		acme_email VARCHAR(255),
		log_level VARCHAR(10) DEFAULT 'info',
		is_master BOOLEAN DEFAULT TRUE,
		master_url VARCHAR(255),
		sync_interval INTEGER DEFAULT 60,
		caddy_log_level VARCHAR(10) DEFAULT 'info',
		caddy_log_size_mb INTEGER NOT NULL DEFAULT 100,
		-- 历史修复:默认 128(与 coraza 默认 RequestBodyLimit 统一)。批 1+2:
		-- NOT NULL+渲染直读,存量库 0 行由启动回填报 128,渲染层写死 128 兜底废除。
		request_body_max_size_mb INTEGER NOT NULL DEFAULT 128,
		http_read_timeout INTEGER NOT NULL DEFAULT 60,
		http_write_timeout INTEGER NOT NULL DEFAULT 60,
		http_idle_timeout INTEGER NOT NULL DEFAULT 120,
		upstream_keepalive_timeout INTEGER DEFAULT 0,
		proxy_dial_timeout INTEGER DEFAULT 0,
		proxy_response_header_timeout INTEGER DEFAULT 0,
		proxy_read_timeout INTEGER DEFAULT 0,
		proxy_write_timeout INTEGER DEFAULT 0,
		proxy_stream_timeout INTEGER DEFAULT 0,
		proxy_flush_interval INTEGER DEFAULT 0,
		proxy_stream_close_delay INTEGER DEFAULT 0,
		server_tokens_hidden BOOLEAN DEFAULT FALSE,
		cert_expiry_days INTEGER DEFAULT 30,
		cert_renewal_days INTEGER DEFAULT 30,
		-- 历史问题（历史）：续期次数与天数同族——fresh DDL 与 ensureNewColumns
		-- （存量库）双锚，缺此列会让 DDL DEFAULT 钉测在 fresh 库上查无此列。
		cert_renewal_attempts INTEGER DEFAULT 5,
		task_log_size_mb INTEGER DEFAULT 10,
		audit_log_size_mb INTEGER DEFAULT 10,
		caddy_apply_error TEXT DEFAULT '',
	runtime_log_size_mb INTEGER DEFAULT 100,
		access_log_json BOOLEAN DEFAULT TRUE,
		access_log_format TEXT DEFAULT '',
		audit_retention_months INTEGER DEFAULT 3,
		jwt_expire_minutes INTEGER DEFAULT 20,
		timezone VARCHAR(50) DEFAULT 'Asia/Shanghai',
		github_proxy_url TEXT NOT NULL DEFAULT 'https://v4.gh-proxy.org/',
		-- 可选 GITHUB_TOKEN（2026-09-25 用户裁定）：未认证 GitHub API 限流
		-- 60/h/IP（共享出口易打满），令牌提升 5000/h；仅发 api.github.com 直连。
		github_token TEXT NOT NULL DEFAULT '',
		last_sync DATETIME,
		last_sync_error TEXT DEFAULT '',
		applied_version INTEGER DEFAULT 0,
		cluster_version INTEGER DEFAULT 0,
		cluster_token TEXT DEFAULT '',
		registration_id INTEGER DEFAULT 0,
		registration_secret TEXT DEFAULT '',
		sync_fingerprint TEXT DEFAULT '',
	-- 自动备份设置(v2.3.x):调度器仅主节点运行;六设置列随 users 节同步到
	-- 从节点(历史问题,提升为主节点后直接生效,从端本地只读态不消费);
	-- last_run 为节点本地运行态——不同步、不入 cluster_version 触发器 OF 列表。
		auto_backup_enabled INTEGER DEFAULT 0,
		auto_backup_frequency TEXT DEFAULT 'daily',
		auto_backup_time TEXT DEFAULT '03:00',
		auto_backup_day INTEGER DEFAULT 1,
		auto_backup_keep INTEGER DEFAULT 7,
		auto_backup_sections TEXT DEFAULT '["users","rules","security","cluster"]',
		auto_backup_sections_version INTEGER NOT NULL DEFAULT 0,
		auto_backup_last_run DATETIME,
	-- 威胁大屏本站坐标(v3,node-local):面板设置里的公网坐标,0,0=未设置(前端
	-- 回退地图视觉中心);节点属性不入集群同步(先例 auto_backup_last_run)。
	server_map_lat REAL NOT NULL DEFAULT 0,
	server_map_lon REAL NOT NULL DEFAULT 0,
		updated_at DATETIME
	);

	-- Nodes table
	-- 历史问题-03（历史）：三列是历史状态机残留，语义如下，禁止新消费：
	--   status VARCHAR(20)         仅注册/审批/上报时写（pending/online），从不回写
	--                              'offline'；在线判定唯一口径=nodes.is_approved +
	--                              last_seen + nodeOfflineThreshold（ComputeNodeStatus）。
	--                              唯一判定性读点是审批 SQL 的 status='pending'
	--                              （若未来重建表，可改 is_approved=0 且
	--                              registration_secret 非空）。
	--   cluster_token_delivered    只写不读（注册/审批置 0、令牌下发置 1）；令牌重投
	--                              语义由 registration_secret 保留 + Snapshot 确认清除
	--                              承载，本列无消费方。
	--   sync_interval              写侧从不写（schema 默认 60），阈值口径统一读
	--                              global_config.sync_interval（历史问题-01）。
	-- 三列随下一次 nodes 重建迁移删除；此前保留仅为兼容旧库/旧快照回放。
	CREATE TABLE IF NOT EXISTS nodes (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		mode VARCHAR(10) NOT NULL DEFAULT 'slave',
		ip_address VARCHAR(45) NOT NULL,
		port INTEGER DEFAULT 8000,
		protocol VARCHAR(10) DEFAULT 'http',
		is_approved BOOLEAN DEFAULT FALSE,
		sync_interval INTEGER DEFAULT 60,
		status VARCHAR(20) DEFAULT 'offline',
		cluster_token_hash VARCHAR(64),
		registration_secret VARCHAR(64),
		registration_secret_expires_at DATETIME,
		cluster_token_delivered BOOLEAN DEFAULT FALSE,
		reported_version INTEGER DEFAULT 0,
		health_json TEXT,
		last_sync_at DATETIME,
		last_sync_error TEXT,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		server_map_lat REAL NOT NULL DEFAULT 0,
		server_map_lon REAL NOT NULL DEFAULT 0,
		UNIQUE(ip_address, port)
	);

	-- Create indexes
	-- 历史问题-5（历史）：idx_nodes_status 零查询消费（status 唯一读点是审批
	-- 点查 + is_approved 过滤，走 id 主键/无索引需求）——DDL 与两处表重建迁移
	-- 均不再创建，存量库由下方 DROP INDEX 迁移回收（省每次写入的索引维护）。

	CREATE TABLE IF NOT EXISTS cluster_register_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		token_hash VARCHAR(64) UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		used_at DATETIME,
		created_by INTEGER,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS used_login_tickets (
		jti_hash TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_used_login_tickets_expires_at ON used_login_tickets(expires_at);

	-- MFA 登录二步挑战（v2.1.8）：节点本地临时态，不参与集群同步/配置备份
	--（同 used_login_tickets 先例）；过期行（含未消费）由每次签发挑战时的
	-- 惰性 DELETE 清除（历史问题 修正：原注释所述 loginRateLimit 桶扫描不存在）。
	-- password_version（历史修复）：绑定签发时的密码版本——改密/重置
	-- 后旧挑战校验必败（验证端要求与 users.password_version 相等），
	-- 杜绝「旧密码取得挑战→重置后仍能完成 MFA」。
	CREATE TABLE IF NOT EXISTS mfa_challenges (
		token TEXT PRIMARY KEY,
		user_id INTEGER NOT NULL,
		expires_at DATETIME NOT NULL,
		consumed BOOLEAN DEFAULT 0,
		attempts INTEGER DEFAULT 0,
		password_version INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_mfa_challenges_expires_at ON mfa_challenges(expires_at);

	-- 登录令牌吊销表（logout 写入 jti_hash，jwtAuth 逐请求查）。
	-- 历史问题-2（历史）边界：不参与配置备份/还原与集群同步（备份节注册表
	-- config_backup.go:50-59 不含本表）——恢复后未过期的已吊销令牌在本节点复活。
	-- 判定有意设计-可接受：吊销项短时（expires_at 随令牌 exp，下方清理），且改密
	-- bump users.password_version 是持久吊销通道（pwd_ver 不匹配即拒）。
	CREATE TABLE IF NOT EXISTS revoked_jti (
		jti_hash TEXT PRIMARY KEY,
		expires_at DATETIME NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_revoked_jti_expires_at ON revoked_jti(expires_at);

	CREATE TABLE IF NOT EXISTS security_custom_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		conditions TEXT DEFAULT '[]',
		action TEXT DEFAULT 'block',
		score INTEGER DEFAULT 5,
		enabled BOOLEAN DEFAULT TRUE,
		updated_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	);

	CREATE TABLE IF NOT EXISTS security_block_pages (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		content TEXT DEFAULT '',
		-- 拦截响应 历史修复（2026-09-25 用户裁定可配置，白名单见 models）；
		-- 存量行由 ensureNewColumns 补列，默认即内置三页的形态。
		content_type TEXT DEFAULT 'text/html; charset=utf-8',
		is_default BOOLEAN DEFAULT FALSE,
		is_builtin BOOLEAN DEFAULT FALSE,
		created_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_by INTEGER DEFAULT 0,
		updated_at DATETIME DEFAULT (datetime('now'))
	);

	INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, created_at, updated_at)
		VALUES (1, '默认拦截页面', '系统默认 403 拦截页面',
			'<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Access Denied</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(165deg,#f8fafc 0%,#f1f5f9 45%,#eef2f7 100%);position:relative;overflow:hidden}.blob{position:absolute;border-radius:50%;filter:blur(70px)}.blob-a{width:380px;height:380px;background:rgba(59,130,246,.10);top:-120px;right:-80px}.blob-b{width:320px;height:320px;background:rgba(244,63,94,.08);bottom:-110px;left:-70px}.card{position:relative;background:#fff;border-radius:22px;padding:52px 48px 34px;text-align:center;width:min(560px,calc(100vw - 40px));box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px -8px rgba(16,24,40,.12),0 32px 64px -16px rgba(16,24,40,.10)}.card::before{content:"";position:absolute;top:0;left:24px;right:24px;height:3px;border-radius:0 0 4px 4px;background:linear-gradient(90deg,transparent,#f87171 18%,#ef4444 50%,#f87171 82%,transparent)}.badge{position:relative;width:84px;height:84px;margin:0 auto 20px}.badge-ring{position:absolute;inset:0;border-radius:24px;background:linear-gradient(145deg,#fef2f2,#fee2e2);border:1px solid #fecaca;box-shadow:0 4px 12px -2px rgba(239,68,68,.18)}.badge-halo{position:absolute;inset:-12px;border-radius:32px;border:1px dashed #fecdd3}.badge svg{position:absolute;inset:0;margin:auto;width:38px;height:38px}.chip{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;letter-spacing:.6px;color:#b91c1c;background:#fef2f2;border:1px solid #fecaca;border-radius:999px;padding:5px 14px;margin-bottom:16px}.chip::before{content:"";width:6px;height:6px;border-radius:50%;background:#ef4444}h1{font-size:28px;font-weight:700;color:#0f172a;letter-spacing:.2px;margin-bottom:14px}p{font-size:14px;color:#64748b;line-height:1.75;margin-bottom:6px}p strong{color:#334155;font-weight:600}.divider{margin:26px auto 0;padding-top:18px;width:75%;border-top:1px solid #f1f5f9;font-size:12px;color:#94a3b8}.divider .name{font-weight:600;color:#475569}</style></head><body><div class="blob blob-a"></div><div class="blob blob-b"></div><div class="card"><div class="badge"><div class="badge-halo"></div><div class="badge-ring"></div><svg viewBox="0 0 24 24" fill="none" stroke="#dc2626" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.4-3 8.4-7 10-4-1.6-7-5.6-7-10V6l7-3z"/><line x1="9.5" y1="9.5" x2="14.5" y2="14.5"/><line x1="14.5" y1="9.5" x2="9.5" y2="14.5"/></svg></div><div class="chip">403 Forbidden</div><h1>Access Denied</h1><p>Your request has been blocked by the <strong>security policy</strong>.</p><p>If you believe this is an error, please contact the administrator.</p><div class="divider">Powered by <span class="name">Lazy Balancer</span></div></div></body></html>',
			TRUE, datetime('now'), datetime('now'));


	-- 可复用 IP 地址列表（v2.3.0）：条目为 {value, remark} 对象数组；策略经
	-- ip_acl_list_refs / ip_whitelist_refs 以 ID 数组引用，生成期展开为
	-- inline ∪ 引用条目（去重、inline 优先）。时间戳列与 security_policies
	-- 同款 TEXT 形态（不用 block_pages 的 DATETIME 默认值，保持 NULL/'' 容忍）。
	CREATE TABLE IF NOT EXISTS security_ip_lists (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		category TEXT DEFAULT '',
		entries TEXT DEFAULT '[]',
		created_by INTEGER DEFAULT 0,
		created_at TEXT DEFAULT '',
		updated_by INTEGER DEFAULT 0,
		updated_at TEXT DEFAULT '',
		system INTEGER NOT NULL DEFAULT 0
	);

	-- 预置「自动封禁名单」行（历史问题）在 runMigrations 播种（威胁名单种子同位）
	-- ——schema 段引用 system 列会在「无 system 列的存量旧表」上炸掉整份建表
	-- 脚本（TestIPListsSystemColumn_legacyMigration 同款场景）。

	CREATE TABLE IF NOT EXISTS security_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		mode TEXT DEFAULT 'off',
		anomaly_threshold INTEGER DEFAULT 5,
		ip_acl_mode TEXT DEFAULT '',
		ip_acl_list TEXT DEFAULT '[]',
		ip_acl_enabled BOOLEAN DEFAULT FALSE,
		ip_whitelist TEXT DEFAULT '[]',
		ip_whitelist_enabled INTEGER DEFAULT 1,
		ip_blacklist TEXT DEFAULT '[]',
		rate_limit_enabled BOOLEAN DEFAULT FALSE,
		rate_limit_rps INTEGER DEFAULT 0,
		rate_limit_burst INTEGER DEFAULT 0,
		crs_rule_groups TEXT DEFAULT '[]',
		crs_excluded_rules TEXT DEFAULT '[]',
	custom_rules TEXT DEFAULT '[]',
	block_page_id INTEGER DEFAULT 0,
	block_status_code INTEGER DEFAULT 0,
	enabled BOOLEAN DEFAULT TRUE,
		updated_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now')),
	geoip_countries TEXT DEFAULT '[]',
	geoip_mode TEXT DEFAULT 'deny',
	waf_check_response INTEGER DEFAULT 0,
	log_request_body INTEGER DEFAULT 0,
	ip_acl_list_refs TEXT DEFAULT '[]',
	ip_whitelist_refs TEXT DEFAULT '[]',
	-- 历史修复（历史）：实体单职化/阶段 0 两列与 newColumns 对齐
	-- （TEXT NOT NULL DEFAULT '' / BOOLEAN NOT NULL DEFAULT 0），fresh 建库
	-- 不再依赖启动补列。
	policy_type TEXT NOT NULL DEFAULT '',
	trust_detection BOOLEAN NOT NULL DEFAULT 0,
	geoip_crawler_exempt INTEGER NOT NULL DEFAULT 0,
	geoip_crawler_engines TEXT NOT NULL DEFAULT '[]'
	);
	CREATE TABLE IF NOT EXISTS security_policy_bindings (
		rule_caddy_id TEXT NOT NULL,
		policy_id INTEGER NOT NULL,
		PRIMARY KEY (rule_caddy_id, policy_id)
	);
	CREATE INDEX IF NOT EXISTS idx_lb_rules_enabled ON lb_rules(enabled);
	CREATE TABLE IF NOT EXISTS security_crs_version (
		id INTEGER PRIMARY KEY,
		version TEXT NOT NULL,
		updated_at DATETIME DEFAULT (datetime('now')),
		auto_update BOOLEAN DEFAULT TRUE,
		schedule_days TEXT NOT NULL DEFAULT '1,2,3,4,5,6,7',
		schedule_time TEXT NOT NULL DEFAULT '04:00'
	);
	CREATE TABLE IF NOT EXISTS security_ip2region_version (
		id INTEGER PRIMARY KEY,
		version TEXT NOT NULL,
		updated_at DATETIME DEFAULT (datetime('now')),
		auto_update BOOLEAN DEFAULT TRUE,
		update_status TEXT DEFAULT 'idle',
		message TEXT DEFAULT '',
		last_checked DATETIME,
		next_update DATETIME,
		trigger TEXT DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME,
		schedule_days TEXT NOT NULL DEFAULT '1,2,3,4,5,6,7',
		schedule_time TEXT NOT NULL DEFAULT '04:00'
	);
	CREATE TABLE IF NOT EXISTS auto_backups (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		filename TEXT NOT NULL UNIQUE,
		created_at DATETIME NOT NULL DEFAULT (datetime('now')),
		status TEXT NOT NULL DEFAULT 'success' CHECK (status IN ('success','failed')),
		size_bytes INTEGER DEFAULT 0,
		sections TEXT DEFAULT '[]',
		trigger_type TEXT NOT NULL DEFAULT 'schedule' CHECK (trigger_type IN ('schedule','manual')),
		message TEXT DEFAULT '',
		app_version TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_auto_backups_created_at ON auto_backups(created_at);
	-- 统一任务引擎（v2.3.4 lazy-task-engine）：全部任务族的运行历史。
	-- 304 空轮/纯镜像不落库；仅真实执行与终态。保留随安全事件保留清理族。
	-- 历史修复（历史）：stage/entry_count 零写入方死列已删（存量库经
	-- deadColumnDrops 幂等移除）。
	CREATE TABLE IF NOT EXISTS task_runs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		task_id TEXT NOT NULL,
		family TEXT NOT NULL,
		trigger TEXT NOT NULL DEFAULT '',
		operator TEXT NOT NULL DEFAULT '',
		status TEXT NOT NULL DEFAULT 'running' CHECK (status IN ('running','success','failed','cancelled','skipped','interrupted')),
		started_at TEXT NOT NULL DEFAULT (datetime('now')),
		finished_at TEXT DEFAULT '',
		duration_ms INTEGER DEFAULT 0,
		message TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_task_runs_task_time ON task_runs(task_id, started_at DESC);
	CREATE INDEX IF NOT EXISTS idx_task_runs_time ON task_runs(started_at DESC);
	-- 历史问题（历史）：RunOverview 的「每任务最新行」（id IN (SELECT MAX(id)
	-- ... GROUP BY task_id)）此前每 10s 全表扫描 task_runs；(task_id, id) 复合
	-- 索引让 GROUP BY task_id 走索引有序扫描（免回表），代价降到索引面。
	CREATE INDEX IF NOT EXISTS idx_task_runs_task_latest ON task_runs(task_id, id);
	-- 任务调度偏好（历史问题，历史）：节点本地持久化用户显式启停，
	-- 进程重启/角色翻转后据此覆盖默认启动清单；业务驱动任务以业务字段为
	-- 唯一事实源，不写本表。节点本地表：不进入集群快照/备份导出。
	CREATE TABLE IF NOT EXISTS task_loop_prefs (
		task_id TEXT PRIMARY KEY,
		enabled INTEGER NOT NULL,
		updated_at TEXT NOT NULL DEFAULT (datetime('now'))
	);
	-- 爬虫地址库（v2.3.8）：四个官方爬虫 IP 源，update_enabled 默认开；
	-- 版本=成功更新日期（YYYY.MM.DD），独立源表/排程/状态机，不并入威胁情报库。
	CREATE TABLE IF NOT EXISTS security_crawler_sources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL DEFAULT '',
		url TEXT NOT NULL DEFAULT '',
		format TEXT NOT NULL DEFAULT 'plain',
		update_enabled INTEGER NOT NULL DEFAULT 1,
		entry_count INTEGER NOT NULL DEFAULT 0,
		version TEXT NOT NULL DEFAULT '',
		update_status TEXT NOT NULL DEFAULT 'idle',
		message TEXT NOT NULL DEFAULT '',
		last_checked DATETIME,
		next_update DATETIME,
		trigger TEXT NOT NULL DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME,
		consecutive_failures INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	);

CREATE TABLE IF NOT EXISTS security_threat_sources (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL DEFAULT '',
		url TEXT NOT NULL DEFAULT '',
		format TEXT NOT NULL DEFAULT 'plain',
		update_enabled INTEGER NOT NULL DEFAULT 1,
		-- 弃用保留（历史问题）：v2.3.2 名单化后零消费（「引用即应用」），保留仅为旧备份还原/旧快照兼容。
		apply_enabled INTEGER NOT NULL DEFAULT 1,
		entry_count INTEGER NOT NULL DEFAULT 0,
		version TEXT NOT NULL DEFAULT '',
		update_status TEXT NOT NULL DEFAULT 'idle',
		message TEXT NOT NULL DEFAULT '',
		last_checked DATETIME,
		next_update DATETIME,
		trigger TEXT NOT NULL DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME,
		consecutive_failures INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	);
	INSERT OR IGNORE INTO security_ip2region_version (id, version, auto_update) VALUES (1, 'unknown', 1);
	`

	if _, err := DB.Exec(schema); err != nil {
		return err
	}
	// 威胁库三源种子（v2.3.x）——USTC URL 含「?」必须走参数化（原始 SQL 中
	// 会被当作占位符）。INSERT OR IGNORE 幂等，存量库重启重复执行安全。
	for _, seed := range threatSourceSeeds {
		if _, err := DB.Exec(`INSERT OR IGNORE INTO security_threat_sources (name, display_name, url, format) VALUES (?, ?, ?, ?)`, seed.Name, seed.DisplayName, seed.URL, seed.Format); err != nil {
			return fmt.Errorf("failed to seed threat source %s: %w", seed.Name, err)
		}
		// 存量行 display_name 专业化跟进（2026-09-24 用户裁定；name 为定位键不变）
		if _, err := DB.Exec(`UPDATE security_threat_sources SET display_name=? WHERE name=? AND COALESCE(display_name,'')<>?`, seed.DisplayName, seed.Name, seed.DisplayName); err != nil {
			return fmt.Errorf("failed to refresh threat source display_name %s: %w", seed.Name, err)
		}
	}
	return nil
}

func runMigrations() error {
	// 历史修复（历史）：users.display_name/is_enabled、api_keys.is_enabled/
	// mcp_enabled/read_only/mcp_ip_whitelist 与 lb_rules 八列（domain/tls_cert/
	// tls_key/tls_http_redirect/dynamic_dns/enable_active_health_check/tls_source/
	// acme_config_id）的「缺列即补」自此收敛入下方 newColumns 统一通道登记——
	// 三代并存惯用法（逐列硬编码/局部 map 循环/通用 ensureNewColumns）只留后者，
	// 下次加列只有一处登记点（schedule_days 单侧漏登记事故即登记点分裂的代价）。

	strategyResult, err := DB.Exec("UPDATE lb_rules SET strategy='weighted_round_robin' WHERE strategy='round_robin'")
	if err != nil {
		return fmt.Errorf("failed to normalize lb_rules strategy: %w", err)
	}
	if n, _ := strategyResult.RowsAffected(); n > 0 {
		// 历史问题（历史）：用户规则配置被改写须留痕。
		detail := fmt.Sprintf("启动迁移：存量规则负载策略 round_robin 归一为 weighted_round_robin：%d 条", n)
		log.Print(detail)
		recordSystemAudit("启动迁移", "负载规则", detail)
	}

	if _, err := DB.Exec("DROP TABLE IF EXISTS config_versions"); err != nil {
		return fmt.Errorf("failed to drop config_versions: %w", err)
	}
	if _, err := dropColumnIfExists("global_config", "access_log_enabled"); err != nil {
		return err
	}
	// 历史修复（2026-09-05/06 审计裁定）：metrics_public/metrics_origins 为零
	// 消费死列（历史上预留给「指标公开访问/CORS」设想，从未接线）；
	// metrics_retention_days 的指标保留期已改用 audit_retention_months
	//（2026-09-06 裁定，历史修复）——三列存量库逐列删除（逐列判定使单列残留
	// 形态也可收敛）；新库由建表语句与 newColumns 不再补建。
	for _, deadMetricsColumn := range []string{"metrics_public", "metrics_origins", "metrics_retention_days"} {
		if _, err := dropColumnIfExists("global_config", deadMetricsColumn); err != nil {
			return err
		}
	}

	// ca_providers columns are created by createTables; here we only add columns to existing tables.
	// 历史修复（历史声明对齐口径）：fresh DDL 不追平 newColumns 为既定口径，
	// 适用表——global_config（单行表，原裁定见下文 threat_schedule 段注释）、
	// security_threat_sources（content_hash/raw_hash）、security_crs_version
	//（update_status/message/last_checked/next_update/trigger/started_at/
	// finished_at/consecutive_failures 八列；姊妹表 security_ip2region_version
	// fresh DDL 全带属历史不对称，不追平）、nodes（access_url 等）、users
	//（mfa_*/oidc_*/password_* 等）。fresh 库与存量库恒经本通道补列收敛；
	// 例外：整表重建迁移（users/security_policies/nodes/lb_rules+upstreams/
	// cert_jobs 重建 DDL）必须同步携列——重建位于二次 ensureNewColumns 安全网
	// 之后，丢列无同启动自愈（历史问题 先例）。
	newColumns := map[string]string{
		// 历史修复（历史）迁入登记：原 runMigrations 头部的逐列硬编码检查与
		// apiKeyColumns/newLbColumns 局部 map 循环——DDL 与默认值逐字沿用原登记。
		"users.display_name":                  "VARCHAR(100)",
		"users.is_enabled":                    "BOOLEAN DEFAULT 1",
		"api_keys.is_enabled":                 "BOOLEAN DEFAULT 1",
		"api_keys.mcp_enabled":                "INTEGER DEFAULT 0",
		"api_keys.read_only":                  "INTEGER DEFAULT 0",
		"api_keys.mcp_ip_whitelist":           "TEXT DEFAULT ''",
		"lb_rules.domain":                     "VARCHAR(255)",
		"lb_rules.tls_cert":                   "TEXT",
		"lb_rules.tls_key":                    "TEXT",
		"lb_rules.tls_http_redirect":          "BOOLEAN DEFAULT 0",
		"lb_rules.dynamic_dns":                "BOOLEAN DEFAULT 0",
		"lb_rules.enable_active_health_check": "BOOLEAN DEFAULT 0",
		"lb_rules.tls_source":                 "VARCHAR(20) DEFAULT 'manual'",
		"lb_rules.acme_config_id":             "INTEGER DEFAULT 0",
		"lb_rules.ca_provider_id":             "INTEGER DEFAULT 0",
		"lb_rules.caddy_id":                   "VARCHAR(20)",
		"lb_rules.dns_family":                 "VARCHAR(20) DEFAULT 'ipv4'",
		"lb_rules.updated_by":                 "INTEGER",
		"lb_rules.tcp_health_check_port":      "INTEGER DEFAULT 0",
		"lb_rules.tcp_proxy_protocol":         "BOOLEAN DEFAULT 0",
		"lb_rules.tcp_try_duration":           "INTEGER DEFAULT 0",
		"lb_rules.tcp_try_interval":           "INTEGER NOT NULL DEFAULT 250",
		"lb_rules.request_body_max_size_mb":   "INTEGER DEFAULT 0",
		"lb_rules.upstream_keepalive_timeout": "INTEGER DEFAULT 0",
		"lb_rules.server_tokens_hidden":       "INTEGER DEFAULT 0",
		"lb_rules.ntlm_compatible":            "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.upstream_force_http1":       "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.block_page_stage1_id":       "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.block_page_stage1_status":   "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.block_page_stage3_id":       "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.block_page_stage3_status":   "INTEGER NOT NULL DEFAULT 0",
		"auto_backups.app_version":            "TEXT NOT NULL DEFAULT ''",
		// 统一任务引擎（历史问题-03）：手动触发操作者归因列——runNow/Trigger 落
		// 操作者，auto/startup/legacy 落空串。存量库幂等补列（ensureNewColumns）。
		"task_runs.operator":                              "TEXT NOT NULL DEFAULT ''",
		"security_custom_rules.updated_by":                "INTEGER DEFAULT 0",
		"security_policies.policy_type":                   "TEXT NOT NULL DEFAULT ''",
		"security_policies.trust_detection":               "BOOLEAN NOT NULL DEFAULT 0",
		"security_crs_version.update_status":              "TEXT DEFAULT 'idle'",
		"security_crs_version.message":                    "TEXT DEFAULT ''",
		"security_crs_version.last_checked":               "DATETIME",
		"security_crs_version.next_update":                "DATETIME",
		"security_crs_version.trigger":                    "TEXT DEFAULT ''",
		"security_crs_version.started_at":                 "DATETIME",
		"security_crs_version.finished_at":                "DATETIME",
		"security_crs_version.consecutive_failures":       "INTEGER DEFAULT 0",
		"security_ip2region_version.update_status":        "TEXT DEFAULT 'idle'",
		"security_ip2region_version.message":              "TEXT DEFAULT ''",
		"security_ip2region_version.last_checked":         "DATETIME",
		"security_ip2region_version.next_update":          "DATETIME",
		"security_ip2region_version.trigger":              "TEXT DEFAULT ''",
		"security_ip2region_version.started_at":           "DATETIME",
		"security_ip2region_version.finished_at":          "DATETIME",
		"security_ip2region_version.consecutive_failures": "INTEGER DEFAULT 0",
		"upstreams.max_connections":                       "INTEGER DEFAULT 0",
		// 逐上游回源域名 + 健康检查域名（2026-10-10）：空串=不配置，
		// 回退规则级 host_header / 现状默认。
		"upstreams.origin_domain":          "TEXT NOT NULL DEFAULT ''",
		"lb_rules.health_check_host":       "TEXT NOT NULL DEFAULT ''",
		"global_config.threat_auto_update": "INTEGER NOT NULL DEFAULT 1",
		// 一次性迁移旗标列：迁移函数只读/置位，列创建统一走本登记点
		// （幂等 ensureNewColumns），不再各自 pragma 探测 + ALTER。
		"global_config.waf_mode4_migrated":     "BOOLEAN DEFAULT 0",
		"global_config.sync_switches_migrated": "BOOLEAN DEFAULT 0",
		// 存量自定义规则清理的一次性指纹 marker（迁移定义版本；''=未跑）。
		// 该迁移的判据在 JSON 内容里，无法用索引探测，只能整表读+解析——marker
		// 置位后启动零读零写。
		"global_config.legacy_custom_rule_sanitize_fp": "TEXT NOT NULL DEFAULT ''",
		"security_ip_lists.system":                     "INTEGER NOT NULL DEFAULT 0",
		// MFA 登录挑战绑定签发时密码版本（历史修复）。
		"mfa_challenges.password_version":      "INTEGER NOT NULL DEFAULT 0",
		"path_rules.upstream_path":             "TEXT NOT NULL DEFAULT ''",
		"security_threat_sources.content_hash": "TEXT DEFAULT ''",
		"security_threat_sources.raw_hash":     "TEXT DEFAULT ''",
		// 规则库定时调度（v2.3.x）：星期多选逗号串（1=周一…7=周日，默认全选=
		// 每天）+ HH:MM 时间（默认 04:00），槽位按基础设置时区本地日历计算、
		// UTC 落库。CRS/IP2Region 列落版本表；威胁库为任务级排程，列挂
		// global_config（与 threat_auto_update 同表先例）。
		"security_crs_version.schedule_days": "TEXT NOT NULL DEFAULT '1,2,3,4,5,6,7'",
		"security_crs_version.schedule_time": "TEXT NOT NULL DEFAULT '04:00'",
		// 自定义路由静态响应/301 跳转（2026-10-10）：path_rules 五列，''=转发零漂移。
		"path_rules.response_mode":         "TEXT NOT NULL DEFAULT ''",
		"path_rules.response_status":       "INTEGER NOT NULL DEFAULT 200",
		"path_rules.response_body":         "TEXT NOT NULL DEFAULT ''",
		"path_rules.response_content_type": "TEXT NOT NULL DEFAULT ''",
		"path_rules.redirect_to":           "TEXT NOT NULL DEFAULT ''",
		// ip2region 侧同族两列（历史追加问题，用户上报）：fresh DDL 建表
		// 含两列（db.go ip2region_version CREATE），存量库补列迁移此前漏登记
		// ——升级安装更新定时排程必报 no such column: schedule_days。
		"security_ip2region_version.schedule_days": "TEXT NOT NULL DEFAULT '1,2,3,4,5,6,7'",
		"security_ip2region_version.schedule_time": "TEXT NOT NULL DEFAULT '04:00'",
		// global_config 单行表恒经 newColumns 补列（threat_auto_update 起的既定
		// 口径——fresh DDL 不追平，历史修复 对齐仅适用多行版本/策略表）。
		"global_config.threat_schedule_days": "TEXT NOT NULL DEFAULT '1,2,3,4,5,6,7'",
		"global_config.threat_schedule_time": "TEXT NOT NULL DEFAULT '04:00'",
		// 爬虫地址库（v2.3.8 独立库）：任务级总闸与排程独立三列，
		// 不共享 threat_* 配置。
		"global_config.crawler_auto_update":    "INTEGER NOT NULL DEFAULT 1",
		"global_config.crawler_schedule_days":  "TEXT NOT NULL DEFAULT '1,2,3,4,5,6,7'",
		"global_config.crawler_schedule_time":  "TEXT NOT NULL DEFAULT '04:00'",
		"cert_jobs.ca_provider_id":             "INTEGER DEFAULT 0",
		"cert_jobs.renewal_attempts":           "INTEGER DEFAULT 0",
		"cert_jobs.ca_available_after":         "DATETIME",
		"cert_jobs.last_error_code":            "VARCHAR(20)",
		"cert_jobs.deployment_attempts":        "INTEGER DEFAULT 0",
		"cert_jobs.deployment_available_after": "DATETIME",
		"users.mfa_enabled":                    "BOOLEAN DEFAULT 0",
		"users.mfa_secret":                     "TEXT DEFAULT ''",
		"users.mfa_pending_secret":             "TEXT DEFAULT ''",
		"users.mfa_recovery_codes":             "TEXT DEFAULT '[]'",
		"users.mfa_last_timestep":              "INTEGER DEFAULT 0",
		"users.mfa_pending_fails":              "INTEGER DEFAULT 0",
		// 历史修复（契约）：账户级登录锁定列（auth.go Login 写读；与 MFA 写保护的
		// mfa_* 计数列独立，登录锁定与 MFA 冷却互不牵连）。计数列 NOT NULL——
		// 存量行取默认 0，不存在 NULL 语义。
		"users.login_failed_attempts": "INTEGER NOT NULL DEFAULT 0",
		"users.login_locked_until":    "TEXT",
		// OIDC 集成(2026-09-17 v2.3.0):用户来源标记与身份三元组——
		// auth_provider 'local'/'oidc';oidc 用户不绑定本地账号(独立行),
		// (issuer, subject) 唯一定位,重复登录按此命中。
		"users.auth_provider":               "TEXT NOT NULL DEFAULT 'local'",
		"users.oidc_subject":                "TEXT DEFAULT ''",
		"users.oidc_issuer":                 "TEXT DEFAULT ''",
		"global_config.oidc_config":         "TEXT",
		"mfa_challenges.attempts":           "INTEGER DEFAULT 0",
		"global_config.mfa_write_guard":     "BOOLEAN DEFAULT 0",
		"global_config.mfa_lockout_enabled": "BOOLEAN DEFAULT 0",
		// v2.3.x 真实 IP 支持：受信代理（CDN 回源）四列——启用开关、回源网段
		// （CIDR JSON 数组）、请求头名（有序 JSON 数组）、严格模式。渲染层
		// （servers.trusted_proxies）与 caddygeoip/限流/阶段 0 取值共用。
		"global_config.trusted_proxy_enabled": "INTEGER NOT NULL DEFAULT 0",
		"global_config.trusted_proxy_ranges":  "TEXT NOT NULL DEFAULT '[]'",
		// 受信网段引用名单（2026-10-12）：JSON 数组文本，存 security_ip_lists 的
		// id 列表（镜像策略 ip_acl_list_refs 形态）；渲染与内联 CIDR 合并投影
		// （2026-10-15 热路径化：tp.txt/lb_file 文件源，内容变化零 /load）。
		"global_config.trusted_proxy_range_refs":               "TEXT NOT NULL DEFAULT '[]'",
		"global_config.trusted_proxy_headers":                  "TEXT NOT NULL DEFAULT '[]'",
		"global_config.trusted_proxy_strict":                   "INTEGER NOT NULL DEFAULT 1",
		"global_config.default_ca_provider_id":                 "INTEGER DEFAULT 0",
		"global_config.cert_renewal_days":                      "INTEGER DEFAULT 30",
		"global_config.cert_renewal_attempts":                  "INTEGER DEFAULT 5",
		"global_config.task_log_size_mb":                       "INTEGER DEFAULT 10",
		"global_config.audit_log_size_mb":                      "INTEGER DEFAULT 10",
		"global_config.caddy_apply_error":                      "TEXT DEFAULT ''",
		"global_config.runtime_log_size_mb":                    "INTEGER DEFAULT 100",
		"global_config.acme_email":                             "VARCHAR(255)",
		"global_config.cert_expiry_days":                       "INTEGER DEFAULT 30",
		"global_config.caddy_log_level":                        "VARCHAR(10) DEFAULT 'info'",
		"global_config.caddy_log_size_mb":                      "INTEGER NOT NULL DEFAULT 100",
		"global_config.request_body_max_size_mb":               "INTEGER NOT NULL DEFAULT 128",
		"global_config.http_read_timeout":                      "INTEGER NOT NULL DEFAULT 60",
		"global_config.http_write_timeout":                     "INTEGER NOT NULL DEFAULT 60",
		"global_config.http_idle_timeout":                      "INTEGER NOT NULL DEFAULT 120",
		"global_config.upstream_keepalive_timeout":             "INTEGER DEFAULT 0",
		"global_config.server_tokens_hidden":                   "BOOLEAN DEFAULT FALSE",
		"global_config.admin_tls_enabled":                      "BOOLEAN DEFAULT 0",
		"global_config.admin_tls_mode":                         "VARCHAR(20) DEFAULT 'selfsigned'",
		"global_config.admin_tls_cert":                         "TEXT DEFAULT ''",
		"global_config.admin_tls_key":                          "TEXT DEFAULT ''",
		"global_config.access_log_json":                        "BOOLEAN DEFAULT TRUE",
		"global_config.access_log_format":                      "TEXT DEFAULT ''",
		"global_config.audit_retention_months":                 "INTEGER DEFAULT 3",
		"global_config.jwt_expire_minutes":                     "INTEGER DEFAULT 20",
		"global_config.timezone":                               "VARCHAR(50) DEFAULT 'Asia/Shanghai'",
		"global_config.github_proxy_url":                       "TEXT NOT NULL DEFAULT 'https://v4.gh-proxy.org/'",
		"global_config.github_token":                           "TEXT NOT NULL DEFAULT ''",
		"global_config.server_map_lat":                         "REAL NOT NULL DEFAULT 0",
		"global_config.threat_screen_mode":                     fmt.Sprintf("TEXT NOT NULL DEFAULT '%s'", DefaultThreatScreenMode),
		"global_config.threat_traffic_sample_n":                fmt.Sprintf("INTEGER NOT NULL DEFAULT %d", DefaultThreatTrafficSampleN), // -1=自适应/0=关闭（全量/固定档废除）
		"global_config.threat_traffic_sample_unified_migrated": "INTEGER NOT NULL DEFAULT 0",
		// 安全事件保留显式化：默认 90 天 / 100 万行由配置本身承载，
		// 不再用 0 隐式映射服务层写死默认值。历史问题：默认值单源=Default* 常量。
		"global_config.security_events_retention_days":     fmt.Sprintf("INTEGER NOT NULL DEFAULT %d", DefaultSecurityEventsRetentionDays),
		"global_config.security_events_row_cap":            fmt.Sprintf("INTEGER NOT NULL DEFAULT %d", DefaultSecurityEventsRowCap),
		"global_config.security_events_retention_migrated": "INTEGER NOT NULL DEFAULT 0",
		// 历史问题（历史）：CA 提供商播种一次性 marker。此前「表空即
		// 播种」每次启动评估——导入/集群快照把 ca_providers 清空后重启会复活
		// ZeroSSL/LE 并覆盖 default_ca_provider_id，与「删除即不存在」相悖。
		// marker=1 表示本库已完成首播，此后表空保持空（节点本地语义：不参与
		// 集群快照/配置备份——见 runMigrations 播种块注释）。
		"global_config.ca_providers_seeded":           "INTEGER NOT NULL DEFAULT 0",
		"global_config.server_map_lon":                "REAL NOT NULL DEFAULT 0",
		"lb_rules.log_enabled":                        "BOOLEAN DEFAULT 0",
		"lb_rules.custom_routes_enabled":              "BOOLEAN NOT NULL DEFAULT 0",
		"lb_rules.proxy_dial_timeout":                 "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_response_header_timeout":      "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_read_timeout":                 "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_write_timeout":                "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_stream_timeout":               "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_flush_interval":               "INTEGER NOT NULL DEFAULT 0",
		"lb_rules.proxy_stream_close_delay":           "INTEGER NOT NULL DEFAULT 0",
		"global_config.proxy_dial_timeout":            "INTEGER DEFAULT 0",
		"global_config.proxy_response_header_timeout": "INTEGER DEFAULT 0",
		"global_config.proxy_read_timeout":            "INTEGER DEFAULT 0",
		"global_config.proxy_write_timeout":           "INTEGER DEFAULT 0",
		"global_config.proxy_stream_timeout":          "INTEGER DEFAULT 0",
		"global_config.proxy_flush_interval":          "INTEGER DEFAULT 0",
		"global_config.proxy_stream_close_delay":      "INTEGER DEFAULT 0",
		"users.password_changed_at":                   "DATETIME",
		"users.password_version":                      "INTEGER NOT NULL DEFAULT 0",
		"global_config.cluster_version":               "INTEGER DEFAULT 0",
		"global_config.sync_users":                    "BOOLEAN DEFAULT 1",
		// branding.json 原文镜像(2026-09-11):主节点经快照分发到从节点,
		// 入触发器 OF 列表——文件变化即 bump cluster_version。
		"global_config.branding_json":                 "TEXT DEFAULT ''",
		"global_config.sync_rules":                    "BOOLEAN DEFAULT 1",
		"global_config.sync_security":                 "BOOLEAN DEFAULT 1",
		"global_config.cluster_token":                 "TEXT DEFAULT ''",
		"global_config.registration_id":               "INTEGER DEFAULT 0",
		"global_config.registration_secret":           "TEXT DEFAULT ''",
		"global_config.registration_confirm_failures": "INTEGER DEFAULT 0",
		"global_config.applied_version":               "INTEGER DEFAULT 0",
		"global_config.last_sync_error":               "TEXT DEFAULT ''",
		"global_config.sync_fingerprint":              "TEXT DEFAULT ''",
		"nodes.cluster_token_hash":                    "VARCHAR(64)",
		"nodes.protocol":                              "VARCHAR(10) DEFAULT 'http'",
		"nodes.access_url":                            "VARCHAR(255) DEFAULT ''",
		"nodes.registration_secret":                   "VARCHAR(64)",
		"nodes.registration_secret_expires_at":        "DATETIME",
		"nodes.cluster_token_delivered":               "BOOLEAN DEFAULT 0",
		"nodes.reported_version":                      "INTEGER DEFAULT 0",
		"nodes.health_json":                           "TEXT",
		"nodes.last_sync_at":                          "DATETIME",
		"nodes.last_sync_error":                       "TEXT",
		"security_policies.crs_excluded_rules":        "TEXT DEFAULT '[]'",
		"security_policies.ip_acl_mode":               "TEXT DEFAULT ''",
		"security_policies.ip_acl_list":               "TEXT DEFAULT '[]'",
		"security_policies.ip_acl_enabled":            "BOOLEAN DEFAULT FALSE",
		"security_policies.block_page_id":             "INTEGER DEFAULT 0",
		"security_block_pages.created_by":             "INTEGER DEFAULT 0",
		"security_block_pages.updated_by":             "INTEGER DEFAULT 0",
		// 内置备选拦截页标志（2026-09-25 裁定）：id 9001 限流/9002 维护，与
		// is_default 同门禁（不可编辑/删除），仅作模板手动选用，无自动绑定。
		"security_block_pages.is_builtin":   "INTEGER DEFAULT 0",
		"security_block_pages.content_type": "TEXT DEFAULT 'text/html; charset=utf-8'",
		"security_policies.updated_by":      "INTEGER DEFAULT 0",
		// 四列刻意可空（不加 NOT NULL）：restoreTable/快照/带外脏数据可携带 NULL，
		// 读路径 loadSecurityPolicyContext 以 COALESCE 归一化；加 NOT NULL 会拒绝 null 恢复（历史修复 回归测试）。
		"security_policies.ip_whitelist_enabled":  "INTEGER DEFAULT 1",
		"security_policies.geoip_countries":       "TEXT DEFAULT '[]'",
		"security_policies.geoip_mode":            "TEXT DEFAULT 'deny'",
		"security_policies.geoip_crawler_exempt":  "INTEGER NOT NULL DEFAULT 0",
		"security_policies.geoip_crawler_engines": "TEXT NOT NULL DEFAULT '[]'",
		"security_policies.waf_check_response":    "INTEGER DEFAULT 0",
		"security_policies.block_status_code":     "INTEGER DEFAULT 0",
		// 策略级「记录请求体」开关（v2.2.3）：开启后该策略 handler 的审计 parts
		// 加 C，事件落 request_body（64KB 截断）。同口径刻意可空，读路径
		// COALESCE(...,0) 归一。
		"security_policies.log_request_body": "INTEGER DEFAULT 0",
		// 可复用 IP 列表引用列（v2.3.0）：JSON 数组文本，存 security_ip_lists 的
		// id 列表；同样刻意可空——读路径一律 COALESCE(...,'[]') 归一（同上口径）。
		"security_policies.ip_acl_list_refs":  "TEXT DEFAULT '[]'",
		"security_policies.ip_whitelist_refs": "TEXT DEFAULT '[]'",
		// 自动备份(v2.3.x):设置五列 + 节点本地运行态 last_run
		"global_config.auto_backup_enabled":          "INTEGER DEFAULT 0",
		"global_config.auto_backup_frequency":        "TEXT DEFAULT 'daily'",
		"global_config.auto_backup_time":             "TEXT DEFAULT '03:00'",
		"global_config.auto_backup_day":              "INTEGER DEFAULT 1",
		"global_config.auto_backup_keep":             "INTEGER DEFAULT 7",
		"global_config.auto_backup_sections":         "TEXT DEFAULT '[\"users\",\"rules\",\"security\",\"cluster\"]'",
		"global_config.auto_backup_sections_version": "INTEGER NOT NULL DEFAULT 0",
		"global_config.auto_backup_last_run":         "DATETIME",
		// 三分类合并·方案A(2026-09-19):文件态记账专用列(wafFilesDrifted
		// 的 304 兜底与 历史问题 标签自愈依赖;哈希域=纯 ref 含版本标签)。
		"global_config.applied_waf_ref_hash":    "TEXT DEFAULT ''",
		"global_config.applied_waf_ref_version": "INTEGER DEFAULT 0",
		// 自动封禁（历史问题）六项配置列：启用/阈值/窗口分钟/封禁时长（枚举
		// '10m','30m','1h','6h','12h','24h','permanent'）/统计口径（'blocked',
		// 'logged','all'）/观察模式（1=默认 dry-run，仅记录建议不落名单）。
		// 全部 NOT NULL——语义零值即合法值（关/100/5/'1h'/'all'/观察），无 NULL 分支。
		"global_config.autoban_enabled":        "INTEGER NOT NULL DEFAULT 0",
		"global_config.autoban_threshold":      "INTEGER NOT NULL DEFAULT 100",
		"global_config.autoban_window_minutes": "INTEGER NOT NULL DEFAULT 5",
		"global_config.autoban_duration":       "TEXT NOT NULL DEFAULT '1h'",
		"global_config.autoban_scope":          "TEXT NOT NULL DEFAULT 'all'",
		"global_config.autoban_dry_run":        "INTEGER NOT NULL DEFAULT 1",
		"nodes.server_map_lat":                 "REAL NOT NULL DEFAULT 0",
		"nodes.server_map_lon":                 "REAL NOT NULL DEFAULT 0",
	}
	// 历史问题: 四个全局超时列的 0→推荐默认回填原为「仅新增列时执行一次」——
	// 当时渲染层把 0 当作「省略=用 Caddy 默认」的有效值，每启动无条件回填会
	// 静默改写用户显式设置的 0。批 1+2（库值唯一真相，2026-10-14 用户裁定）
	// 推翻该口径：http_read/write/idle_timeout 三列转为类型①值型（0 无效），
	// 回填改为每启动幂等 UPDATE（defaultUpdates，WHERE IS NULL OR <=0——0 已非
	// 合法用户选择，归一不是改写）；此处三列一次性回填随之退役。
	// upstream_keepalive_timeout 保持类型②省略型（0=省略=历史问题 用户裁定，继承
	// Caddy/Go Transport 默认 2 分钟）——「新增列时代存量行为 0」的一次性形状
	// 防御保留，显式 60 是写侧合法值，任何迁移不得改写（历史问题）。
	newColumnBackfills := map[string]string{
		// 审计 历史问题/本列自引入起 DEFAULT 0，新增当刻存量行恒为 0——
		// 此回填仅覆盖理论上的「列带 DEFAULT 60 时代新增」路径，实际库零命中
		//（保留作形状防御）；真正的默认值收敛由 fresh CREATE DEFAULT 0 承担。
		// 用户显式设置的 60 是写侧合法值，任何启动期迁移不得改写。
		"global_config.upstream_keepalive_timeout": "UPDATE global_config SET upstream_keepalive_timeout=0 WHERE upstream_keepalive_timeout=60",
		// 历史 存量挑战按用户当前密码版本回填（列新增当刻这些
		// 挑战本就按「当前密码未变」语义有效，行为零漂移；一次性形状）。
		"mfa_challenges.password_version": "UPDATE mfa_challenges SET password_version=COALESCE((SELECT COALESCE(password_version,0) FROM users WHERE users.id=mfa_challenges.user_id),0)",
	}
	if err := ensureNewColumns(newColumns, newColumnBackfills); err != nil {
		return err
	}
	if err := migrateUsersIsEnabledNotNull(); err != nil {
		return fmt.Errorf("failed to migrate users.is_enabled: %w", err)
	}
	if err := migrateSecurityPoliciesNullable(); err != nil {
		return fmt.Errorf("failed to migrate security_policies nullable columns: %w", err)
	}
	if err := migrateCrawlerSourcesID(); err != nil {
		return fmt.Errorf("failed to migrate security_crawler_sources id: %w", err)
	}
	if err := migrateCrawlerSourcesOutOfThreat(); err != nil {
		return fmt.Errorf("failed to separate crawler sources from threat sources: %w", err)
	}
	if err := migrateNodesDeadColumns(); err != nil {
		return fmt.Errorf("failed to migrate nodes legacy columns: %w", err)
	}
	// 历史问题-5（历史）：idx_nodes_status 死索引回收——零查询消费；DDL 与
	// 两处 nodes 表重建迁移已停止创建，存量库由此处一次性删除。
	if _, err := DB.Exec("DROP INDEX IF EXISTS idx_nodes_status"); err != nil {
		return fmt.Errorf("failed to drop dead nodes status index: %w", err)
	}
	// 历史问题 结构性兜底：上方整表重建迁移若以陈旧 DDL 重建而丢列，这里幂等
	// 补齐收敛——重建迁移自身漏列不再造成列永久丢失（数据按列默认值回填）。
	if err := ensureNewColumns(newColumns, newColumnBackfills); err != nil {
		return err
	}
	if err := migrateAutoBackupNodeTopologySection(); err != nil {
		return fmt.Errorf("failed to migrate auto backup node topology section: %w", err)
	}
	if err := normalizeUpstreamWeightsMigration(); err != nil {
		return fmt.Errorf("failed to normalize upstream weights: %w", err)
	}
	if err := normalizeNtlmTakeoverConsistencyMigration(); err != nil {
		return fmt.Errorf("failed to normalize ntlm takeover consistency: %w", err)
	}
	if err := migrateSecurityEventRetentionDefaults(); err != nil {
		return err
	}
	if err := migrateThreatTrafficSampleUnified(); err != nil {
		return err
	}
	// 内置备选拦截页（2026-09-25 裁定）：必须在 ensureNewColumns 之后执行——存量库
	// 的 security_block_pages 无 is_builtin 列，schema 阶段插入会直接失败阻断启动
	// （dev 实证）；限流/维护两页仅作模板手动选用，无自动绑定。
	if _, err := DB.Exec(`INSERT OR IGNORE INTO security_block_pages (id, name, description, content, is_default, is_builtin, created_at, updated_at)
		VALUES (9001, '限流拦截页面', '系统内置 429 限流拦截页面（备选，手动选用后生效）',
			'<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Too Many Requests</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(165deg,#f8fafc 0%,#f1f5f9 45%,#eef2f7 100%);position:relative;overflow:hidden}.blob{position:absolute;border-radius:50%;filter:blur(70px)}.blob-a{width:380px;height:380px;background:rgba(59,130,246,.10);top:-120px;right:-80px}.blob-b{width:320px;height:320px;background:rgba(244,63,94,.08);bottom:-110px;left:-70px}.card{position:relative;background:#fff;border-radius:22px;padding:52px 48px 34px;text-align:center;width:min(560px,calc(100vw - 40px));box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px -8px rgba(16,24,40,.12),0 32px 64px -16px rgba(16,24,40,.10)}.card::before{content:"";position:absolute;top:0;left:24px;right:24px;height:3px;border-radius:0 0 4px 4px;background:linear-gradient(90deg,transparent,#fbbf24 18%,#f59e0b 50%,#fbbf24 82%,transparent)}.badge{position:relative;width:84px;height:84px;margin:0 auto 20px}.badge-ring{position:absolute;inset:0;border-radius:24px;background:linear-gradient(145deg,#fffbeb,#fef3c7);border:1px solid #fde68a;box-shadow:0 4px 12px -2px rgba(16,24,40,.12)}.badge-halo{position:absolute;inset:-12px;border-radius:32px;border:1px dashed #fcd34d}.badge svg{position:absolute;inset:0;margin:auto;width:38px;height:38px}.chip{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;letter-spacing:.6px;color:#b45309;background:#fffbeb;border:1px solid #fde68a;border-radius:999px;padding:5px 14px;margin-bottom:16px}.chip::before{content:"";width:6px;height:6px;border-radius:50%;background:#f59e0b}h1{font-size:28px;font-weight:700;color:#0f172a;letter-spacing:.2px;margin-bottom:14px}p{font-size:14px;color:#64748b;line-height:1.75;margin-bottom:6px}p strong{color:#334155;font-weight:600}.divider{margin:26px auto 0;padding-top:18px;width:75%;border-top:1px solid #f1f5f9;font-size:12px;color:#94a3b8}.divider .name{font-weight:600;color:#475569}</style></head><body><div class="blob blob-a"></div><div class="blob blob-b"></div><div class="card"><div class="badge"><div class="badge-halo"></div><div class="badge-ring"></div><svg viewBox="0 0 24 24" fill="none" stroke="#d97706" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 15a8 8 0 1 1 16 0"/><path d="M12 15l4.5-4.5"/><circle cx="12" cy="15" r="1.4" fill="#d97706" stroke="none"/></svg></div><div class="chip">429 Too Many Requests</div><h1>Too Many Requests</h1><p>You have sent too many requests in a short time.</p><p>Please wait a moment and try again.</p><div class="divider">Powered by <span class="name">Lazy Balancer</span></div></div></body></html>',
			FALSE, TRUE, datetime('now'), datetime('now')),
		(9002, '系统维护页面', '系统内置维护页面（备选，手动选用后生效）',
			'<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Under Maintenance</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(165deg,#f8fafc 0%,#f1f5f9 45%,#eef2f7 100%);position:relative;overflow:hidden}.blob{position:absolute;border-radius:50%;filter:blur(70px)}.blob-a{width:380px;height:380px;background:rgba(59,130,246,.10);top:-120px;right:-80px}.blob-b{width:320px;height:320px;background:rgba(244,63,94,.08);bottom:-110px;left:-70px}.card{position:relative;background:#fff;border-radius:22px;padding:52px 48px 34px;text-align:center;width:min(560px,calc(100vw - 40px));box-shadow:0 1px 2px rgba(16,24,40,.05),0 12px 32px -8px rgba(16,24,40,.12),0 32px 64px -16px rgba(16,24,40,.10)}.card::before{content:"";position:absolute;top:0;left:24px;right:24px;height:3px;border-radius:0 0 4px 4px;background:linear-gradient(90deg,transparent,#60a5fa 18%,#3b82f6 50%,#60a5fa 82%,transparent)}.badge{position:relative;width:84px;height:84px;margin:0 auto 20px}.badge-ring{position:absolute;inset:0;border-radius:24px;background:linear-gradient(145deg,#eff6ff,#dbeafe);border:1px solid #bfdbfe;box-shadow:0 4px 12px -2px rgba(16,24,40,.12)}.badge-halo{position:absolute;inset:-12px;border-radius:32px;border:1px dashed #93c5fd}.badge svg{position:absolute;inset:0;margin:auto;width:38px;height:38px}.chip{display:inline-flex;align-items:center;gap:7px;font-size:12px;font-weight:600;letter-spacing:.6px;color:#1d4ed8;background:#eff6ff;border:1px solid #bfdbfe;border-radius:999px;padding:5px 14px;margin-bottom:16px}.chip::before{content:"";width:6px;height:6px;border-radius:50%;background:#3b82f6}h1{font-size:28px;font-weight:700;color:#0f172a;letter-spacing:.2px;margin-bottom:14px}p{font-size:14px;color:#64748b;line-height:1.75;margin-bottom:6px}p strong{color:#334155;font-weight:600}.divider{margin:26px auto 0;padding-top:18px;width:75%;border-top:1px solid #f1f5f9;font-size:12px;color:#94a3b8}.divider .name{font-weight:600;color:#475569}</style></head><body><div class="blob blob-a"></div><div class="blob blob-b"></div><div class="card"><div class="badge"><div class="badge-halo"></div><div class="badge-ring"></div><svg viewBox="0 0 24 24" fill="none" stroke="#2563eb" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14.7 6.3a4.2 4.2 0 0 0-5.8 5.8L4.6 16.4a1.5 1.5 0 0 0 0 2.1l.9.9a1.5 1.5 0 0 0 2.1 0l4.3-4.3a4.2 4.2 0 0 0 5.8-5.8l-2.6 2.6-2.1-2.1 2.6-2.6z"/></svg></div><div class="chip">System Maintenance</div><h1>Under Maintenance</h1><p>The service is temporarily unavailable while we perform maintenance.</p><p>Please check back soon.</p><div class="divider">Powered by <span class="name">Lazy Balancer</span></div></div></body></html>',
			FALSE, TRUE, datetime('now'), datetime('now'));`); err != nil {
		return fmt.Errorf("failed to seed builtin block pages: %w", err)
	}
	// 历史修复（历史）：置于二次 ensureNewColumns 之后——users 的
	// auth_provider/oidc_subject/oidc_issuer 三列此刻在任意形态库上均已就位。
	if err := migrateOidcIdentityUniqueIndex(); err != nil {
		return fmt.Errorf("failed to migrate oidc identity unique index: %w", err)
	}
	if _, err := DB.Exec("DROP TABLE IF EXISTS tls_certificates"); err != nil {
		return fmt.Errorf("failed to drop tls_certificates: %w", err)
	}
	// 审计 FK OFF 时代 DeleteRule 缺 path_rules 显式删除所积累的孤儿行
	// 一次性清理（幂等，无孤儿零命中）——孤儿随备份导出会使导入侧引用校验 400。
	orphanPathResult, err := DB.Exec("DELETE FROM path_rules WHERE rule_id NOT IN (SELECT caddy_id FROM lb_rules)")
	if err != nil {
		return fmt.Errorf("failed to clean orphaned path_rules: %w", err)
	}
	if n, _ := orphanPathResult.RowsAffected(); n > 0 {
		// 历史问题（历史）：删除用户数据须留痕（与孤儿 upstream 审计同口径）。
		detail := fmt.Sprintf("启动迁移：已清理 %d 条孤儿 path_rules 行（rule_id 无对应规则）", n)
		log.Print(detail)
		recordSystemAudit("启动迁移", "负载规则", detail)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_api_keys_prefix_hash ON api_keys(key_prefix,key_hash)"); err != nil {
		return fmt.Errorf("failed to index API key authentication: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_path_rules_rule_order ON path_rules(rule_id, sort_order, id)"); err != nil {
		return fmt.Errorf("failed to index path_rules: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_security_bindings_policy ON security_policy_bindings(policy_id)"); err != nil {
		return fmt.Errorf("failed to index security_policy_bindings: %w", err)
	}

	// Drop legacy cert_job_logs table — logs now stored in files under /app/logs/
	if _, err := DB.Exec("DROP TABLE IF EXISTS cert_job_logs"); err != nil {
		return fmt.Errorf("failed to drop cert_job_logs: %w", err)
	}

	// Normalize legacy/global default values that are invalid regardless of version
	// 历史问题: 移除原第 3 条「追加 UA rename 行」的 UPDATE——该行每次启动都被下方
	// 清理循环无条件剔除（死代码），且引发每启动一次无谓写放大。
	defaultUpdates := []string{
		"UPDATE global_config SET jwt_expire_minutes=20 WHERE jwt_expire_minutes IS NULL OR jwt_expire_minutes<=0 OR jwt_expire_minutes>1440",
		"UPDATE global_config SET access_log_format='' WHERE access_log_format LIKE '{%'",
		// 空串/空白 timezone 归一（带外直写或旧备份恢复的脏行在下次启动收敛；
		// 写侧已拒绝空串，读侧 COALESCE 只兜 NULL 不兜空串）。
		fmt.Sprintf("UPDATE global_config SET timezone='%s' WHERE COALESCE(TRIM(timezone),'')=''", DefaultTimezone),
		// 历史问题 三次（用户反馈）：上游长连接空闲超时旧默认 60s 主动关闭空闲连接
		//（SSE/WebSocket/LLM 流场景 churn）——NULL 行归 0（继承 Caddy/Go
		// Transport 默认 2 分钟）。审计 历史问题：不得命中显式 60——60 是写侧
		// 校验的合法值，原 COALESCE 口径会在每次启动把用户显式设置的 60
		// 静默抹为 0（循环复现）。
		"UPDATE global_config SET upstream_keepalive_timeout=0 WHERE upstream_keepalive_timeout IS NULL",
		// 库值唯一真相（批 1+2，2026-10-14 用户裁定）：类型①值型列每启动幂等
		// 回填——NULL/<=0 归默认（fresh DDL NOT NULL+DEFAULT、newColumns 补列、
		// 写侧 400、导入/快照/传输归一门之外的最后防线：带外直写/旧备份恢复的
		// 脏行在下次启动收敛）。用户已设有效值（>0）恒不触碰。渲染层对这批列
		// 直读零兜底，无效值在此之后只能显性报错。
		fmt.Sprintf("UPDATE global_config SET request_body_max_size_mb=%d WHERE request_body_max_size_mb IS NULL OR request_body_max_size_mb<=0", DefaultRequestBodyMaxSizeMB),
		fmt.Sprintf("UPDATE global_config SET http_read_timeout=%d WHERE http_read_timeout IS NULL OR http_read_timeout<=0", DefaultHTTPReadTimeout),
		fmt.Sprintf("UPDATE global_config SET http_write_timeout=%d WHERE http_write_timeout IS NULL OR http_write_timeout<=0", DefaultHTTPWriteTimeout),
		fmt.Sprintf("UPDATE global_config SET http_idle_timeout=%d WHERE http_idle_timeout IS NULL OR http_idle_timeout<=0", DefaultHTTPIdleTimeout),
		fmt.Sprintf("UPDATE global_config SET caddy_log_size_mb=%d WHERE caddy_log_size_mb IS NULL OR caddy_log_size_mb<=0", DefaultCaddyLogSizeMB),
		fmt.Sprintf("UPDATE lb_rules SET health_check_interval=%d WHERE health_check_interval IS NULL OR health_check_interval<=0", DefaultHealthCheckInterval),
		fmt.Sprintf("UPDATE lb_rules SET health_check_timeout=%d WHERE health_check_timeout IS NULL OR health_check_timeout<=0", DefaultHealthCheckTimeout),
		fmt.Sprintf("UPDATE lb_rules SET health_check_unhealthy_threshold=%d WHERE health_check_unhealthy_threshold IS NULL OR health_check_unhealthy_threshold<=0", DefaultHealthCheckUnhealthyThreshold),
		fmt.Sprintf("UPDATE lb_rules SET health_check_healthy_threshold=%d WHERE health_check_healthy_threshold IS NULL OR health_check_healthy_threshold<=0", DefaultHealthCheckHealthyThreshold),
		fmt.Sprintf("UPDATE lb_rules SET tcp_try_interval=%d WHERE tcp_try_interval IS NULL OR tcp_try_interval<=0", DefaultTCPTryInterval),
		// 库值唯一真相（批 3）：cert_expiry_days 类型①值型列（写侧 1-365 校验
		// 历史修复 + 导入钳制 历史问题 之外的最后防线）：NULL/<=0 归 30；用户已设
		// 有效值（>0）恒不触碰。消费侧 GetCertExpiryThreshold 直读零兜底。
		fmt.Sprintf("UPDATE global_config SET cert_expiry_days=%d WHERE cert_expiry_days IS NULL OR cert_expiry_days<=0", DefaultCertExpiryDays),
		// 历史问题（历史）：cert_renewal_days/cert_renewal_attempts 纳入同一
		// 启动回填（此前只有 DDL DEFAULT，带外直写 NULL 后读侧字面量 COALESCE
		// 静默吞掉，无任何留痕）。读侧 GetCertRenewalDays/Attempts 直读零兜底。
		fmt.Sprintf("UPDATE global_config SET cert_renewal_days=%d WHERE cert_renewal_days IS NULL OR cert_renewal_days<=0", DefaultCertRenewalDays),
		fmt.Sprintf("UPDATE global_config SET cert_renewal_attempts=%d WHERE cert_renewal_attempts IS NULL OR cert_renewal_attempts<=0", DefaultCertRenewalAttempts),
		// 历史修复（历史）：自动封禁六列每启动幂等回填（同上铁律的最后防线
		// 形态）——带外直写/畸形备份导入的脏行（0-1 外布尔、枚举外文本、写侧
		// 边界外数值）在下次启动收敛到治理默认；运行期窗口内的无效值由消费侧
		// 护栏（RunAutobanCycle 执行前校验，拒绝执行+显性报错）承担，不静默兜底。
		// 边界与枚举单源=services.ValidateAutobanConfig/ValidAutobanDuration/
		// ValidAutobanScope（db 包不可反向依赖，SQL 字面量与迁移 DDL DEFAULT
		// 同款双锚，db_autoban_migration_test/db_autoban_backfill_test 钉测对齐）。
		"UPDATE global_config SET autoban_enabled=0 WHERE autoban_enabled IS NULL OR autoban_enabled NOT IN (0,1)",
		"UPDATE global_config SET autoban_threshold=100 WHERE autoban_threshold IS NULL OR autoban_threshold<1 OR autoban_threshold>10000",
		"UPDATE global_config SET autoban_window_minutes=5 WHERE autoban_window_minutes IS NULL OR autoban_window_minutes<1 OR autoban_window_minutes>60",
		"UPDATE global_config SET autoban_duration='1h' WHERE autoban_duration IS NULL OR autoban_duration NOT IN ('10m','30m','1h','6h','12h','24h','permanent')",
		"UPDATE global_config SET autoban_scope='all' WHERE autoban_scope IS NULL OR autoban_scope NOT IN ('blocked','logged','all')",
		"UPDATE global_config SET autoban_dry_run=1 WHERE autoban_dry_run IS NULL OR autoban_dry_run NOT IN (0,1)",
	}
	for _, statement := range defaultUpdates {
		if _, err := DB.Exec(statement); err != nil {
			return fmt.Errorf("failed to update global config defaults: %w", err)
		}
	}

	// Headers are kept in access logs so 历史修复 stats work; the filter
	// encoder cannot rename a field under a deleted parent.
	var lf string
	if err := DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&lf); err != nil {
		return fmt.Errorf("failed to read global config access log format: %w", err)
	}
	if lf != "" {
		out := []string{}
		for _, l := range strings.Split(lf, "\n") {
			t := strings.TrimSpace(l)
			if t == "request>headers -> delete" || t == "request>headers>User-Agent -> user_agent" {
				continue
			}
			out = append(out, l)
		}
		// 历史问题: 内容未变化时跳过写回（避免每启动一次无谓 UPDATE）。
		if cleaned := strings.Join(out, "\n"); cleaned != lf {
			if _, err := DB.Exec("UPDATE global_config SET access_log_format=? WHERE id=1", cleaned); err != nil {
				return fmt.Errorf("failed to clean global config access log format: %w", err)
			}
		}
	}

	// Sensitive credential headers are dropped from access logs (Cookie and
	// Authorization are redacted by Caddy itself; API keys are not). 历史问题：
	// 归一为唯一规范行——既有的 X-API-Key rename 行会被移除（渲染层虽强制
	// delete 覆盖，落库值仍应与所见一致）；空格式不写回（「不裁剪原生字段」
	// 的默认形态，渲染层恒注入脱敏行）。
	var lf2 string
	if err := DB.QueryRow("SELECT COALESCE(access_log_format,'') FROM global_config WHERE id=1").Scan(&lf2); err != nil {
		return fmt.Errorf("failed to reread global config access log format: %w", err)
	}
	const apiKeyPath = "request>headers>X-API-Key"
	if lf2 != "" {
		kept := make([]string, 0, 8)
		for _, line := range strings.Split(lf2, "\n") {
			parts := strings.SplitN(strings.TrimSpace(line), "->", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) == apiKeyPath {
				continue
			}
			kept = append(kept, line)
		}
		normalized := strings.Join(append(kept, apiKeyPath+" -> delete"), "\n")
		if normalized != lf2 {
			if _, err := DB.Exec("UPDATE global_config SET access_log_format = ? WHERE id=1", normalized); err != nil {
				return fmt.Errorf("failed to redact API key access log header: %w", err)
			}
		}
	}

	// Migrate existing data: set caddy_id for rows that don't have it.
	// Must run before migrateCanonicalDomains, which keys lb_rules updates
	// by caddy_id and would match zero rows while it is still NULL.
	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''").Scan(&count); err != nil {
		return fmt.Errorf("failed to count lb_rules without caddy_id: %w", err)
	}
	if count > 0 {
		// Generate caddy_id for existing rules. Collect ids before writing: an
		// open SELECT cursor on one pooled connection blocks the UPDATE on
		// another under _txlock=immediate.
		rows, err := DB.Query("SELECT id FROM lb_rules WHERE caddy_id IS NULL OR caddy_id = ''")
		if err != nil {
			return fmt.Errorf("failed to query lb_rules without caddy_id: %w", err)
		}
		var ruleIDs []int
		for rows.Next() {
			var ruleID int
			if err := rows.Scan(&ruleID); err != nil {
				rows.Close()
				return fmt.Errorf("failed to scan lb_rule without caddy_id: %w", err)
			}
			ruleIDs = append(ruleIDs, ruleID)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("failed to iterate lb_rules without caddy_id: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("failed to close lb_rules migration rows: %w", err)
		}
		for _, ruleID := range ruleIDs {
			caddyID := generateCaddyIDForMigration()
			if _, err := DB.Exec("UPDATE lb_rules SET caddy_id = ? WHERE id = ?", caddyID, ruleID); err != nil {
				return fmt.Errorf("failed to set caddy_id for lb_rule %d: %w", ruleID, err)
			}
		}
	}

	if err := migrateCanonicalDomains(); err != nil {
		return fmt.Errorf("failed to normalize stored domains: %w", err)
	}

	// Enforce cert_jobs status CHECK constraint and queued default on existing DBs.
	if err := migrateCertJobsStatusConstraint(); err != nil {
		return fmt.Errorf("failed to migrate cert_jobs status constraint: %w", err)
	}
	// idx_cert_jobs_rule_domain 与 idx_cert_jobs_rule_domain_unique 左前缀重叠
	//（历史清理），删除冗余索引；IF EXISTS 幂等，存量库一次性回收。
	if _, err := DB.Exec("DROP INDEX IF EXISTS idx_cert_jobs_rule_domain"); err != nil {
		return fmt.Errorf("failed to drop redundant cert_jobs rule-domain index: %w", err)
	}
	if _, err := DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain)"); err != nil {
		return fmt.Errorf("failed to create cert_jobs unique index: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_status_ca_available ON cert_jobs(status, ca_available_after)"); err != nil {
		return fmt.Errorf("failed to index cert_jobs CA availability: %w", err)
	}
	// 历史问题（历史）：证书任务列表分页索引从只读 handler 内懒建（首个
	// GET 拿 schema 写锁、并发首请求可能 SQLITE_BUSY）移入迁移期——读路径只查询。
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_created_at_desc ON cert_jobs(created_at DESC)"); err != nil {
		return fmt.Errorf("failed to index cert_jobs created_at: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_status_expires ON cert_jobs(status, expires_at)"); err != nil {
		return fmt.Errorf("failed to index cert_jobs expiration: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_cert_jobs_rule_updated_id_expires ON cert_jobs(rule_id, updated_at DESC, id DESC, expires_at)"); err != nil {
		return fmt.Errorf("failed to index cluster certificate selection: %w", err)
	}

	// Normalize ca_available_after to SQLite canonical UTC datetime format.
	// Older rows may contain Go time.Time strings like
	// "2026-07-02 11:56:03.432055881+00:00" which don't compare correctly
	// against datetime('now'). datetime() of an already-canonical string
	// returns the same value, so this is safe to run repeatedly.
	// datetime() 对无法解析的值返回 NULL：若无条件覆盖，存量垃圾值会被静默清成
	// NULL，丢失「该行数据异常」的信号。仅规范化可解析的值。
	if _, err := normalizeCertJobsCAAvailableAfter(); err != nil {
		return fmt.Errorf("failed to normalize cert_jobs.ca_available_after: %w", err)
	}

	if err := migrateLegacyDNSCredentials(); err != nil {
		return err
	}

	// Drop legacy columns from lb_rules if they still exist (no longer used).
	legacyLbColumns := []string{"tls_auto_cert", "tls_email"}
	for _, col := range legacyLbColumns {
		dropped, err := dropColumnIfExists("lb_rules", col)
		if err != nil {
			return err
		}
		if dropped {
			log.Printf("Dropped legacy column %s from lb_rules", col)
		}
	}

	// Migration: Check if we need to rebuild lb_rules with caddy_id as primary key
	// SQLite doesn't support changing primary key directly, so we need to rebuild the table
	if err := migrateLbRulesPrimaryKey(); err != nil {
		return fmt.Errorf("failed to migrate lb_rules primary key: %w", err)
	}

	// 历史修复（历史）：lb_rules/upstreams 三张高频索引必须在 PK 重建之后创建——
	// 重建会 DROP 两张旧表，随表级联删除的索引若在重建前创建，则本次启动内一直
	// 缺失（端口冲突检查/配置生成/指标采集退化为全表扫描），要到下次启动才被
	// IF NOT EXISTS 自愈。fresh 库路径 PK 已是 caddy_id，此处 IF NOT EXISTS 为幂等
	// no-op（schema 侧已建的同名索引不冲突）。
	// 历史问题：listen_port 用于创建/更新规则的端口冲突检查；
	// enabled 用于 Caddy 配置生成与每 5s 指标采集。
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_upstreams_rule_enabled_id ON upstreams(rule_id,enabled,id)"); err != nil {
		return fmt.Errorf("failed to index upstream rule loading: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_lb_rules_listen_port ON lb_rules(listen_port)"); err != nil {
		return fmt.Errorf("failed to index lb_rules listen_port: %w", err)
	}
	if _, err := DB.Exec("CREATE INDEX IF NOT EXISTS idx_lb_rules_enabled ON lb_rules(enabled)"); err != nil {
		return fmt.Errorf("failed to index lb_rules enabled: %w", err)
	}

	// 历史问题: 须在 lb_rules 重建之后——重建前的遗留表可能没有 enable_tls 列。
	if err := migrateLegacyHTTPSProtocol(); err != nil {
		return fmt.Errorf("failed to migrate legacy https protocol: %w", err)
	}

	// 历史问题-1（历史）：TCP DNS 死配置清理由 deadFields 同族收口；
	// TLS-only 旧形态由 runMigrations 尾部的 migrateTCPRuleDeadFields 覆盖并负责版本 bump。
	if err := migrateTCPRuleStaleDNSServer(); err != nil {
		return fmt.Errorf("failed to migrate tcp rule stale dns server: %w", err)
	}

	// Drop legacy columns from upstreams if they still exist (no longer used).
	// 历史修复（历史）：host_header/domain/proxy_protocol+dns_server 三个
	// 逐字相同的独立循环合并为单一登记清单。
	legacyUpstreamDeadColumns := []string{"host_header", "domain", "proxy_protocol", "dns_server"}
	for _, col := range legacyUpstreamDeadColumns {
		dropped, err := dropColumnIfExists("upstreams", col)
		if err != nil {
			return err
		}
		if dropped {
			log.Printf("Dropped legacy column %s from upstreams", col)
		}
	}

	// 历史: 一次性迁移——存量 upstreams.enabled 为 NULL 的遗留行归一化为 0
	// （NULL 视禁用，与渲染/CRUD/度量侧 IIF 口径一致；幂等，重跑无副作用）。
	if _, err := DB.Exec("UPDATE upstreams SET enabled=0 WHERE enabled IS NULL"); err != nil {
		return fmt.Errorf("failed to normalize NULL upstreams.enabled: %w", err)
	}

	// 历史: 一次性迁移——存量 lb_rules.enabled 为 NULL 的遗留行归一化为 0
	// （NULL 视禁用，与渲染侧 WHERE enabled=1 口径一致；幂等，重跑无副作用）。
	// migrateLbRulesPrimaryKey 的重建拷贝已用 COALESCE(enabled,0) 兜底，顺序无关。
	if _, err := DB.Exec("UPDATE lb_rules SET enabled=0 WHERE enabled IS NULL"); err != nil {
		return fmt.Errorf("failed to normalize NULL lb_rules.enabled: %w", err)
	}

	// 历史修复（历史）：备份恢复通道的 epoch 归一（config_backup.go
	// backupTableNullDefaults）只守住「新恢复」的行——修复前已恢复的存量行仍带
	// NULL 时间戳，集群 dump 侧 snapshotRules/snapshotACME 裸列直扫 time.Time
	// 对 NULL 失败会中断整集群同步。启动幂等回填 epoch（与恢复通道、dump 侧
	// COALESCE 同值）；须在 PK 重建之后（重建拷贝对 created_at 原样保留 NULL）。
	if _, err := DB.Exec("UPDATE lb_rules SET created_at='1970-01-01 00:00:00' WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL lb_rules.created_at: %w", err)
	}
	if _, err := DB.Exec("UPDATE ca_providers SET created_at='1970-01-01 00:00:00' WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL ca_providers.created_at: %w", err)
	}
	if _, err := DB.Exec("UPDATE ca_providers SET updated_at='1970-01-01 00:00:00' WHERE updated_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL ca_providers.updated_at: %w", err)
	}
	if _, err := DB.Exec("UPDATE certificate_configs SET created_at='1970-01-01 00:00:00' WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL certificate_configs.created_at: %w", err)
	}

	// 策略实体单职化（2026-09-20 用户裁定「实体拆分」）：policy_type 列经
	// newColumns 加入后存量行为 ''——按内容推断一次性回填（models.InferPolicyType
	// 单一事实源；幂等：仅 '' 行参与，显式值不被覆盖，重跑无副作用）。
	{
		rows, err := DB.Query(`SELECT id, COALESCE(mode,'off'), COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_list_refs,'[]'),
			COALESCE(ip_blacklist,'[]'), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_whitelist,'[]'), COALESCE(ip_whitelist_refs,'[]'),
			COALESCE(rate_limit_enabled,0), COALESCE(rate_limit_rps,0), COALESCE(custom_rules,'[]'), COALESCE(geoip_mode,'off'), COALESCE(geoip_countries,'[]')
			FROM security_policies WHERE policy_type=''`)
		if err != nil {
			return fmt.Errorf("failed to list untyped security policies: %w", err)
		}
		type typedPolicy struct {
			id    int
			type_ string
		}
		var pending []typedPolicy
		for rows.Next() {
			var id, rlRPS int
			var mode, aclList, aclRefs, blacklist, whitelist, wlRefs, customRules, geoipMode, geoipCountries string
			var aclEnabled, rlEnabled, wlEnabled bool
			if err := rows.Scan(&id, &mode, &aclEnabled, &aclList, &aclRefs, &blacklist, &wlEnabled, &whitelist, &wlRefs, &rlEnabled, &rlRPS, &customRules, &geoipMode, &geoipCountries); err != nil {
				rows.Close()
				return fmt.Errorf("failed to scan untyped security policy: %w", err)
			}
			pending = append(pending, typedPolicy{id, models.InferPolicyType(&models.SecurityPolicy{
				Mode: mode, IPACLEnabled: aclEnabled, IPACLList: aclList, IPACLListRefs: aclRefs,
				IPBlacklist: json.RawMessage(blacklist), IPWhitelistEnabled: wlEnabled, IPWhitelist: json.RawMessage(whitelist), IPWhitelistRefs: wlRefs,
				RateLimitEnabled: rlEnabled, RateLimitRPS: rlRPS, CustomRules: json.RawMessage(customRules),
				GeoIPMode: geoipMode, GeoIPCountries: json.RawMessage(geoipCountries),
			})})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("failed to iterate untyped security policies: %w", err)
		}
		rows.Close()
		for _, tp := range pending {
			if _, err := DB.Exec("UPDATE security_policies SET policy_type=? WHERE id=? AND policy_type=''", tp.type_, tp.id); err != nil {
				return fmt.Errorf("failed to backfill security_policies.policy_type: %w", err)
			}
		}
	}

	// 历史问题（历史）：同一恢复通道对 users/api_keys/path_rules/cert_jobs 的
	// created_at 也做 epoch 归一，历史修复 回填未跟上——修复前已恢复的存量 NULL
	// 行持续毒化裸 time.Time 消费端（users→登录 Scan 失败 500 永久锁死/用户
	// 列表/集群快照、api_keys 列表与快照、path_rules 快照、cert_jobs 列表/
	// 详情/重试）。同块补齐同值 epoch 回填；users_not_null 重建
	// （migrateUsersIsEnabledNotNull，上方先行执行）的 INSERT 拷贝对
	// created_at 原样保留 NULL，此处位于重建之后，顺序安全；幂等。
	if _, err := DB.Exec("UPDATE users SET created_at='1970-01-01 00:00:00' WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL users.created_at: %w", err)
	}
	if _, err := DB.Exec("UPDATE api_keys SET created_at='1970-01-01 00:00:00' WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL api_keys.created_at: %w", err)
	}
	if _, err := DB.Exec("UPDATE path_rules SET created_at='1970-01-01 00:00:00' WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL path_rules.created_at: %w", err)
	}
	if _, err := DB.Exec("UPDATE cert_jobs SET created_at='1970-01-01 00:00:00' WHERE created_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL cert_jobs.created_at: %w", err)
	}

	// 历史问题: 版本表 consecutive_failures 一次性 NULL 回填（读取端
	// crsupdate.go/crsscheduler.go readConsecutiveFailures 对 NULL 优雅回退 0，
	// 此处消灭理论 NULL 使落库形态与备份归一口径一致；幂等）。
	if _, err := DB.Exec("UPDATE security_crs_version SET consecutive_failures=0 WHERE consecutive_failures IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL security_crs_version.consecutive_failures: %w", err)
	}
	if _, err := DB.Exec("UPDATE security_ip2region_version SET consecutive_failures=0 WHERE consecutive_failures IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill NULL security_ip2region_version.consecutive_failures: %w", err)
	}

	// 历史问题: global_config.is_master NULL 回填——NULL 时 readonly 判定与
	// cluster_version 触发器均走 COALESCE(is_master,1)（视为主库）；归一为 1
	// 与两者一致（fresh 行的 schema 默认即 TRUE；幂等）。is_master 无 ADD COLUMN 迁移，遗留库可能
	// 整列缺失，此时跳过（列缺失是既有形态，不属于本次回填范围）。
	var isMasterColumn int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('global_config') WHERE name='is_master'").Scan(&isMasterColumn); err != nil {
		return fmt.Errorf("failed to check global_config.is_master: %w", err)
	}
	if isMasterColumn > 0 {
		if _, err := DB.Exec("UPDATE global_config SET is_master=1 WHERE id=1 AND is_master IS NULL"); err != nil {
			return fmt.Errorf("failed to backfill NULL global_config.is_master: %w", err)
		}
	}

	// Drop legacy global_config.sync_caddy_config if it still exists. 旧开关仅覆盖
	// Caddy 全局配置，已被系统数据节(三分类合并,恒同步)取代，且不再被快照构建或同步开关读取，
	// 切换它只会触发无意义的全量重拉。
	legacyGlobalConfigDeadColumns := []string{"sync_caddy_config"}
	for _, col := range legacyGlobalConfigDeadColumns {
		dropped, err := dropColumnIfExists("global_config", col)
		if err != nil {
			return err
		}
		if dropped {
			log.Printf("Dropped legacy column %s from global_config", col)
		}
	}

	// Drop dead columns that are no longer read or written anywhere:
	// - security_block_pages.status_code / security_custom_rules.status_code
	//   已由 security_policies.block_status_code 统一承载拦截状态码，页面与自定义
	//   规则的状态码列不再写入也不被读取（Caddy 配置渲染统一走策略的 block_status_code）。
	// - global_config.admin_tls_acme_rule_id / admin_tls_port：历史遗留死列——
	//   写点与读点均已移除（历史核实全仓零写零读），存量库启动时删除。
	// - lb_rules.ip_acl_mode / ip_acl_list 为规则级 IP 访问控制的遗留列，规则级 IP ACL 早已
	//   迁入 security_policies（策略级 ip_acl_* 仍在使用），这两列不再被读取或写入。
	deadColumnDrops := []struct{ table, column string }{
		{"task_runs", "stage"},              // 历史修复（历史）：零写入方死列
		{"task_runs", "entry_count"},        // 历史修复（历史）：零写入方死列
		{"global_config", "caddy_log_path"}, // 读取但从未使用，日志文件名由渲染层硬编码
		{"security_block_pages", "status_code"},
		{"security_custom_rules", "status_code"},
		{"global_config", "admin_tls_acme_rule_id"},
		{"global_config", "admin_tls_port"},
		{"lb_rules", "ip_acl_mode"},
		{"lb_rules", "ip_acl_list"},
	}
	for _, drop := range deadColumnDrops {
		dropped, err := dropColumnIfExists(drop.table, drop.column)
		if err != nil {
			return err
		}
		if dropped {
			log.Printf("Dropped dead column %s from %s", drop.column, drop.table)
		}
	}

	// 一次性迁移：清理 历史修复 校验落地之前写入的存量自定义规则（尾部反斜杠/空条件），
	// 避免它们在每次配置重生成时产出畸形 SecRule 行而被 coraza 整体拒绝。
	if err := sanitizeLegacyCustomRulePatterns(); err != nil {
		return fmt.Errorf("failed to sanitize legacy custom rule patterns: %w", err)
	}

	// Seed default CA providers once per database (历史问题，历史)。
	// 此前「表空即播种」每次启动评估：导入/集群快照把 ca_providers 清空后重
	// 启会复活 ZeroSSL+LE 并覆盖 default_ca_provider_id，与「删除即不存在」的
	// 用户预期相悖。marker=1 后表空保持空（cert 签发会显式失败，用户可经导入
	// 恢复；UI 无新增入口，这是删除路径的唯一来源）。marker 为节点本地语义：
	// 不进入集群快照（snapshotACME 显式列）与配置备份（显式设置键清单）。
	var caSeeded int
	if err := DB.QueryRow(`SELECT COALESCE(ca_providers_seeded,0) FROM global_config WHERE id=1`).Scan(&caSeeded); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("failed to read CA provider seed marker: %w", err)
	}
	if caSeeded == 0 {
		var caCount int
		if err := DB.QueryRow("SELECT COUNT(*) FROM ca_providers").Scan(&caCount); err != nil {
			return fmt.Errorf("failed to count CA providers: %w", err)
		}
		if caCount == 0 {
			if _, err := DB.Exec(`
				INSERT INTO ca_providers (name, provider, directory_url, credentials, max_concurrent, min_interval_ms, enabled)
				VALUES
					('ZeroSSL', 'zerossl', 'https://acme.zerossl.com/v2/DV90', '{}', 1, 10000, 1),
					('Let''s Encrypt', 'letsencrypt', 'https://acme-v02.api.letsencrypt.org/directory', '{}', 2, 5000, 1)
			`); err != nil {
				return fmt.Errorf("failed to seed CA providers: %w", err)
			}
			// LastInsertId returns the last row of the multi-row insert (Let's Encrypt),
			// so look up Let's Encrypt's actual ID directly and set it as the default.
			var leid int64
			if err := DB.QueryRow("SELECT id FROM ca_providers WHERE provider = 'letsencrypt' ORDER BY id LIMIT 1").Scan(&leid); err != nil {
				return fmt.Errorf("failed to find seeded Let's Encrypt provider: %w", err)
			}
			res, err := DB.Exec("UPDATE global_config SET default_ca_provider_id = ? WHERE id = 1", leid)
			if err != nil {
				return fmt.Errorf("failed to set default CA provider: %w", err)
			}
			rowsAffected, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("failed to read default CA provider update result: %w", err)
			}
			if rowsAffected == 0 {
				return fmt.Errorf("failed to set default CA provider: global config singleton not found")
			}
			log.Print("已播种默认 CA 提供商（ZeroSSL / Let's Encrypt）")
		}
		if _, err := DB.Exec(`UPDATE global_config SET ca_providers_seeded=1 WHERE id=1`); err != nil {
			return fmt.Errorf("failed to record CA provider seed marker: %w", err)
		}
	}

	// Backfill any existing CA providers that were seeded before updated_at had a default.
	if _, err := DB.Exec("UPDATE ca_providers SET updated_at = CURRENT_TIMESTAMP WHERE updated_at IS NULL"); err != nil {
		return fmt.Errorf("failed to backfill CA provider timestamps: %w", err)
	}

	if err := migrateSecurityPolicyCustomOnlyMode(); err != nil {
		return err
	}
	if err := migrateDropDeadMFALockColumns(); err != nil {
		return err
	}
	if err := migrateDropMergedSyncSwitchColumns(); err != nil {
		return err
	}

	// 存量内置名单专业化改名（2026-09-24 用户裁定，保 id）——须在种子前执行，
	// 否则按新名查重落空会插入第二组名单行。
	if err := migrateThreatSystemListNames(); err != nil {
		return err
	}
	// system=1 名单的名称唯一性由部分唯一索引兜底（迁移前先去重）。
	// 此前 EnsureSystemIPList 是纯 历史修复，无 schema 约束；当前调用面
	// 虽串行（启动播种/导入提交），未来并行自愈或导入即可插入重复 system 行，
	// 更新任务按 name 定位、策略选择器按名称展示会出现写入歧义。
	if err := migrateSystemIPListUniqueIndex(); err != nil {
		return err
	}
	// 威胁情报库/自动封禁内置只读名单种子（单源：SeedSystemIPLists，
	// 导入提交后由 handlers 以同一函数重播）。name 稳定（更新任务定位键），
	// 条目空，由更新任务独占写；system=1 行面板/API 拒改拒删。
	// 历史问题-1：存在性判定按 name+system=1——同名用户列表（旧备份
	// 可携带 system=0 行）不阻止内置行创建，也不被合并/删除，仅留痕。
	if err := SeedSystemIPLists(DB); err != nil {
		return err
	}
	// 预置行描述文案归一由 SeedSystemIPLists（EnsureSystemIPList 的已存在行
	// 分支）统一承担（历史问题：种子即文案真相，幂等 UPDATE）——此处不再保留
	// 针对单一文案的一次性补丁。

	// 规则三面同构迁移（2026-10-11 用户裁定「如果没有就都应该没有/时间戳格式
	// 统一」）：TCP 死值清零（bump cluster_version 触发从端下轮收敛）+ 时间戳
	// 格式归一（RFC3339/+00:00/平面 三态并存 → SQLite 平面 UTC）。
	if err := migrateTCPRuleDeadFields(); err != nil {
		return err
	}
	// 历史问题：旧版本 HTTP→TCP 切换前遗留的惰性策略绑定。
	if err := migrateTCPRuleSecurityPolicyBindings(); err != nil {
		return err
	}
	if err := normalizeRuleTimestampsMigration(); err != nil {
		return err
	}
	return nil
}

// migrateDropDeadMFAColumns(2026-09-10 审计 历史修复):users.mfa_failed_attempts/
// mfa_locked_until 是 历史修复 残留死列——现行锁定走 login_failed_attempts/
// login_locked_until(auth.go),该二列零消费(仅残留清零写与快照搬运)。删除
// 列+全部搬运/清零写点;集群同步不做向下兼容(2026-09-09 裁定),新旧快照
// 字段集不一致由同版本升级前提保证。幂等:列存在才 DROP。
func migrateDropDeadMFALockColumns() error {
	for _, col := range []string{"mfa_failed_attempts", "mfa_locked_until"} {
		dropped, err := dropColumnIfExists("users", col)
		if err != nil {
			return err
		}
		if !dropped {
			continue
		}
		log.Printf("已删除 users.%s(M7 残留死列,现行锁定走 login_* 列)", col)
	}
	return nil
}

// migrateDropMergedSyncSwitchColumns(2026-09-19 三分类合并,用户裁定):
// sync_global_config(全局配置并入系统数据节,恒同步)与 sync_waf_files
// (规则库并入安全防护开关)两列随开关删除——readSyncSwitches/UpdateSettings/
// 快照触发器 OF 列表均已不再引用。同步删除 cluster_applied_sections 的
// global_config 陈旧行清除;waf_files 记账行数据(哈希域=纯 ref 含版本
// 标签)搬入 global_config 专用列后一并删除——表严格 3 行与 syncSections
// 同构(方案A,2026-09-19 裁定)。幂等:列存在才 DROP;搬运仅目标列空时
// 执行,重启不回灌;行删除恒幂等。
func migrateDropMergedSyncSwitchColumns() error {
	for _, col := range []string{"sync_global_config", "sync_waf_files"} {
		dropped, err := dropColumnIfExists("global_config", col)
		if err != nil {
			return err
		}
		if !dropped {
			continue
		}
		log.Printf("已删除 global_config.%s(三分类合并:开关随分类并入收敛)", col)
	}
	// 表由集群 schema 建表步骤创建,迁移可能先于其执行(全新库)——表不
	// 存在时跳过清理与搬运。
	var tableCount int
	if err := DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='cluster_applied_sections'").Scan(&tableCount); err != nil {
		return err
	}
	if tableCount > 0 {
		if _, err := DB.Exec(`UPDATE global_config SET
			applied_waf_ref_hash=COALESCE((SELECT hash FROM cluster_applied_sections WHERE section='waf_files'),''),
			applied_waf_ref_version=COALESCE((SELECT applied_version FROM cluster_applied_sections WHERE section='waf_files'),0)
			WHERE id=1 AND COALESCE(applied_waf_ref_hash,'')=''`); err != nil {
			return fmt.Errorf("failed to move waf bookkeeping into global_config columns: %w", err)
		}
		if _, err := DB.Exec(`DELETE FROM cluster_applied_sections WHERE section IN ('global_config','waf_files')`); err != nil {
			return fmt.Errorf("failed to clear legacy applied sections: %w", err)
		}
	}
	return nil
}

// migrateSecurityPolicyCustomOnlyMode(2026-09-09 裁定):WAF 模式四态化后
// off 收敛为「CRS 与自定义规则均不生效」。存量 mode=off 且挂启用中自定义规则
// 的策略自动迁移 custom_only,保持原有防护行为零突变。两种存储形状都识别:
// 早期内嵌对象(元素含 $.enabled)与 v2.1.0 起的规则 ID 数组(元素为整数,
// 需连 security_custom_rules 查 enabled)。一次性门(global_config 旗标列,
// 同 sync_switches_migrated 先例):迁移后用户主动保存的 off+自定义规则
// 属新语义合法状态,不得在下次重启被再次改写。json_each/json_extract 为
// modernc sqlite 内建 JSON1。
// SecurityPolicyCustomOnlyModeNormalizationSQL 是旧世界 off+启用自定义规则
// 归一为 custom_only 的唯一 SQL 事实源：启动一次性迁移与配置导入共用，
// 测试直接引用本常量（不得文本复刻）。json_type 双门保证顶层字符串/畸形
// JSON 不触发 json_each 报错。
const SecurityPolicyCustomOnlyModeNormalizationSQL = `UPDATE security_policies SET mode='custom_only'
WHERE mode='off' AND json_valid(COALESCE(custom_rules,'[]')) AND json_type(COALESCE(custom_rules,'[]')) IN ('array','object') AND EXISTS (
  SELECT 1 FROM json_each(COALESCE(custom_rules,'[]')) je
  WHERE json_extract(je.value,'$.enabled')=1
     OR (json_type(je.value)='integer' AND EXISTS (
          SELECT 1 FROM security_custom_rules r
          WHERE r.id=je.value AND COALESCE(r.enabled,1)=1)))`

func migrateSecurityPolicyCustomOnlyMode() error {
	// 直调兼容：marker 列的 canonical 登记点是 newColumns（见 migrateSyncSwitches 同款说明）。
	if err := ensureNewColumns(map[string]string{"global_config.waf_mode4_migrated": "BOOLEAN DEFAULT 0"}, nil); err != nil {
		return err
	}
	var done bool
	if err := DB.QueryRow("SELECT COALESCE(waf_mode4_migrated,0) FROM global_config WHERE id=1").Scan(&done); err != nil && err != sql.ErrNoRows {
		return err
	}
	if done {
		return nil
	}
	res, err := DB.Exec(SecurityPolicyCustomOnlyModeNormalizationSQL)
	if err != nil {
		return fmt.Errorf("failed to migrate off-mode policies with custom rules: %w", err)
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		log.Printf("WAF 模式四态化迁移：%d 个 mode=off 且挂启用自定义规则的策略已迁移为 custom_only（行为不变）", n)
	}
	_, err = DB.Exec("UPDATE global_config SET waf_mode4_migrated=1 WHERE id=1")
	return err
}

// normalizeCertJobsCAAvailableAfter 将 cert_jobs.ca_available_after 规范化为
// SQLite 规范 UTC 格式（详见 runMigrations 调用点注释）。返回执行结果供
// 调用方/测试断言受影响行数。WHERE 追加 ca_available_after != datetime(...)
// 排除已规范化的行：SQLite 对值未变的 UPDATE 也写页（页脏 + WAL 增长），
// 该守卫让迁移成为真正的一次性回填。
func normalizeCertJobsCAAvailableAfter() (sql.Result, error) {
	return DB.Exec(`UPDATE cert_jobs SET ca_available_after = datetime(ca_available_after)
		WHERE ca_available_after IS NOT NULL
		AND datetime(ca_available_after) IS NOT NULL
		AND ca_available_after != datetime(ca_available_after)`)
}

// legacyHTTPSHasCertPredicate 是 migrateLegacyHTTPSProtocol 的「有证」判定
// （SELECT 预判与 UPDATE 归一必须同谓词，否则审计详情与实际分支发散）。
const legacyHTTPSHasCertPredicate = `(
	(COALESCE(tls_cert,'') != '' AND COALESCE(tls_key,'') != '')
	OR (tls_source = 'acme_dns' AND EXISTS (
		SELECT 1 FROM cert_jobs
		WHERE cert_jobs.rule_id = lb_rules.caddy_id
		  AND COALESCE(cert_jobs.cert_pem,'') != ''
		  AND COALESCE(cert_jobs.key_pem,'') != ''
		  AND cert_jobs.status != 'disabled'
	))
)`

// migrateLegacyHTTPSProtocol 一次性迁移：a1ecbe3a 期写入路径曾接受 protocol='https'
// （语义即 http+TLS），b6e2b624 起写侧白名单收敛为 http/tcp，存量 https 行编辑/复制
// 全部 400、启用后按「非 http 即 TCP」渲染（域名匹配静默丢失）。归一规则（历史问题）：
//   - 有证行 → protocol='http' + enable_tls=1，保持原意图（含 enable_tls 已为 0 的
//     行——https 协议本身隐含 TLS）；
//   - 无证行 → protocol='http' + enable_tls=0 且清 tls_http_redirect：渲染为普通
//     HTTP，保持可编辑，避免 TLS 端口明文与指向非 TLS 端口的幻影跳转（历史修复 形态的
//     迁移再制造）。
//
// 「有证」判定（历史问题）：内联 tls_cert/tls_key 均非空，或 tls_source='acme_dns'
// 且 cert_jobs 中存有该规则已签发的证书（cert_pem/key_pem 非空、任务未禁用）——
// 签发门控（caqueue）不筛 protocol，历史 https 行可能经 ACME 签出证书，仅查内联
// 列会把此类行当无证处理，导致已签发证书静默不再加载且永不续期。
//
// 幂等，重跑零命中。受影响规则记入操作日志（历史问题：迁移跑在审计库初始化之前，
// 先缓冲、InitializeAuditDB 就绪后落库）。
func migrateLegacyHTTPSProtocol() error {
	// 先探测（只读、零行物化）：无 protocol='https' 行时直接返回——此前每次
	// 启动都物化全部命中行（含 caddy_id/name/证书判定），已迁移库白付扫描。
	var stale int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE protocol='https'`).Scan(&stale); err != nil {
		return fmt.Errorf("failed to inspect legacy https lb_rules: %w", err)
	}
	if stale == 0 {
		return nil
	}
	rows, err := DB.Query(`SELECT caddy_id, name,
		CASE WHEN ` + legacyHTTPSHasCertPredicate + ` THEN 1 ELSE 0 END
		FROM lb_rules WHERE protocol='https'`)
	if err != nil {
		return fmt.Errorf("failed to query legacy https lb_rules: %w", err)
	}
	type legacyHTTPSRule struct {
		caddyID string
		name    string
		hasCert bool
	}
	var legacy []legacyHTTPSRule
	for rows.Next() {
		var rule legacyHTTPSRule
		if err := rows.Scan(&rule.caddyID, &rule.name, &rule.hasCert); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan legacy https lb_rules: %w", err)
		}
		legacy = append(legacy, rule)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate legacy https lb_rules: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close legacy https lb_rules rows: %w", err)
	}
	if len(legacy) == 0 {
		return nil
	}
	startupMigrationWriteTx.Add(1)
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin legacy https lb_rules migration: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`UPDATE lb_rules SET protocol='http', enable_tls=1
		WHERE protocol='https' AND ` + legacyHTTPSHasCertPredicate); err != nil {
		return fmt.Errorf("failed to normalize cert-bearing legacy https lb_rules: %w", err)
	}
	if _, err := tx.Exec(`UPDATE lb_rules SET protocol='http', enable_tls=0, tls_http_redirect=0
		WHERE protocol='https'`); err != nil {
		return fmt.Errorf("failed to normalize certless legacy https lb_rules: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit legacy https lb_rules migration: %w", err)
	}
	// 系统审计走内存缓冲而非 SQL 事务：只在数据库提交成功后入缓冲；
	// 任一 UPDATE 失败会整体回滚且不留半迁移审计。
	for _, rule := range legacy {
		var detail string
		if rule.hasCert {
			detail = fmt.Sprintf("存量 https 协议规则已迁移为 http+TLS：caddy_id=%s name=%s", rule.caddyID, rule.name)
		} else {
			detail = fmt.Sprintf("存量 https 协议规则已迁移为普通 HTTP（无可用证书，未启用 TLS）：caddy_id=%s name=%s", rule.caddyID, rule.name)
		}
		log.Print(detail)
		recordSystemAudit("启动迁移", "系统配置", detail)
	}
	return nil
}

// migrateTCPRuleStaleDNSServer 一次性迁移（历史问题-1，历史）：存量
// protocol='tcp' 行可携带 enable_dns_server=1 / dns_server 非空——两字段是
// HTTP 侧 DNS 服务发现语义，TCP 渲染路径（caddy.go L4 分支）永不消费且无
// 告警，落库即死配置并随快照/导出/复制放大（保存侧已补 400 拒绝，本迁移清理
// 存量）。归一为 enable_dns_server=0 + dns_server=”（与 UpdateRule 切换到
// TCP 的零值化分支同语义）；HTTP 行同名字段是合法配置不受影响。幂等，重跑
// 零命中。
func migrateTCPRuleStaleDNSServer() error {
	rows, err := DB.Query(`SELECT caddy_id, name FROM lb_rules
		WHERE protocol='tcp' AND (IIF(enable_dns_server IN ('1',1),1,0)=1 OR TRIM(COALESCE(dns_server,''))<>'')`)
	if err != nil {
		return fmt.Errorf("failed to query tcp rules with stale dns server: %w", err)
	}
	type staleDNSRule struct {
		caddyID string
		name    string
	}
	var stale []staleDNSRule
	for rows.Next() {
		var rule staleDNSRule
		if err := rows.Scan(&rule.caddyID, &rule.name); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan tcp rules with stale dns server: %w", err)
		}
		stale = append(stale, rule)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate tcp rules with stale dns server: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close tcp rules with stale dns server: %w", err)
	}
	if len(stale) == 0 {
		return nil
	}
	// 历史问题（历史）：清理与 cluster_version bump 同事务——与姊妹
	// 迁移 migrateTCPRuleSecurityPolicyBindings 同口径。此前清字段但不 bump，
	// 从端快照版本门永不失效（主从 canonical 分叉）。
	startupMigrationWriteTx.Add(1)
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin tcp stale dns server cleanup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	res, err := tx.Exec(`UPDATE lb_rules SET enable_dns_server=0, dns_server=''
		WHERE protocol='tcp' AND (IIF(enable_dns_server IN ('1',1),1,0)=1 OR TRIM(COALESCE(dns_server,''))<>'')`)
	if err != nil {
		return fmt.Errorf("failed to normalize tcp rules with stale dns server: %w", err)
	}
	cleared, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read normalized tcp rule count: %w", err)
	}
	if cleared > 0 {
		if _, err := tx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
			return fmt.Errorf("failed to bump cluster_version after tcp stale dns cleanup: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit tcp stale dns server cleanup: %w", err)
	}
	committed = true
	for _, rule := range stale {
		detail := fmt.Sprintf("存量 TCP 规则携带无效 DNS 服务发现配置（渲染永不消费），已清空 enable_dns_server/dns_server：caddy_id=%s name=%s", rule.caddyID, rule.name)
		log.Print(detail)
		recordSystemAudit("启动迁移", "系统配置", detail)
	}
	return nil
}

type canonicalDomainMigrationRow struct {
	table  string
	key    any
	value  string
	column string
}

// sanitizeLegacyCustomRulePatterns 一次性迁移：清理 历史修复 校验落地之前写入的存量自定义
// 规则。尾部反斜杠或空条件的规则在发射时会被跳过（见 services.emitCustomRules 的发射
// 侧防御），这里改为「保留数据、禁用即可」，避免它们在配置重生成时产出畸形 SecRule。
//
//  1. security_custom_rules 表：conditions JSON 为空或任一 pattern 以 `\` 结尾 → enabled=0。
//  2. security_policies.custom_rules 内嵌 JSON：条目 conditions 含尾部反斜杠 pattern 或
//     为占位形状（无条件且无 target/operator）→ 将条目 enabled 置 false（内嵌形状的
//     CustomRule 带 enabled 字段，无需整条删除）。
//
// 幂等：已禁用的行/条目保持禁用，重复执行无副作用；不可解析的 JSON 保持原样不动，
// 绝不 brick 一条策略或一条规则。
//
// 一次性门（指纹 marker）：判据在 JSON 内容里，无法用索引探测——此前每次启动
// 都整表读 security_custom_rules + security_policies 并逐条解析。marker 存
// global_config 列（newColumns 登记），值为迁移定义指纹：条目判定规则变化时
// 改指纹即自动重跑，不会因「已迁移」布尔旗标永久跳过新规则。
var startupLegacySanitizeMigrations atomic.Int64 // 真正执行整表扫描的次数（测试观测）

// startupMigrationWriteTx 启动迁移开启写事务的次数（测试观测二次启动零写事务）。
var startupMigrationWriteTx atomic.Int64

func sanitizeLegacyCustomRulePatterns() error {
	return sanitizeLegacyCustomRulePatternsAt(legacyCustomRuleSanitizeFingerprint)
}

const legacyCustomRuleSanitizeFingerprint = "sanitize-v1"

func sanitizeLegacyCustomRulePatternsAt(fingerprint string) error {
	if legacyCustomRuleSanitizeApplied(fingerprint) {
		return nil
	}
	startupLegacySanitizeMigrations.Add(1)
	hasTrailingBackslash := func(conditions []models.CustomRuleCondition, legacyPattern string) bool {
		for _, cond := range conditions {
			if strings.HasSuffix(cond.Pattern, `\`) {
				return true
			}
		}
		return strings.HasSuffix(legacyPattern, `\`)
	}

	disabled := 0

	// 1. 独立自定义规则表
	rows, err := DB.Query("SELECT id, COALESCE(conditions,'') FROM security_custom_rules")
	if err != nil {
		return fmt.Errorf("failed to query security_custom_rules: %w", err)
	}
	type customRuleRow struct {
		id         int
		conditions string
	}
	var ruleRows []customRuleRow
	for rows.Next() {
		var row customRuleRow
		if err := rows.Scan(&row.id, &row.conditions); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan security_custom_rules: %w", err)
		}
		ruleRows = append(ruleRows, row)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate security_custom_rules: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close security_custom_rules rows: %w", err)
	}
	for _, row := range ruleRows {
		var conditions []models.CustomRuleCondition
		// 不可解析的 conditions 一并禁用：发射阶段同样无法判定其合法性。
		if err := json.Unmarshal([]byte(row.conditions), &conditions); err != nil || len(conditions) == 0 || hasTrailingBackslash(conditions, "") {
			res, err := DB.Exec("UPDATE security_custom_rules SET enabled=0 WHERE id=? AND enabled=1", row.id)
			if err != nil {
				return fmt.Errorf("failed to disable security_custom_rule %d: %w", row.id, err)
			}
			if affected, _ := res.RowsAffected(); affected > 0 {
				disabled++
			}
		}
	}

	// 2. 策略内嵌自定义规则
	policyRows, err := DB.Query("SELECT id, COALESCE(custom_rules,'') FROM security_policies")
	if err != nil {
		return fmt.Errorf("failed to query security_policies: %w", err)
	}
	type policyRow struct {
		id          int
		customRules string
	}
	var policies []policyRow
	for policyRows.Next() {
		var row policyRow
		if err := policyRows.Scan(&row.id, &row.customRules); err != nil {
			policyRows.Close()
			return fmt.Errorf("failed to scan security_policies: %w", err)
		}
		policies = append(policies, row)
	}
	if err := policyRows.Err(); err != nil {
		policyRows.Close()
		return fmt.Errorf("failed to iterate security_policies: %w", err)
	}
	if err := policyRows.Close(); err != nil {
		return fmt.Errorf("failed to close security_policies rows: %w", err)
	}
	for _, policy := range policies {
		var embedded []models.CustomRule
		// 规则 ID 数组或不可解析的 JSON 保持原样（ID 数组对应的独立规则已在上一步处理）。
		if err := json.Unmarshal([]byte(policy.customRules), &embedded); err != nil {
			continue
		}
		changed := false
		for i := range embedded {
			rule := &embedded[i]
			isPlaceholder := len(rule.Conditions) == 0 && rule.Target == "" && rule.Operator == ""
			if !isPlaceholder && !hasTrailingBackslash(rule.Conditions, rule.Pattern) {
				continue
			}
			if rule.Enabled {
				rule.Enabled = false
				changed = true
				disabled++
			}
		}
		if !changed {
			continue
		}
		encoded, err := json.Marshal(embedded)
		if err != nil {
			continue
		}
		if _, err := DB.Exec("UPDATE security_policies SET custom_rules=? WHERE id=?", string(encoded), policy.id); err != nil {
			return fmt.Errorf("failed to update security_policy %d custom_rules: %w", policy.id, err)
		}
	}

	if disabled > 0 {
		// 历史问题（历史）：禁用用户规则属于用户可见数据改写，须留痕
		//（此前只有进程 stdout）。
		detail := fmt.Sprintf("启动迁移：已禁用 %d 条含非法 pattern 的存量自定义规则（尾部反斜杠/空条件/不可解析 conditions）", disabled)
		log.Print(detail)
		recordSystemAudit("启动迁移", "自定义规则", detail)
	}
	// 收敛完成才置 marker：执行中报错返回时不置位，下次启动重试（与 audit
	// 侧归一 marker 同口径）。
	if _, err := DB.Exec(`UPDATE global_config SET legacy_custom_rule_sanitize_fp=? WHERE id=1`, fingerprint); err != nil {
		// marker 写失败不阻断启动：下次启动重跑（幂等，零副作用）。
		log.Printf("启动迁移：自定义规则清理 marker 写入失败（下次启动将重跑）: %v", err)
	}
	return nil
}

// legacyCustomRuleSanitizeApplied 报告 marker 是否已按当前指纹置位。
// 读失败（列缺失/无 global_config 行）按未迁移处理——迁移自身会重试。
func legacyCustomRuleSanitizeApplied(fingerprint string) bool {
	var stored string
	err := DB.QueryRow(`SELECT COALESCE(legacy_custom_rule_sanitize_fp,'') FROM global_config WHERE id=1`).Scan(&stored)
	return err == nil && stored == fingerprint
}

// canonicalDomainMigrationSources 归一扫描的数据源，判定门与迁移本体共用同一份
// 定义，防止两处口径漂移。
var canonicalDomainMigrationSources = []struct {
	table  string
	column string
	query  string
}{
	{table: "lb_rules", column: "domain", query: "SELECT caddy_id, domain FROM lb_rules WHERE domain IS NOT NULL AND trim(domain) != ''"},
	{table: "cert_jobs", column: "domain", query: "SELECT id, domain FROM cert_jobs WHERE trim(domain) != ''"},
	{table: "upstreams", column: "host", query: "SELECT id, host FROM upstreams WHERE trim(host) != ''"},
}

// canonicalDomainMigrationNeeded 以与迁移本体相同的口径判定是否有事可做：任一存量
// 值与规范形不同，或 cert_jobs 仍存在 (rule_id, domain) 重复组。无事可做时调用方
// 整段跳过——否则每次启动都白跑一次 DROP/CREATE 唯一索引（立即写事务）加三次全表
// 扫描（历史修复）。迁移在服务器接受流量前单线程执行，判定与迁移间无并发写入。
func canonicalDomainMigrationNeeded() (bool, error) {
	for _, source := range canonicalDomainMigrationSources {
		rows, err := DB.Query(source.query)
		if err != nil {
			return false, fmt.Errorf("query %s.%s: %w", source.table, source.column, err)
		}
		needed := false
		for rows.Next() {
			var key any
			var value string
			if err := rows.Scan(&key, &value); err != nil {
				rows.Close()
				return false, fmt.Errorf("scan %s.%s: %w", source.table, source.column, err)
			}
			if source.table == "upstreams" && net.ParseIP(strings.TrimSpace(value)) != nil {
				continue
			}
			canonical, err := CanonicalDomains(value)
			if err != nil || canonical == value {
				continue
			}
			needed = true
			break
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return false, fmt.Errorf("iterate %s.%s: %w", source.table, source.column, err)
		}
		if err := rows.Close(); err != nil {
			return false, fmt.Errorf("close %s.%s rows: %w", source.table, source.column, err)
		}
		if needed {
			return true, nil
		}
	}
	var hasDupes bool
	if err := DB.QueryRow("SELECT EXISTS(SELECT 1 FROM cert_jobs GROUP BY rule_id, domain HAVING COUNT(*) > 1)").Scan(&hasDupes); err != nil {
		return false, fmt.Errorf("check cert_jobs duplicate groups: %w", err)
	}
	return hasDupes, nil
}

func migrateCanonicalDomains() error {
	needed, err := canonicalDomainMigrationNeeded()
	if err != nil {
		return err
	}
	if !needed {
		return nil
	}
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("begin domain normalization: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec("DROP INDEX IF EXISTS idx_cert_jobs_rule_domain_unique"); err != nil {
		return fmt.Errorf("drop cert_jobs domain index: %w", err)
	}

	rowsToNormalize := make([]canonicalDomainMigrationRow, 0)
	for _, source := range canonicalDomainMigrationSources {
		rows, err := tx.Query(source.query)
		if err != nil {
			return fmt.Errorf("query %s.%s: %w", source.table, source.column, err)
		}
		for rows.Next() {
			var key any
			var value string
			if err := rows.Scan(&key, &value); err != nil {
				rows.Close()
				return fmt.Errorf("scan %s.%s: %w", source.table, source.column, err)
			}
			rowsToNormalize = append(rowsToNormalize, canonicalDomainMigrationRow{table: source.table, key: key, value: value, column: source.column})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return fmt.Errorf("iterate %s.%s: %w", source.table, source.column, err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close %s.%s rows: %w", source.table, source.column, err)
		}
	}

	renamedDomains := 0
	for _, row := range rowsToNormalize {
		if row.table == "upstreams" && net.ParseIP(strings.TrimSpace(row.value)) != nil {
			continue
		}
		canonical, err := CanonicalDomains(row.value)
		if err != nil {
			log.Printf("Skipping invalid domain during migration: table=%s column=%s row=%v value=%q: %v", row.table, row.column, row.key, row.value, err)
			continue
		}
		if canonical == row.value {
			continue
		}
		keyColumn := "id"
		if row.table == "lb_rules" {
			keyColumn = "caddy_id"
		}
		if _, err := tx.Exec("UPDATE "+row.table+" SET "+row.column+"=? WHERE "+keyColumn+"=?", canonical, row.key); err != nil {
			return fmt.Errorf("update %s.%s row %v: %w", row.table, row.column, row.key, err)
		}
		renamedDomains++
	}
	// 历史问题：去重保留判据改为「优先有证书材料的行，同列再比 id」——原 MAX(id)
	// 在规范域碰撞时（legacy 大小写/IDN 变体行）可能删掉带已签发证书的旧行、
	// 保留其后创建的无证书行，规则丢失现网证书需重签。一次性迁移窗口内生效。
	dedupeResult, err := tx.Exec(`DELETE FROM cert_jobs WHERE id NOT IN (
		SELECT a.id FROM cert_jobs a WHERE a.id = (
			SELECT b.id FROM cert_jobs b
			WHERE b.rule_id = a.rule_id AND b.domain = a.domain
			ORDER BY (CASE WHEN COALESCE(b.cert_pem,'')='' OR COALESCE(b.key_pem,'')='' THEN 0 ELSE 1 END) DESC, b.id DESC
			LIMIT 1))`)
	if err != nil {
		return fmt.Errorf("deduplicate cert_jobs: %w", err)
	}
	dedupedJobs, _ := dedupeResult.RowsAffected()
	if _, err := tx.Exec("CREATE UNIQUE INDEX idx_cert_jobs_rule_domain_unique ON cert_jobs(rule_id, domain)"); err != nil {
		return fmt.Errorf("create cert_jobs domain index: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit domain normalization: %w", err)
	}
	committed = true
	// 历史问题（历史）：域名归一/证书任务去重都是用户可见数据改写，
	// 提交成功后聚合留痕。
	if renamedDomains > 0 {
		detail := fmt.Sprintf("启动迁移：存量域名归一为规范形（lb_rules/cert_jobs/upstreams）：%d 行", renamedDomains)
		log.Print(detail)
		recordSystemAudit("启动迁移", "证书配置", detail)
	}
	if dedupedJobs > 0 {
		detail := fmt.Sprintf("启动迁移：cert_jobs 同规则同域重复行已去重（优先保留带证书材料行）：%d 条", dedupedJobs)
		log.Print(detail)
		recordSystemAudit("启动迁移", "证书任务", detail)
	}
	return nil
}

// migrateThreatTrafficSampleUnified 把大屏采样列收敛到 -1/0 两值契约
// （全量档已退役；自适应从 1/1 起步，低流量等价全量）。
// 一次性迁移：1、固定 2..64 与畸形越界值统一归自适应；{-1,0} 原样保留。
// marker 置 1 后不再触碰运行期写值（写侧门 -1/0 已单点约束）。
func migrateThreatTrafficSampleUnified() error {
	var done int
	if err := DB.QueryRow(`SELECT COALESCE(threat_traffic_sample_unified_migrated,0) FROM global_config WHERE id=1`).Scan(&done); err != nil && err != sql.ErrNoRows {
		return err
	}
	if done != 0 {
		// marker 已置位的旧库仍可能残留全量 1（旧契约允许）；全量已退役，
		// 每次启动做一次幂等收敛（仅命中 1，未命中零写入）。
		var legacyFull int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM global_config WHERE id=1 AND threat_traffic_sample_n=1`).Scan(&legacyFull); err != nil {
			return err
		}
		if legacyFull > 0 {
			if _, err := DB.Exec(`UPDATE global_config SET threat_traffic_sample_n=? WHERE id=1 AND threat_traffic_sample_n=1`, DefaultThreatTrafficSampleN); err != nil {
				return err
			}
			detail := fmt.Sprintf("启动迁移：大屏流量采样全量档已退役，归一为 %d（自适应）", DefaultThreatTrafficSampleN)
			log.Print(detail)
			recordSystemAudit("启动迁移", "系统配置", detail)
		}
		return nil
	}
	// 列 NOT NULL，但历史库存在带外直写 NULL 的可能：NULL 一并归一 -1；
	// 1/2..64/畸形越界值全部归自适应。
	var invalidRows int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM global_config
		WHERE id=1 AND (threat_traffic_sample_n IS NULL OR threat_traffic_sample_n NOT IN (-1,0))`).Scan(&invalidRows); err != nil {
		return err
	}
	if _, err := DB.Exec(`UPDATE global_config
		SET threat_traffic_sample_n = CASE
		        WHEN threat_traffic_sample_n IS NULL OR threat_traffic_sample_n NOT IN (-1,0) THEN ?
		        ELSE threat_traffic_sample_n
		    END,
		    threat_traffic_sample_unified_migrated = 1
		WHERE id = 1`, DefaultThreatTrafficSampleN); err != nil {
		return err
	}
	if invalidRows > 0 {
		// 历史问题：配置值被改写须留痕（与 retention 回填同口径）。
		detail := fmt.Sprintf("启动迁移：大屏流量采样列归一为 %d（自适应，全量/旧固定档废除）：%d 行", DefaultThreatTrafficSampleN, invalidRows)
		log.Print(detail)
		recordSystemAudit("启动迁移", "系统配置", detail)
	}
	return nil
}

// migrateSecurityEventRetentionDefaults 一次性把旧库的 0=自动 语义回填为显式
// 默认值（保留天数 90 天、行数上限 100 万），marker 置 1 后不再触碰运行期写值
// （历史问题-5/历史问题-5：原实现每启动无条件把 0 改写为 90——写侧拒绝 0 后的存量
// 0 只来自旧版本/旧导入，迁移一次即可；运行期显式值不得被重启静默改写）。
func migrateAutoBackupNodeTopologySection() error {
	var version int
	var raw sql.NullString
	if err := DB.QueryRow(`SELECT COALESCE(auto_backup_sections_version,0), auto_backup_sections FROM global_config WHERE id=1`).Scan(&version, &raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		return err
	}
	if version >= 1 {
		return nil
	}
	sections := []string{}
	if raw.Valid && strings.TrimSpace(raw.String) != "" {
		if err := json.Unmarshal([]byte(raw.String), &sections); err != nil {
			// 畸形存量值不在迁移中猜测修复；交由设置读侧 fail-visible。
			_, err = DB.Exec(`UPDATE global_config SET auto_backup_sections_version=1 WHERE id=1`)
			return err
		}
	}
	if len(sections) == 0 {
		sections = []string{"users", "rules", "security", "cluster"}
	} else if slices.Equal(sections, []string{"users", "rules", "security"}) {
		// 旧默认全选（三分类）一次追加节点拓扑；用户此后取消勾选会保存
		// 三键并把 version 置 1，不会在下次启动被重新加回。
		sections = append(sections, "cluster")
	}
	encoded, err := json.Marshal(sections)
	if err != nil {
		return err
	}
	_, err = DB.Exec(`UPDATE global_config SET auto_backup_sections=?, auto_backup_sections_version=1 WHERE id=1`, string(encoded))
	return err
}

func normalizeUpstreamWeightsMigration() error {
	res, err := DB.Exec(`UPDATE upstreams SET weight=1 WHERE weight IS NULL OR weight < 1`)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		// 历史问题（历史）：上游权重被改写须留痕。
		detail := fmt.Sprintf("启动迁移：存量上游权重无效值（NULL/<1）归 1：%d 条", n)
		log.Print(detail)
		recordSystemAudit("启动迁移", "负载规则", detail)
	}
	return nil
}

// normalizeNtlmTakeoverConsistencyMigration：ntlm_compatible
// 是展示/声明列——渲染对其零感知，真实 NTLM 行为由四列接管形态决定
// （tcp_try_duration=-1/upstream_force_http1=1/proxy_flush_interval=-1/
// upstream_keepalive_timeout=300，UI 修改器落下的唯一合法形态）。写侧/导入/
// 启用三族门收紧前，API 直构/旧备份/集群快照可落「ntlm=1 但四列不齐」的
// 不一致行——面板宣称 NTLM、运行行为非 NTLM。启动期归一 ntlm_compatible=0：
// 纯展示修正（该列渲染零消费），四列运行值原样保留、渲染行为零漂移；用户
// 经向导重新开启开关即恢复完整接管形态。幂等：一致行与 ntlm=0 行零命中。
// 集群同步侧不需单独处理——主端归一后经快照收敛从端。
func normalizeNtlmTakeoverConsistencyMigration() error {
	res, err := DB.Exec(`UPDATE lb_rules SET ntlm_compatible=0 WHERE ntlm_compatible=1 AND (
		COALESCE(tcp_try_duration,0)<>-1 OR COALESCE(upstream_force_http1,0)<>1
		OR COALESCE(proxy_flush_interval,0)<>-1 OR COALESCE(upstream_keepalive_timeout,0)<>300)`)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		// 与孤儿 path_rules/上游权重归一同口径：归一用户数据须留痕。
		detail := fmt.Sprintf("启动迁移：已将 %d 条「ntlm_compatible=1 但接管四列不齐」的规则归一为 ntlm_compatible=0（渲染对该列零感知，运行行为不变）", n)
		log.Print(detail)
		recordSystemAudit("启动迁移", "负载规则", detail)
	}
	return nil
}

func migrateSecurityEventRetentionDefaults() error {
	var done int
	if err := DB.QueryRow(`SELECT COALESCE(security_events_retention_migrated,0) FROM global_config WHERE id=1`).Scan(&done); err != nil && err != sql.ErrNoRows {
		return err
	}
	if done != 0 {
		return nil
	}
	var invalidRows int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM global_config WHERE id=1
		AND (COALESCE(security_events_retention_days,0)<=0 OR COALESCE(security_events_row_cap,0)<=0)`).Scan(&invalidRows); err != nil {
		return err
	}
	_, err := DB.Exec(`UPDATE global_config
		SET security_events_retention_days = CASE WHEN COALESCE(security_events_retention_days,0) <= 0 THEN ? ELSE security_events_retention_days END,
		    security_events_row_cap = CASE WHEN COALESCE(security_events_row_cap,0) <= 0 THEN ? ELSE security_events_row_cap END,
		    security_events_retention_migrated = 1
		WHERE id = 1`, DefaultSecurityEventsRetentionDays, DefaultSecurityEventsRowCap)
	if err != nil {
		return err
	}
	if invalidRows > 0 {
		// 历史问题：旧语义 0=自动 被改写为显式默认，须留痕。
		detail := fmt.Sprintf("启动迁移：安全事件保留 0/缺省回填为显式默认（%d 天 / %d 行）", DefaultSecurityEventsRetentionDays, DefaultSecurityEventsRowCap)
		log.Print(detail)
		recordSystemAudit("启动迁移", "系统配置", detail)
	}
	return nil
}

// migrateSystemIPListUniqueIndex 为 security_ip_lists 的 system=1 行建立
// (name) 部分唯一索引。存量重复行先按 MIN(id) 去重——同名
// system=1 行只可能来自历史修复 竞态，保留最早一行（与其它
// 迁移的去重优先级一致）；删除行数留运行日志，便于事后核对引用。
// 同名 system=0 用户列表不受索引约束（部分索引仅覆盖 system=1）。
func migrateSystemIPListUniqueIndex() error {
	var duplicates int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1 AND id NOT IN (SELECT MIN(id) FROM security_ip_lists WHERE system=1 GROUP BY name)`).Scan(&duplicates); err != nil {
		return fmt.Errorf("count duplicate system ip lists: %w", err)
	}
	if duplicates > 0 {
		if _, err := DB.Exec(`DELETE FROM security_ip_lists WHERE system=1 AND id NOT IN (SELECT MIN(id) FROM security_ip_lists WHERE system=1 GROUP BY name)`); err != nil {
			return fmt.Errorf("dedupe system ip lists: %w", err)
		}
		detail := fmt.Sprintf("启动迁移：security_ip_lists 重复的 system=1 名单行已去重（保留每组 MIN(id)）：%d 条", duplicates)
		log.Print(detail)
		// 删除整行属用户可见数据改写（重复行可能携带已入库 IP 条目）：与
		// cert_jobs 去重/域名归一同口径落「全操作审计」，不只留进程 stdout。
		recordSystemAudit("启动迁移", "IP 名单", detail)
	}
	if _, err := DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS u_security_ip_lists_system_name ON security_ip_lists(name) WHERE system=1"); err != nil {
		return fmt.Errorf("create unique system ip list index: %w", err)
	}
	return nil
}

// EnsureSystemIPList 幂等确保一条内置 system=1 名单行存在（name+system=1
// 判定，同名 system=0 用户列表保留并留痕）。返回是否新建。
// 历史问题-1：db 启动播种、autoban 运行期自愈与导入提交后重播共用本函数，
// 禁止再按裸 name 判定（旧实现会因同名用户列表永久跳过内置行）。
func EnsureSystemIPList(database *sql.DB, name, description, category string) (bool, error) {
	if database == nil {
		return false, errors.New("确保系统名单: 数据库未初始化")
	}
	// 唯一索引建立后，并发/重入播种不再依赖 历史修复 的
	// 互斥假设——OR IGNORE 让「另一路径刚插入同名 system=1 行」退化为
	// RowsAffected=0（走已存在分支的描述归一），而不是约束错误。
	result, err := database.Exec(`INSERT OR IGNORE INTO security_ip_lists (name, description, category, entries, system, created_at, updated_at)
		SELECT ?, ?, ?, '[]', 1, datetime('now'), datetime('now')
		WHERE NOT EXISTS (SELECT 1 FROM security_ip_lists WHERE name=? AND system=1)`,
		name, description, category, name)
	if err != nil {
		return false, fmt.Errorf("failed to seed system list %s: %w", name, err)
	}
	n, _ := result.RowsAffected()
	if n > 0 {
		var userOwned int
		if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=0`, name).Scan(&userOwned); err == nil && userOwned > 0 {
			log.Printf("内置名单 %q 与用户自建列表同名：已创建独立 system=1 行（按 id 引用，互不影响）；建议重命名用户列表以消除选择器歧义", name)
		}
		return true, nil
	}
	// 历史问题（历史）：已存在的 system=1 行描述随代码文案收敛（幂等）——
	// 此前只在缺失时 INSERT，任何文案修订都要再写一次性 UPDATE 补丁才生效，
	// 存量库与新库文案长期分叉（2026-10-15「删除条目即解封」即此复发路径）。
	// 预置行描述禁改由 UpdateIPList 400 守卫保证，不存在用户自定义描述形态；
	// 备份/快照恢复带入的旧文案在下一次启动/导入重播时归一。
	if _, err := database.Exec(`UPDATE security_ip_lists SET description=?, updated_at=datetime('now')
		WHERE name=? AND system=1 AND COALESCE(description,'')<>?`, description, name, description); err != nil {
		return false, fmt.Errorf("failed to normalize system list %s description: %w", name, err)
	}
	return false, nil
}

// SeedSystemIPLists 重播全部内置 system 名单（启动播种与导入提交后共用单源）。
func SeedSystemIPLists(database *sql.DB) error {
	for _, sl := range ThreatSystemLists() {
		if _, err := EnsureSystemIPList(database, sl.Name, sl.Description, "恶意 IP"); err != nil {
			return err
		}
	}
	_, err := EnsureSystemIPList(database, "自动封禁名单", "自动封禁命中 IP（自动封禁任务维护；可手动追加或删除条目）", "自动封禁")
	return err
}

// ensureNewColumns 按清单逐列补齐（幂等：列已存在零命中）。历史问题 提取自
// runMigrations 内联循环：三个整表重建迁移之后需再次调用，收敛重建以陈旧 DDL
// 重建时丢失的列（数据按列默认值回填，不再永久丢失）。
func ensureNewColumns(columns, backfills map[string]string) error {
	var colCount int
	for col, dtype := range columns {
		parts := strings.Split(col, ".")
		// 历史修复（历史）：畸形登记 key 启动期响亮失败——此前静默跳过
		//（continue），登记笔误（漏点/多段）会让列静默不补、运行时才以
		// no such column 暴露，与「启动期响亮失败」基调不一致。
		if len(parts) != 2 {
			return fmt.Errorf("malformed newColumns key %q: want table.column", col)
		}
		table, name := parts[0], parts[1]
		if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, name).Scan(&colCount); err != nil {
			return fmt.Errorf("failed to check column %s.%s: %w", table, name, err)
		}
		if colCount != 0 {
			continue
		}
		// 历史问题（历史）：ALTER 与一次性回填必须落同一事务。此前两条
		// 语句各自自动提交——ALTER 成功、回填前崩溃会让「列已存在」成为下次
		// 启动的跳过判据，回填永久丢失（mfa_challenges.password_version 令存量
		// 挑战按 0 校验；upstream_keepalive_timeout 残留旧默认 60）。SQLite DDL
		// 可事务化：失败整体回滚→列不存在→下次启动重试 ALTER+回填。
		if err := addColumnWithBackfill(table, name, dtype, backfills[col]); err != nil {
			return err
		}
	}
	return nil
}

// addColumnWithBackfill 在同一事务内完成 ADD COLUMN 与（可选）一次性回填，
// 保证二者原子（历史问题）。backfill 为空串表示无回填。
func addColumnWithBackfill(table, name, dtype, backfill string) error {
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin column %s.%s migration: %w", table, name, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.Exec("ALTER TABLE " + table + " ADD COLUMN " + name + " " + dtype); err != nil {
		return fmt.Errorf("failed to add column %s.%s: %w", table, name, err)
	}
	if backfill != "" {
		if _, err := tx.Exec(backfill); err != nil {
			return fmt.Errorf("failed to backfill column %s.%s: %w", table, name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit column %s.%s migration: %w", table, name, err)
	}
	committed = true
	return nil
}

// migrateCrawlerSourcesOutOfThreat：早期合并形态把四个爬虫地址库源写进
// security_threat_sources，导致威胁情报库弹框与更新任务混入爬虫。将源行及
// 用户开关/版本/状态/排程迁入独立表，再从威胁表删除；名单与快照文件不动。
func migrateCrawlerSourcesOutOfThreat() error {
	tx, err := DB.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	const columns = `name,display_name,url,format,update_enabled,entry_count,version,update_status,message,last_checked,next_update,"trigger",started_at,finished_at,consecutive_failures,created_at,updated_at`
	for _, name := range []string{"googlebot", "gptbot", "bingbot", "so360spider"} {
		query := `INSERT INTO security_crawler_sources (` + columns + `)
			SELECT ` + columns + ` FROM security_threat_sources WHERE name=?
			ON CONFLICT(name) DO UPDATE SET
				display_name=excluded.display_name, url=excluded.url, format=excluded.format,
				update_enabled=excluded.update_enabled, entry_count=excluded.entry_count,
				version=excluded.version, update_status=excluded.update_status, message=excluded.message,
				last_checked=excluded.last_checked, next_update=excluded.next_update, "trigger"=excluded."trigger",
				started_at=excluded.started_at, finished_at=excluded.finished_at,
				consecutive_failures=excluded.consecutive_failures, updated_at=excluded.updated_at`
		if _, err := tx.Exec(query, name); err != nil {
			return fmt.Errorf("迁移爬虫源 %s: %w", name, err)
		}
	}
	if _, err := tx.Exec(`DELETE FROM security_threat_sources WHERE name IN ('googlebot','gptbot','bingbot','so360spider')`); err != nil {
		return fmt.Errorf("清理威胁表爬虫源: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

// withTableRebuild 是整表重建迁移的统一事务骨架（历史问题，历史）：独立
// 连接（PRAGMA foreign_keys 是会话级设置，必须与事务同连接）→ 读取并关闭 FK →
// 事务内执行 fn → 提交 → 还原 FK。fn 返回错误或提交失败时整体回滚，崩溃不会
// 留下半建表（DROP 与 RENAME 之间失败曾可致表丢失/残留 _new 表阻断重跑）。
// label 只用于日志与错误上下文。
func withTableRebuild(ctx context.Context, label string, fn func(tx *sql.Tx) error) error {
	conn, err := DB.Conn(ctx)
	if err != nil {
		return fmt.Errorf("failed to acquire %s migration connection: %w", label, err)
	}
	defer conn.Close()
	fkPrev, err := readForeignKeysSetting(ctx, conn)
	if err != nil {
		return fmt.Errorf("failed to read foreign_keys setting: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return fmt.Errorf("failed to disable foreign keys: %w", err)
	}
	defer func() {
		if err := restoreForeignKeysSetting(ctx, conn, fkPrev); err != nil {
			log.Printf("failed to restore foreign_keys=%d after %s migration: %v", fkPrev, label, err)
		}
	}()
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin %s migration transaction: %w", label, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := fn(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit %s migration: %w", label, err)
	}
	committed = true
	return nil
}

// dropColumnIfExists 幂等删除表列（历史问题，历史）：列存在才 DROP，返回
// 是否实际删除（调用方按需记日志）。table/column 仅来自代码常量，拼接安全。
func dropColumnIfExists(table, column string) (bool, error) {
	var count int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name=?", table, column).Scan(&count); err != nil {
		return false, fmt.Errorf("failed to check %s.%s: %w", table, column, err)
	}
	if count == 0 {
		return false, nil
	}
	if _, err := DB.Exec("ALTER TABLE " + table + " DROP COLUMN " + column); err != nil {
		return false, fmt.Errorf("failed to drop %s.%s: %w", table, column, err)
	}
	return true, nil
}

// migrateCrawlerSourcesID：初版 security_crawler_sources 建表漏了 id 主键
// （管理面 :id/flags 与 ORDER BY id 均依赖）。新库 CREATE 已含 id 直接跳过；
// 存量无 id 库整表重建并保留全部源行（无 FK 引用，单事务即可）。
func migrateCrawlerSourcesID() error {
	var hasID int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('security_crawler_sources') WHERE name='id'").Scan(&hasID); err != nil {
		return fmt.Errorf("inspect security_crawler_sources.id: %w", err)
	}
	if hasID > 0 {
		return nil
	}
	return withTableRebuild(context.Background(), "security_crawler_sources", func(tx *sql.Tx) error {
		if _, err := tx.Exec(`CREATE TABLE security_crawler_sources_with_id (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL DEFAULT '',
		url TEXT NOT NULL DEFAULT '',
		format TEXT NOT NULL DEFAULT 'plain',
		update_enabled INTEGER NOT NULL DEFAULT 1,
		entry_count INTEGER NOT NULL DEFAULT 0,
		version TEXT NOT NULL DEFAULT '',
		update_status TEXT NOT NULL DEFAULT 'idle',
		message TEXT NOT NULL DEFAULT '',
		last_checked DATETIME,
		next_update DATETIME,
		trigger TEXT NOT NULL DEFAULT '',
		started_at DATETIME,
		finished_at DATETIME,
		consecutive_failures INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now'))
	);
	INSERT INTO security_crawler_sources_with_id (name,display_name,url,format,update_enabled,entry_count,version,update_status,message,last_checked,next_update,"trigger",started_at,finished_at,consecutive_failures,created_at,updated_at)
	SELECT name,display_name,url,format,update_enabled,entry_count,version,update_status,message,last_checked,next_update,"trigger",started_at,finished_at,consecutive_failures,created_at,updated_at FROM security_crawler_sources;
	DROP TABLE security_crawler_sources;
	ALTER TABLE security_crawler_sources_with_id RENAME TO security_crawler_sources;`); err != nil {
			return fmt.Errorf("rebuild security_crawler_sources: %w", err)
		}
		return nil
	})
}

func migrateUsersIsEnabledNotNull() error {
	var notNull int
	if err := DB.QueryRow("SELECT \"notnull\" FROM pragma_table_info('users') WHERE name='is_enabled'").Scan(&notNull); err != nil {
		return fmt.Errorf("inspect users.is_enabled: %w", err)
	}
	if notNull == 1 {
		return nil
	}
	return withTableRebuild(context.Background(), "users", func(tx *sql.Tx) error {
		if _, err := tx.Exec(`UPDATE users SET is_enabled=1 WHERE is_enabled IS NULL;
		CREATE TABLE users_not_null (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username VARCHAR(50) UNIQUE NOT NULL,
			password_hash VARCHAR(255) NOT NULL,
			role VARCHAR(20) NOT NULL DEFAULT 'user',
			display_name VARCHAR(100),
			is_enabled BOOLEAN NOT NULL DEFAULT 1,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_login DATETIME,
			password_changed_at DATETIME,
			password_version INTEGER NOT NULL DEFAULT 0,
			mfa_enabled BOOLEAN DEFAULT 0,
			mfa_secret TEXT DEFAULT '',
			mfa_pending_secret TEXT DEFAULT '',
			mfa_recovery_codes TEXT DEFAULT '[]',
			mfa_last_timestep INTEGER DEFAULT 0,
			mfa_pending_fails INTEGER DEFAULT 0,
			login_failed_attempts INTEGER NOT NULL DEFAULT 0,
			login_locked_until TEXT,
			auth_provider TEXT NOT NULL DEFAULT 'local',
			oidc_subject TEXT DEFAULT '',
			oidc_issuer TEXT DEFAULT ''
		);
		INSERT INTO users_not_null (id,username,password_hash,role,display_name,is_enabled,created_at,last_login,password_changed_at,password_version,mfa_enabled,mfa_secret,mfa_pending_secret,mfa_recovery_codes,mfa_last_timestep,mfa_pending_fails,login_failed_attempts,login_locked_until,auth_provider,oidc_subject,oidc_issuer)
		SELECT id,username,password_hash,role,display_name,is_enabled,created_at,last_login,password_changed_at,password_version,mfa_enabled,mfa_secret,mfa_pending_secret,mfa_recovery_codes,mfa_last_timestep,mfa_pending_fails,login_failed_attempts,login_locked_until,auth_provider,oidc_subject,oidc_issuer FROM users;
		DROP TABLE users;
		ALTER TABLE users_not_null RENAME TO users;`); err != nil {
			return fmt.Errorf("rebuild users table: %w", err)
		}
		return nil
	})
}

// migrateSecurityPoliciesNullable（历史问题）：历史 NOT-NULL 窗口期建库的
// security_policies 四列（geoip_countries/geoip_mode/waf_check_response/
// block_status_code）永久停留 NOT NULL——fresh CREATE 与 newColumns 迁移
// 现均为可空，但二者对「列已存在」的窗口期库都不生效，无收敛路径；NOT NULL
// 形态会拒绝 restoreTable/快照通道携带的 NULL 行（与 :757 刻意可空口径
// 冲突）。检测任一列 notnull=1 即整表重建为当前 fresh CREATE 形状并保数据，
// 幂等：已收敛的库四列 notnull=0，直接返回。
func migrateSecurityPoliciesNullable() error {
	var notNullCount int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('security_policies')
		WHERE name IN ('geoip_countries','geoip_mode','waf_check_response','block_status_code') AND "notnull"=1`).Scan(&notNullCount); err != nil {
		return fmt.Errorf("inspect security_policies nullability: %w", err)
	}
	if notNullCount == 0 {
		return nil
	}
	if err := withTableRebuild(context.Background(), "security_policies", func(tx *sql.Tx) error {
		// rebuild 必须与 fresh CREATE（含 refs 两列）同形状并搬运其数据——
		// 陈旧 DDL 会把同一 runMigrations 早前 newColumns 刚加的列丢掉
		//（历史问题：窗口期库首启安全策略子系统整体 no such column）。
		if _, err := tx.Exec(`CREATE TABLE security_policies_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT DEFAULT '',
			mode TEXT DEFAULT 'off',
			anomaly_threshold INTEGER DEFAULT 5,
			ip_acl_mode TEXT DEFAULT '',
			ip_acl_list TEXT DEFAULT '[]',
			ip_acl_enabled BOOLEAN DEFAULT FALSE,
			ip_whitelist TEXT DEFAULT '[]',
			ip_blacklist TEXT DEFAULT '[]',
			rate_limit_enabled BOOLEAN DEFAULT FALSE,
			rate_limit_rps INTEGER DEFAULT 0,
			rate_limit_burst INTEGER DEFAULT 0,
			crs_rule_groups TEXT DEFAULT '[]',
			crs_excluded_rules TEXT DEFAULT '[]',
			custom_rules TEXT DEFAULT '[]',
			block_page_id INTEGER DEFAULT 0,
			block_status_code INTEGER DEFAULT 0,
			enabled BOOLEAN DEFAULT TRUE,
			updated_by INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT (datetime('now')),
			updated_at DATETIME DEFAULT (datetime('now')),
			ip_whitelist_enabled INTEGER DEFAULT 1,
			geoip_countries TEXT DEFAULT '[]',
			geoip_mode TEXT DEFAULT 'deny',
			waf_check_response INTEGER DEFAULT 0,
			log_request_body INTEGER DEFAULT 0,
			ip_acl_list_refs TEXT DEFAULT '[]',
			ip_whitelist_refs TEXT DEFAULT '[]',
			policy_type TEXT NOT NULL DEFAULT '',
			trust_detection BOOLEAN NOT NULL DEFAULT 0,
			geoip_crawler_exempt INTEGER NOT NULL DEFAULT 0,
			geoip_crawler_engines TEXT NOT NULL DEFAULT '[]'
		);
		INSERT INTO security_policies_new (id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,
			ip_whitelist,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,
			custom_rules,block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,ip_whitelist_enabled,geoip_countries,geoip_mode,waf_check_response,
			log_request_body,ip_acl_list_refs,ip_whitelist_refs,policy_type,trust_detection,geoip_crawler_exempt,geoip_crawler_engines)
		SELECT id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,
			ip_whitelist,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,
			custom_rules,block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,COALESCE(ip_whitelist_enabled,1),geoip_countries,geoip_mode,waf_check_response,
			COALESCE(log_request_body,0),COALESCE(ip_acl_list_refs,'[]'),COALESCE(ip_whitelist_refs,'[]'),policy_type,COALESCE(trust_detection,0),COALESCE(geoip_crawler_exempt,0),COALESCE(geoip_crawler_engines,'[]')
		FROM security_policies;
		DROP TABLE security_policies;
		ALTER TABLE security_policies_new RENAME TO security_policies;`); err != nil {
			return fmt.Errorf("rebuild security_policies table: %w", err)
		}
		return nil
	}); err != nil {
		return err
	}
	log.Printf("Rebuilt security_policies with nullable geoip/waf columns (converged %d NOT NULL columns)", notNullCount)
	return nil
}

// nodesDedupeSQL 是 nodes 整表重建前的去重语句（历史修复，历史修复）。
// 旧实现只保留 MIN(id)——若重复行里低 id 是旧的未批准行、被删的高 id 才是
// 已批准/持 cluster_token_hash/registration_secret 的当前节点，升级后该节点
// 直接从注册表消失（需重新注册/审批，令牌与 last_seen 一并丢失）。
// 现按「已批准 > 持令牌/注册密钥 > 最近上报 > 最小 id」保留，与两处历史升级
// 路径共用本条单源语句（此前逐字复制两份）。
const nodesDedupeSQL = `DELETE FROM nodes WHERE id NOT IN (
	SELECT id FROM (
		SELECT id, ROW_NUMBER() OVER (
			PARTITION BY ip_address, port
			ORDER BY
				IIF(is_approved IN ('1', 1), 1, 0) DESC,
				IIF(COALESCE(NULLIF(cluster_token_hash, ''), NULLIF(registration_secret, '')) IS NULL, 0, 1) DESC,
				COALESCE(last_seen, '') DESC,
				id ASC
		) AS rn
		FROM nodes
	) WHERE rn = 1
)`

// dedupeNodesTx 在 nodes 重建事务内执行去重并留痕删除条数。
func dedupeNodesTx(tx *sql.Tx) error {
	result, err := tx.Exec(nodesDedupeSQL)
	if err != nil {
		return fmt.Errorf("dedupe nodes: %w", err)
	}
	if removed, rowsErr := result.RowsAffected(); rowsErr == nil && removed > 0 {
		log.Printf("WARN: nodes 迁移去重删除 %d 条重复 (ip_address, port) 行（保留已批准/持令牌/最近上报者）", removed)
	}
	return nil
}

func migrateNodesDeadColumns() error {
	var legacyColumns int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name IN ('sync_enabled','sync_scope')").Scan(&legacyColumns); err != nil {
		return fmt.Errorf("inspect nodes legacy columns: %w", err)
	}
	if legacyColumns == 0 {
		return nil
	}
	return withTableRebuild(context.Background(), "nodes", func(tx *sql.Tx) error {
		// 历史问题:重建目标对齐新 schema(无 master_id/自引用 FK,idx_nodes_master；
		// 补 UNIQUE(ip,port))——master_id 死列经本路径与 migrateNodesDropMasterID
		// 双路径收敛为同一形态。
		// 历史问题:重建 DDL 必须携 server_map_lat/lon 并 COALESCE 保值——
		// 此前漏列，升级重建丢坐标（第二次 ensureNewColumns 仅以默认 0 补回 schema，
		// 值已丢失）。
		// 历史问题（历史）：DDL 与拷贝 SELECT 抽到 nodesRebuildDDL/
		// nodesRebuildCopySQL 单源——本路径与 migrateNodesDropMasterID 曾各自
		// 手写一份并已文本分叉（cluster_token_delivered DEFAULT 0/FALSE），
		// 未来给 nodes 加列只需改单源。
		if err := dedupeNodesTx(tx); err != nil {
			return err
		}
		if _, err := tx.Exec(nodesRebuildDDL("nodes_without_legacy_sync") + nodesRebuildCopySQL("nodes_without_legacy_sync") + `
		DROP TABLE nodes;
		ALTER TABLE nodes_without_legacy_sync RENAME TO nodes;
		`); err != nil {
			return fmt.Errorf("rebuild nodes table: %w", err)
		}
		return nil
	})
}

// nodesRebuildDDL 与 nodesRebuildCopySQL 是 nodes 整表重建的唯一 DDL 单源
// （历史问题，历史）：两条历史升级路径——migrateNodesDeadColumns
// （legacy sync 列）与 migrateNodesDropMasterID（master_id 死列）——共用本形态，
// 杜绝「加列只改一处、另一条升级路径静默丢值」（历史问题 丢过
// server_map_lat/lon）。target 为迁移期临时表名。
//
// fresh CREATE（createTables）的列集合是本函数的超集前提：新增列须同时登记
// newColumns（存量库补列）与本 DDL（重建保留），db_truth_defaults_test 的
// nodes 全形 parity 钉测对 fresh/重建两种稳态逐列比对 name/type/notnull/
// default/pk。
func nodesRebuildDDL(target string) string {
	return `CREATE TABLE ` + target + ` (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		mode VARCHAR(10) NOT NULL DEFAULT 'slave',
		ip_address VARCHAR(45) NOT NULL,
		port INTEGER DEFAULT 8000,
		protocol VARCHAR(10) DEFAULT 'http',
		access_url VARCHAR(255) DEFAULT '',
		is_approved BOOLEAN DEFAULT FALSE,
		sync_interval INTEGER DEFAULT 60,
		status VARCHAR(20) DEFAULT 'offline',
		cluster_token_hash VARCHAR(64),
		registration_secret VARCHAR(64),
		registration_secret_expires_at DATETIME,
		cluster_token_delivered BOOLEAN DEFAULT FALSE,
		reported_version INTEGER DEFAULT 0,
		health_json TEXT,
		last_sync_at DATETIME,
		last_sync_error TEXT,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		server_map_lat REAL NOT NULL DEFAULT 0,
		server_map_lon REAL NOT NULL DEFAULT 0,
		UNIQUE(ip_address, port)
	);`
}

// nodesRebuildCopySQL 与 nodesRebuildDDL 同源配套：列清单与 COALESCE 归一
// 必须逐项对应（mode/protocol/access_url/坐标在存量脏行上可能为 NULL，重建
// 时归一到当前默认，避免 NOT NULL 列拒绝拷贝）。
func nodesRebuildCopySQL(target string) string {
	return `INSERT INTO ` + target + ` (id,name,mode,ip_address,port,protocol,access_url,is_approved,sync_interval,status,cluster_token_hash,registration_secret,registration_secret_expires_at,cluster_token_delivered,reported_version,health_json,last_sync_at,last_sync_error,last_seen,created_at,server_map_lat,server_map_lon)
		SELECT id,name,COALESCE(mode,'slave'),ip_address,port,COALESCE(protocol,'http'),COALESCE(access_url,''),is_approved,sync_interval,status,cluster_token_hash,registration_secret,registration_secret_expires_at,cluster_token_delivered,reported_version,health_json,last_sync_at,last_sync_error,last_seen,created_at,COALESCE(server_map_lat,0),COALESCE(server_map_lon,0) FROM nodes;`
}

// migrateOidcIdentityUniqueIndex（历史修复）：OIDC 身份三元组唯一
// 索引——JIT 开户在并发回调窗口（双请求同走 no-rows 分支）下可产生重复
// (oidc_issuer, oidc_subject) 行，命中 SELECT 无 ORDER BY 时取行不确定，会话
// 随机落到重复行之一。partial 索引只约束 auth_provider='oidc' 且 subject 非空
// 的行，本地用户与历史空串行不受影响。安全阀：建索引前先查重，存量库存在
// 重复身份则跳过建索引并告警（绝不因历史脏数据拖垮启动；重复行需人工合并/
// 清理后重启自动建索引）。幂等：IF NOT EXISTS，重跑零开销。
func migrateOidcIdentityUniqueIndex() error {
	rows, err := DB.Query(`SELECT oidc_issuer, oidc_subject, COUNT(*) FROM users
		WHERE auth_provider='oidc' AND oidc_subject<>'' GROUP BY oidc_issuer, oidc_subject HAVING COUNT(*)>1`)
	if err != nil {
		return fmt.Errorf("inspect duplicate oidc identities: %w", err)
	}
	var duplicates []string
	for rows.Next() {
		var issuer, subject string
		var count int
		if err := rows.Scan(&issuer, &subject, &count); err != nil {
			rows.Close()
			return fmt.Errorf("scan duplicate oidc identities: %w", err)
		}
		duplicates = append(duplicates, fmt.Sprintf("%s/%s×%d", issuer, subject, count))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate duplicate oidc identities: %w", err)
	}
	if len(duplicates) > 0 {
		log.Printf("WARN: users 表存在重复 OIDC 身份(%s)，跳过 u_oidc_identity 唯一索引创建——请人工合并/清理重复行后重启", strings.Join(duplicates, ", "))
		return nil
	}
	if _, err := DB.Exec("CREATE UNIQUE INDEX IF NOT EXISTS u_oidc_identity ON users(oidc_issuer, oidc_subject) WHERE auth_provider='oidc' AND oidc_subject<>''"); err != nil {
		return fmt.Errorf("create u_oidc_identity index: %w", err)
	}
	return nil
}

func migrateLegacyDNSCredentials() error {
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin legacy certificate credential migration: %w", err)
	}
	// 逐列探测：历史中断可能只留下 dns_id 或 dns_key 单列；旧实现要求
	// 两列同时存在，残形会被永久跳过（历史问题-4）。
	var hasID, hasKey bool
	if err := tx.QueryRow(`SELECT
		EXISTS(SELECT 1 FROM pragma_table_info('certificate_configs') WHERE name='dns_id'),
		EXISTS(SELECT 1 FROM pragma_table_info('certificate_configs') WHERE name='dns_key')`).Scan(&hasID, &hasKey); err != nil {
		return rollbackMigration(tx, fmt.Errorf("failed to check legacy certificate credential columns: %w", err))
	}
	if hasID || hasKey {
		idExpr, keyExpr := "''", "''"
		if hasID {
			idExpr = "COALESCE(dns_id,'')"
		}
		if hasKey {
			keyExpr = "COALESCE(dns_key,'')"
		}
		rows, err := tx.Query("SELECT id, " + idExpr + ", " + keyExpr + " FROM certificate_configs WHERE dns_credentials IS NULL OR dns_credentials = ''")
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to query legacy certificate credentials: %w", err))
		}
		type legacyCredential struct {
			id            int
			dnsID, dnsKey string
		}
		var credentials []legacyCredential
		for rows.Next() {
			var credential legacyCredential
			if err := rows.Scan(&credential.id, &credential.dnsID, &credential.dnsKey); err != nil {
				closeErr := rows.Close()
				return rollbackMigration(tx, errors.Join(fmt.Errorf("failed to scan legacy certificate credentials: %w", err), closeErr))
			}
			credentials = append(credentials, credential)
		}
		if err := rows.Err(); err != nil {
			closeErr := rows.Close()
			return rollbackMigration(tx, errors.Join(fmt.Errorf("failed to iterate legacy certificate credentials: %w", err), closeErr))
		}
		if err := rows.Close(); err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to close legacy certificate credential rows: %w", err))
		}
		for _, credential := range credentials {
			if credential.dnsID == "" && credential.dnsKey == "" {
				continue
			}
			encoded, err := json.Marshal(map[string]string{"app_id": credential.dnsID, "app_token": credential.dnsKey})
			if err != nil {
				return rollbackMigration(tx, fmt.Errorf("failed to encode legacy certificate credentials: %w", err))
			}
			if _, err := tx.Exec("UPDATE certificate_configs SET dns_credentials = ? WHERE id = ?", string(encoded), credential.id); err != nil {
				return rollbackMigration(tx, fmt.Errorf("failed to migrate certificate credentials for config %d: %w", credential.id, err))
			}
		}
		// 值已迁入 dns_credentials 后同事务删除两份明文旧列：失败整体回滚，
		// 不出现「新值已提交但退役列仍随 SELECT * 备份外泄」的中间态。
		drop := ""
		if hasID {
			drop += "ALTER TABLE certificate_configs DROP COLUMN dns_id;"
		}
		if hasKey {
			drop += "ALTER TABLE certificate_configs DROP COLUMN dns_key;"
		}
		if drop != "" {
			if _, err := tx.Exec(drop); err != nil {
				return rollbackMigration(tx, fmt.Errorf("failed to drop legacy certificate credential columns: %w", err))
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit legacy certificate credential migration: %w", err)
	}
	return nil
}

func rollbackMigration(tx *sql.Tx, migrationErr error) error {
	if rollbackErr := tx.Rollback(); rollbackErr != nil && !errors.Is(rollbackErr, sql.ErrTxDone) {
		return errors.Join(migrationErr, rollbackErr)
	}
	return migrationErr
}

// readForeignKeysSetting 读取连接当前 foreign_keys 设置（0/1）。历史修复：表重建
// 迁移临时关闭 foreign_keys 前先记原值，结束后还原原值而非无条件 =ON——
// 调用方若刻意保持关闭，迁移不得悄悄改写会话设置。
func readForeignKeysSetting(ctx context.Context, conn *sql.Conn) (int, error) {
	var setting int
	if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&setting); err != nil {
		return 0, err
	}
	return setting, nil
}

// restoreForeignKeysSetting 将连接 foreign_keys 还原为迁移前读到的原值。
func restoreForeignKeysSetting(ctx context.Context, conn *sql.Conn, setting int) error {
	_, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA foreign_keys=%d", setting))
	return err
}

// migrateLbRulesPrimaryKey rebuilds lb_rules and upstreams tables to use caddy_id as primary key
func migrateLbRulesPrimaryKey() error {
	// Check if lb_rules already has caddy_id as primary key (checked via pragma)
	var pkName string
	err := DB.QueryRow("SELECT name FROM pragma_table_info('lb_rules') WHERE pk = 1").Scan(&pkName)
	if err != nil {
		return fmt.Errorf("failed to check primary key: %w", err)
	}

	// If primary key is already 'caddy_id', nothing to do
	if pkName == "caddy_id" {
		log.Println("lb_rules already uses caddy_id as primary key")
		return nil
	}

	// 拷贝阶段的 INNER JOIN 会丢弃 FK OFF 历史期积累的孤儿 upstream。
	// 迁移前计数，成功后留痕；保持既有数据收敛语义，但不允静默消失。
	var orphanUpstreams int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM upstreams u
		LEFT JOIN lb_rules r ON u.rule_id=r.id WHERE r.id IS NULL`).Scan(&orphanUpstreams); err != nil {
		return fmt.Errorf("failed to count orphan upstreams before lb_rules primary key migration: %w", err)
	}

	log.Println("Migrating lb_rules to use caddy_id as primary key...")

	if err := withTableRebuild(context.Background(), "lb_rules", func(tx *sql.Tx) error {
		// Create new lb_rules table with caddy_id as primary key
		_, err := tx.Exec(`
		CREATE TABLE lb_rules_new (
			id INTEGER,
			name VARCHAR(100) NOT NULL,
			description VARCHAR(300),
			protocol VARCHAR(10) NOT NULL,
			domain VARCHAR(255),
			listen_port INTEGER NOT NULL,
			strategy VARCHAR(20) DEFAULT 'weighted_round_robin',
			dynamic_dns BOOLEAN DEFAULT FALSE,
			enable_dns_server BOOLEAN DEFAULT FALSE,
			dns_server VARCHAR(255) DEFAULT '',
			dns_family VARCHAR(20) DEFAULT 'ipv4',
			health_check_path VARCHAR(255),
			health_check_interval INTEGER NOT NULL DEFAULT 10,
			-- 历史问题（历史）：重建 DDL 与 fresh CREATE 同形——健康检查族五列
			-- 均为 NOT NULL + 治理默认（回填 defaultUpdates 在本重建之前已收敛
			-- NULL/<=0，重建拷贝不再可能写入 NULL）。
			health_check_timeout INTEGER NOT NULL DEFAULT 2,
			health_check_unhealthy_threshold INTEGER NOT NULL DEFAULT 3,
			health_check_healthy_threshold INTEGER NOT NULL DEFAULT 2,
			enable_active_health_check BOOLEAN DEFAULT FALSE,
			tcp_health_check_port INTEGER DEFAULT 0,
			tcp_proxy_protocol BOOLEAN DEFAULT 0,
			tcp_try_duration INTEGER DEFAULT 0,
			tcp_try_interval INTEGER NOT NULL DEFAULT 250,
			request_body_max_size_mb INTEGER DEFAULT 0,
			upstream_keepalive_timeout INTEGER DEFAULT 0,
			server_tokens_hidden INTEGER DEFAULT 0,
			-- 与 fresh CREATE 同步携带（ensureNewColumns 已加列，陈旧 DDL 会把列
			-- 连同值一并丢弃——历史修复 先例）。
			ntlm_compatible INTEGER NOT NULL DEFAULT 0,
			upstream_force_http1 INTEGER NOT NULL DEFAULT 0,
			custom_routes_enabled BOOLEAN NOT NULL DEFAULT 0,
			proxy_dial_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_response_header_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_read_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_write_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_stream_timeout INTEGER NOT NULL DEFAULT 0,
			proxy_flush_interval INTEGER NOT NULL DEFAULT 0,
			proxy_stream_close_delay INTEGER NOT NULL DEFAULT 0,
			host_header VARCHAR(255),
			-- 与 fresh CREATE 同步携带（ensureNewColumns 在本重建之前已加列，
			-- 陈旧 DDL 会把列连同值一并丢弃——历史修复 先例）。
			health_check_host TEXT NOT NULL DEFAULT '',
			enable_tls BOOLEAN DEFAULT FALSE,
			tls_cert TEXT,
			tls_key TEXT,
			tls_http_redirect BOOLEAN DEFAULT FALSE,
			tls_source VARCHAR(20) DEFAULT 'manual',
			acme_config_id INTEGER DEFAULT 0,
			ca_provider_id INTEGER DEFAULT 0,
			enable_compress BOOLEAN DEFAULT FALSE,
			compress_types VARCHAR(100) DEFAULT 'gzip',
			enabled BOOLEAN NOT NULL DEFAULT 1,
			log_enabled BOOLEAN DEFAULT 0,
			-- 历史修复（历史）：与 fresh CREATE 同步携带阶段拦截页四列——
			-- ensureNewColumns 在本重建之前已加列，陈旧 DDL 会把列连同值一并
			-- 丢弃，且本重建位于二次 ensureNewColumns 安全网之后（无同启动自愈）。
			block_page_stage1_id INTEGER NOT NULL DEFAULT 0,
			block_page_stage1_status INTEGER NOT NULL DEFAULT 0,
			block_page_stage3_id INTEGER NOT NULL DEFAULT 0,
			block_page_stage3_status INTEGER NOT NULL DEFAULT 0,
			created_by INTEGER,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME,
			updated_by INTEGER,
			caddy_id VARCHAR(20) PRIMARY KEY
		)
	`)
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to create lb_rules_new: %w", err))
		}

		// Copy data from old table to new table。注意：ip_acl_mode / ip_acl_list 是已废弃的规则级
		// IP ACL 列（已迁入 security_policies 的策略级 ip_acl_*），此处列清单与 INSERT...SELECT
		// 映射有意排除它们，重建时随旧表一并丢弃。
		_, err = tx.Exec(`
		INSERT INTO lb_rules_new (
			id, name, description, protocol, domain, listen_port,
			strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_proxy_protocol, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden, ntlm_compatible, upstream_force_http1,
			custom_routes_enabled,
			proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout, proxy_stream_timeout, proxy_flush_interval, proxy_stream_close_delay,
			host_header, health_check_host, enable_tls, tls_cert,
			tls_key, tls_http_redirect, tls_source, acme_config_id,
			ca_provider_id, enable_compress, compress_types, enabled, log_enabled,
			created_by, created_at, updated_at, updated_by, caddy_id,
			block_page_stage1_id, block_page_stage1_status, block_page_stage3_id, block_page_stage3_status
		)
		SELECT
			id, name, description, protocol, domain, listen_port,
			strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path,
			-- 历史问题：重建目标列 NOT NULL——启动序中 defaultUpdates 已先收敛
			-- NULL/<=0，COALESCE 仅覆盖直接调用迁移（测试/运维脚本）的旧形态。
			COALESCE(health_check_interval,` + fmt.Sprint(DefaultHealthCheckInterval) + `),
			COALESCE(health_check_timeout,` + fmt.Sprint(DefaultHealthCheckTimeout) + `),
			COALESCE(health_check_unhealthy_threshold,` + fmt.Sprint(DefaultHealthCheckUnhealthyThreshold) + `),
			COALESCE(health_check_healthy_threshold,` + fmt.Sprint(DefaultHealthCheckHealthyThreshold) + `),
			enable_active_health_check, tcp_health_check_port, tcp_proxy_protocol, tcp_try_duration, COALESCE(tcp_try_interval,` + fmt.Sprint(DefaultTCPTryInterval) + `),
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden, COALESCE(ntlm_compatible,0), COALESCE(upstream_force_http1,0),
			COALESCE(custom_routes_enabled,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
			host_header, COALESCE(health_check_host,''), enable_tls, tls_cert,
			tls_key, tls_http_redirect, tls_source, acme_config_id,
			ca_provider_id, enable_compress, compress_types, COALESCE(enabled,0), COALESCE(log_enabled,0),
			created_by, created_at, updated_at, updated_by, caddy_id,
			COALESCE(block_page_stage1_id,0), COALESCE(block_page_stage1_status,0), COALESCE(block_page_stage3_id,0), COALESCE(block_page_stage3_status,0)
		FROM lb_rules
	`)
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to copy lb_rules data: %w", err))
		}

		// Drop old table
		_, err = tx.Exec("DROP TABLE lb_rules")
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to drop old lb_rules: %w", err))
		}

		// Rename new table
		_, err = tx.Exec("ALTER TABLE lb_rules_new RENAME TO lb_rules")
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to rename lb_rules_new: %w", err))
		}

		// Create new upstreams table with VARCHAR rule_id
		// enabled 与 fresh CREATE 对齐为 NOT NULL DEFAULT 1（历史问题 消除双通道
		// schema 漂移）；本迁移先于导入侧 NULL 归一化执行，拷贝侧以
		// COALESCE(enabled,0) 兜底（与 lb_rules_new 拷贝同口径，NULL 视禁用）。
		_, err = tx.Exec(`
		CREATE TABLE upstreams_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id VARCHAR(20) NOT NULL,
		host VARCHAR(255) NOT NULL,
		port INTEGER NOT NULL,
		weight INTEGER DEFAULT 1,
		dynamic_dns BOOLEAN DEFAULT FALSE,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		protocol VARCHAR(10) DEFAULT 'http',
	max_connections INTEGER DEFAULT 0,
	origin_domain TEXT NOT NULL DEFAULT '',
		FOREIGN KEY (rule_id) REFERENCES lb_rules(caddy_id) ON DELETE CASCADE
	)
`)
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to create upstreams_new: %w", err))
		}

		// Copy data from old upstreams table to new (convert rule_id from int to string)
		_, err = tx.Exec(`
	INSERT INTO upstreams_new (id, rule_id, host, port, weight, dynamic_dns, enabled, protocol, max_connections, origin_domain)
	SELECT u.id, r.caddy_id, u.host, u.port, u.weight, u.dynamic_dns, COALESCE(u.enabled, 0), u.protocol,
		       COALESCE(u.max_connections, 0), COALESCE(u.origin_domain, '')
		FROM upstreams u
		JOIN lb_rules r ON u.rule_id = r.id
	`)
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to copy upstreams data: %w", err))
		}

		// Drop old upstreams table
		_, err = tx.Exec("DROP TABLE upstreams")
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to drop old upstreams: %w", err))
		}

		// Rename new upstreams table
		_, err = tx.Exec("ALTER TABLE upstreams_new RENAME TO upstreams")
		if err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to rename upstreams_new: %w", err))
		}
		return nil
	}); err != nil {
		return err
	}

	if orphanUpstreams > 0 {
		detail := fmt.Sprintf("lb_rules 主键迁移丢弃 %d 条孤儿 upstream 行（rule_id 无对应规则）", orphanUpstreams)
		log.Print("WARN: " + detail)
		recordSystemAudit("启动迁移", "系统配置", detail)
	}
	log.Println("Successfully migrated lb_rules to use caddy_id as primary key")
	return nil
}

var statusInConstraintPattern = regexp.MustCompile(`(?i)\bstatus\s+IN\s*\(([^)]*)\)`)

func hasExactStatusConstraint(tableSQL string, requiredStatuses []string) bool {
	match := statusInConstraintPattern.FindStringSubmatch(tableSQL)
	if len(match) != 2 {
		return false
	}
	statuses := strings.Split(match[1], ",")
	if len(statuses) != len(requiredStatuses) {
		return false
	}
	required := make(map[string]struct{}, len(requiredStatuses))
	for _, status := range requiredStatuses {
		required[status] = struct{}{}
	}
	seen := make(map[string]struct{}, len(statuses))
	for _, rawStatus := range statuses {
		rawStatus = strings.Join(strings.Fields(rawStatus), "")
		if len(rawStatus) < 2 || rawStatus[0] != rawStatus[len(rawStatus)-1] || (rawStatus[0] != '\'' && rawStatus[0] != '"') {
			return false
		}
		status := rawStatus[1 : len(rawStatus)-1]
		if _, ok := required[status]; !ok {
			return false
		}
		seen[status] = struct{}{}
	}
	return len(seen) == len(required)
}

// migrateCertJobsStatusConstraint rebuilds cert_jobs to enforce the allowed
// status CHECK constraint and the 'queued' default value on existing databases.
// 历史修复（历史裁定，边界声明防重报）：此类 CHECK 收敛迁移仅适用于
// 跨版本演化过的表（cert_jobs 的约束集随版本多次扩充，存量库存在旧形态）；
// auto_backups/task_runs 等同版引入的表以 fresh DDL 为准——首版 DDL 即含
// 全量约束，不存在需要收敛的旧库形态，刻意不建同型迁移。
func migrateCertJobsStatusConstraint() error {
	var tableSQL string
	if err := DB.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='cert_jobs'").Scan(&tableSQL); err != nil {
		return fmt.Errorf("failed to read cert_jobs schema: %w", err)
	}
	requiredStatuses := CertJobStatuses()
	constraintComplete := hasExactStatusConstraint(tableSQL, requiredStatuses)
	defaultQueued := false
	statusNotNull := false
	rows, err := DB.Query("PRAGMA table_info(cert_jobs)")
	if err != nil {
		return fmt.Errorf("failed to read cert_jobs columns: %w", err)
	}
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue sql.NullString
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan cert_jobs columns: %w", err)
		}
		if name == "status" {
			defaultQueued = defaultValue.Valid && strings.Trim(defaultValue.String, "'\"") == "queued"
			statusNotNull = notNull == 1
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("failed to iterate cert_jobs columns: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("failed to close cert_jobs columns: %w", err)
	}
	if constraintComplete && defaultQueued && statusNotNull {
		return nil
	}

	log.Println("Migrating cert_jobs status constraint...")

	// 历史问题（历史）：枚举外状态（已废弃/拼写错误）是用户可见数据
	// 改写——归一到终态 failed（保守：failed 不会被签发队列拾取，且
	// certificates.go 的「无 expires_at 的 failed」重签路径可手动恢复），
	// 不再回 'queued'（活跃起始态，会被队列立刻拾取并触发一次无审计的签发/
	// 部署尝试）。改写数量先计数，重建提交后聚合写一条系统审计。
	var unknownStatusRows int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE status IS NOT NULL AND status NOT IN (` + certJobStatusListSQL() + `)`).Scan(&unknownStatusRows); err != nil {
		return fmt.Errorf("failed to count unknown cert_jobs statuses: %w", err)
	}

	if err := withTableRebuild(context.Background(), "cert_jobs", func(tx *sql.Tx) error {
		if _, err := tx.Exec("ALTER TABLE cert_jobs RENAME TO cert_jobs_old"); err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to rename cert_jobs: %w", err))
		}

		if _, err := tx.Exec(`
		CREATE TABLE cert_jobs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			rule_id VARCHAR(20) NOT NULL,
			domain VARCHAR(255) NOT NULL,
			status VARCHAR(20) NOT NULL DEFAULT 'queued' ` + certJobStatusCheckSQL() + `,
			message TEXT,
			expires_at DATETIME,
			cert_pem TEXT,
			key_pem TEXT,
			ca_provider_id INTEGER DEFAULT 0,
			renewal_attempts INTEGER DEFAULT 0,
			ca_available_after DATETIME,
			last_error_code VARCHAR(20),
			deployment_attempts INTEGER DEFAULT 0,
			deployment_available_after DATETIME,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME
		)
	`); err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to create new cert_jobs table: %w", err))
		}

		if _, err := tx.Exec(`
		INSERT INTO cert_jobs (
			id, rule_id, domain, status, message, expires_at, cert_pem, key_pem,
			ca_provider_id, renewal_attempts, ca_available_after, last_error_code, deployment_attempts, deployment_available_after,
			created_at, updated_at
		)
		SELECT
			id, rule_id, domain,
			CASE WHEN COALESCE(status,'queued') IN (` + certJobStatusListSQL() + `) THEN COALESCE(status,'queued') ELSE 'failed' END,
			message, expires_at, cert_pem, key_pem,
			ca_provider_id, renewal_attempts, ca_available_after, last_error_code, deployment_attempts, deployment_available_after,
			created_at, updated_at
		FROM cert_jobs_old
	`); err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to copy cert_jobs data: %w", err))
		}

		if _, err := tx.Exec("DROP TABLE cert_jobs_old"); err != nil {
			return rollbackMigration(tx, fmt.Errorf("failed to drop old cert_jobs table: %w", err))
		}
		return nil
	}); err != nil {
		return err
	}

	log.Println("cert_jobs status constraint migration completed")
	if unknownStatusRows > 0 {
		detail := fmt.Sprintf("cert_jobs 枚举外状态归一到 failed（不再回 queued，避免触发新签发）：%d 行", unknownStatusRows)
		log.Print(detail)
		recordSystemAudit("启动迁移", "证书任务", detail)
	}
	return nil
}

func Close() error {
	stopAPIKeyLastUsedFlusher()
	flushErr := FlushAPIKeyLastUsed()
	var err error
	err = errors.Join(err, flushErr)
	// 历史问题（历史）：Close 后包级句柄必须清空——残留的已关闭 *sql.DB
	// 会让 GetDB()/后台循环把「已关闭句柄」当有效连接使用，且在测试间泄漏。
	// currentDB 同步复位（flush 已在关闭前完成）；重复 Close 因 nil 判定而幂等。
	SetDB(nil)
	if AuditDB != nil {
		err = errors.Join(err, AuditDB.Close())
		AuditDB = nil
	}
	if MetricsDB != nil {
		err = errors.Join(err, MetricsDB.Close())
		MetricsDB = nil
	}
	if DB != nil {
		err = errors.Join(err, DB.Close())
		DB = nil
	}
	return err
}

// generateCaddyIDForMigration generates a unique caddy_id for migration
func generateCaddyIDForMigration() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	randomBytes := make([]byte, 10)
	if _, err := rand.Read(randomBytes); err != nil {
		panic(fmt.Sprintf("crypto/rand unavailable for migration id: %v", err))
	}
	id := make([]byte, 13)
	id[0] = 'l'
	id[1] = 'b'
	id[2] = '_'
	for i := 3; i < 13; i++ {
		id[i] = charset[int(randomBytes[i-3])%len(charset)]
	}
	return string(id)
}

func migrateSyncSwitches() error {
	// 直调兼容：marker 列的 canonical 登记点是 newColumns；此处保证单函数被
	// 直接调用（测试/局部迁移）时列已存在，行为与 runMigrations 路径一致。
	if err := ensureNewColumns(map[string]string{"global_config.sync_switches_migrated": "BOOLEAN DEFAULT 0"}, nil); err != nil {
		return err
	}
	var done bool
	if err := DB.QueryRow("SELECT COALESCE(sync_switches_migrated,0) FROM global_config WHERE id=1").Scan(&done); err != nil && err != sql.ErrNoRows {
		return err
	}
	// 系统数据恒同步(2026-09-11 裁定):存量 sync_users=0 回填 1——幂等
	// UPDATE(合法态恒 1,零副作用),移出 marker 门:已迁移库(marker=1)的
	// 存量 0 值同样回填,Status API 与四处强制点显示一致。
	if _, err := DB.Exec("UPDATE global_config SET sync_users=1 WHERE COALESCE(sync_users,0)=0"); err != nil {
		return err
	}
	if done {
		return nil
	}
	// 分类开关语义历经两轮收敛(sync_caddy_config → 五类开关 → 三分类合并):
	// 旧 sync_caddy_config 仅覆盖 Caddy 全局配置且默认关,五类开关覆盖
	// 日志/时区/Caddy 全部全局项且默认开,语义不同因此不搬运旧值;曾依赖
	// 旧开关关闭同步的用户需在设置卡片重新关闭对应类别。sync_caddy_config
	// 列与其后收敛删除的 sync_global_config/sync_waf_files 列均已随迁移删除。
	_, err := DB.Exec("UPDATE global_config SET sync_switches_migrated=1 WHERE id=1")
	return err
}

// migrateNodesDropMasterID 存量库 nodes 表重建(历史问题,2026-09-12):
// master_id 为死列(无业务读写),连同自引用 FK 与 idx_nodes_master 一并移除;
// 补 UNIQUE(ip_address, port) 防深度(应用层单未用令牌不变式已防竞态,此处
// 为改库/代码回归兜底)。重建前按 (ip,port) 去重保 MIN(id)。幂等:新形态
// (无 master_id 列)直接跳过。
func migrateNodesDropMasterID() error {
	var hasMasterID int
	if err := DB.QueryRow("SELECT COUNT(*) FROM pragma_table_info('nodes') WHERE name='master_id'").Scan(&hasMasterID); err != nil {
		return err
	}
	if hasMasterID == 0 {
		return nil
	}
	// 历史问题-1(历史):conn+foreign_keys 存/关/还原+事务——与同文件
	// 全部兄弟表重建迁移(migrateNodesDeadColumns 等)同模式。此前裸 DB.Exec
	// 逐语句自动提交:半失败→nodes_new 残留→重跑 CREATE 报 already exists→
	// 启动死循环;DROP 与 RENAME 之间崩溃→nodes 表丢失→下次启动静默重建
	// 空表,节点注册表全量丢失。事务化后失败整体回滚、重跑幂等（历史问题：骨架
	// 已收敛到 withTableRebuild）。
	return withTableRebuild(context.Background(), "nodes master_id", func(tx *sql.Tx) error {
		// 历史问题（历史）：DDL/拷贝 SELECT 与 migrateNodesDeadColumns
		// 共用 nodesRebuildDDL/nodesRebuildCopySQL 单源。
		if _, err := tx.Exec(`DROP INDEX IF EXISTS idx_nodes_master;`); err != nil {
			return fmt.Errorf("drop legacy nodes index: %w", err)
		}
		if err := dedupeNodesTx(tx); err != nil {
			return err
		}
		if _, err := tx.Exec(nodesRebuildDDL("nodes_new") + nodesRebuildCopySQL("nodes_new") + `
	DROP TABLE nodes;
	ALTER TABLE nodes_new RENAME TO nodes;`); err != nil {
			return fmt.Errorf("rebuild nodes: %w", err)
		}
		return nil
	})
}

func ensureClusterAppliedSections() error {
	_, err := DB.Exec(`CREATE TABLE IF NOT EXISTS cluster_applied_sections (
		section TEXT PRIMARY KEY,
		hash TEXT NOT NULL DEFAULT '',
		applied_version INTEGER NOT NULL DEFAULT 0,
		applied_at DATETIME
	)`)
	return err
}

func migrateTCPRuleSecurityPolicyBindings() error {
	// TCP 渲染链零消费策略绑定，绑定写接口、协议切换、导入和复制均已在保存
	// 侧阻断新行；旧版本切换前产生的行只会抬高策略 rule_count/绑定视图。
	// 仅删除指向 TCP 规则的绑定，HTTP 与无对应规则的历史行保持不变。
	// 删除改变同步表 security_policy_bindings：在同一事务内沿用现有
	// cluster_version bump 表达式，让从端按既有版本门于下一轮收敛。
	// 先探测再开事务：重复启动无 TCP 绑定时零写入、零版本扰动。
	var stale int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings
		WHERE rule_caddy_id IN (SELECT caddy_id FROM lb_rules WHERE protocol='tcp')`).Scan(&stale); err != nil {
		return fmt.Errorf("failed to inspect TCP rule policy bindings: %w", err)
	}
	if stale == 0 {
		return nil
	}
	startupMigrationWriteTx.Add(1)
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin TCP rule policy binding cleanup: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	res, err := tx.Exec(`DELETE FROM security_policy_bindings
		WHERE rule_caddy_id IN (SELECT caddy_id FROM lb_rules WHERE protocol='tcp')`)
	if err != nil {
		return fmt.Errorf("failed to delete TCP rule policy bindings: %w", err)
	}
	removed, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read deleted TCP rule policy binding count: %w", err)
	}
	if removed > 0 {
		if _, err := tx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
			return fmt.Errorf("failed to bump cluster_version after TCP rule policy binding cleanup: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit TCP rule policy binding cleanup: %w", err)
	}
	if removed > 0 {
		log.Printf("迁移：已清理 %d 条 TCP 规则安全策略绑定", removed)
	}
	return nil
}

// normalizeRuleTimestampsMigration（2026-10-11 用户裁定「时间戳格式本来就应该
// 统一」）：lb_rules/path_rules 的 created_at/updated_at 历史三种并存格式
// （RFC3339 Z[旧版 Go 直写]/Go time +00:00[从端落库]/SQLite 平面[datetime('now')]）
// 统一为 SQLite 平面格式（UTC 存储=audit 先例，展示层按配置时区转换）。
// 幂等：平面格式行 strftime 后原样，LIKE 门只触达非平面行。
func normalizeRuleTimestampsMigration() error {
	for _, table := range []string{"lb_rules", "path_rules"} {
		for _, col := range []string{"created_at", "updated_at"} {
			if _, err := DB.Exec(`UPDATE ` + table + ` SET ` + col + `=strftime('%Y-%m-%d %H:%M:%S', ` + col + `)
				WHERE ` + col + ` IS NOT NULL AND (` + col + ` LIKE '%T%' OR ` + col + ` LIKE '%+%')
				  AND strftime('%Y-%m-%d %H:%M:%S', ` + col + `) IS NOT NULL`); err != nil {
				return fmt.Errorf("failed to normalize %s.%s timestamp format: %w", table, col, err)
			}
		}
	}
	return nil
}

// migrateTCPRuleDeadFields（2026-10-11 用户裁定「如果没有就都应该没有」）：
// 主端存量 TCP 行的 HTTP 专属七字段+NTLM 开关死值清零——与 normalizeRuleForTransport
// 传输归一同一清单。此前仅导出侧归一（历史问题-3「主端存储值不变」），用户
// 裁定改为存储也归零：主端 DB、导出 canonical、从端落库三面同值，快照缓存
// 的 canonical 变化由本迁移写侧触发 cluster_version bump 随下轮同步收敛。
// WHERE 谓词与归一函数逐字对齐：enable_tls=1 即入选（历史修复，历史——
// 此前要求证书材料非空会漏掉「TCP+enable_tls=1+双空证书」形态的存量行）。
// tcpDeadFieldsProbeSQL 死值探测（与下方 UPDATE 同谓词 + TCP 孤儿路径规则）：
// 无命中时零写事务、零版本扰动。谓词必须与 UPDATE WHERE 逐字对齐（改一侧
// 必改另一侧）。
const tcpDeadFieldsProbeSQL = `SELECT
		(SELECT COUNT(*) FROM lb_rules WHERE protocol='tcp' AND (
			COALESCE(host_header,'')<>'' OR COALESCE(health_check_path,'')<>''
			OR enable_compress=1 OR COALESCE(compress_types,'')<>''
			OR request_body_max_size_mb<>0 OR upstream_keepalive_timeout<>0 OR server_tokens_hidden<>0 OR ntlm_compatible<>0 OR upstream_force_http1<>0
			OR proxy_dial_timeout<>0 OR proxy_response_header_timeout<>0 OR proxy_read_timeout<>0 OR proxy_write_timeout<>0 OR proxy_stream_timeout<>0 OR proxy_flush_interval<>0 OR proxy_stream_close_delay<>0
			OR custom_routes_enabled=1 OR dynamic_dns=1
			OR COALESCE(strategy,'')='cookie'
			OR enable_tls=1
		))
		+ (SELECT COUNT(*) FROM path_rules WHERE rule_id IN (SELECT caddy_id FROM lb_rules WHERE protocol='tcp'))`

func migrateTCPRuleDeadFields() error {
	// 历史问题（历史）：清零与 cluster_version bump 必须同事务。此前两条
	// 独立语句：bump 失败→启动失败，但清零已提交→下次启动 WHERE 不再命中→
	// bump 永不发生（主从 canonical 分叉不收敛）。对照 TCP 绑定清理
	// （migrateTCPRuleSecurityPolicyBindings）已在同一事务内完成删除+bump。
	// 先探测再开事务（与姊妹迁移同口径）：无命中时零写事务、零版本扰动——
	// 此前每次启动都无条件开写事务（SET + DELETE 两条写语句）。
	var stale int
	if err := DB.QueryRow(tcpDeadFieldsProbeSQL).Scan(&stale); err != nil {
		return fmt.Errorf("failed to inspect TCP dead fields: %w", err)
	}
	if stale == 0 {
		return nil
	}
	startupMigrationWriteTx.Add(1)
	tx, err := DB.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin TCP dead-field cleanup: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	res, err := tx.Exec(`UPDATE lb_rules SET
		host_header='', health_check_path='', enable_compress=0, compress_types='',
		request_body_max_size_mb=0, upstream_keepalive_timeout=0, server_tokens_hidden=0, ntlm_compatible=0, upstream_force_http1=0,
		proxy_dial_timeout=0, proxy_response_header_timeout=0, proxy_read_timeout=0, proxy_write_timeout=0, proxy_stream_timeout=0, proxy_flush_interval=0, proxy_stream_close_delay=0,
		custom_routes_enabled=0, dynamic_dns=0,
		strategy=CASE WHEN strategy='cookie' THEN 'weighted_round_robin' ELSE strategy END,
		enable_tls=0, tls_cert='', tls_key=''
		WHERE protocol='tcp' AND (
			COALESCE(host_header,'')<>'' OR COALESCE(health_check_path,'')<>''
			OR enable_compress=1 OR COALESCE(compress_types,'')<>''
			OR request_body_max_size_mb<>0 OR upstream_keepalive_timeout<>0 OR server_tokens_hidden<>0 OR ntlm_compatible<>0 OR upstream_force_http1<>0
			OR proxy_dial_timeout<>0 OR proxy_response_header_timeout<>0 OR proxy_read_timeout<>0 OR proxy_write_timeout<>0 OR proxy_stream_timeout<>0 OR proxy_flush_interval<>0 OR proxy_stream_close_delay<>0
			OR custom_routes_enabled=1 OR dynamic_dns=1
			OR COALESCE(strategy,'')='cookie'
			OR enable_tls=1
		)`)
	if err != nil {
		return fmt.Errorf("failed to zero TCP dead fields: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read zeroed TCP rule count: %w", err)
	}
	// TCP 自愈族：TCP 渲染零消费路径规则（buildTCPProxyRoute 无自定义
	// 路径分支）——custom_routes_enabled 归零后残留 path_rules 行成为孤儿，
	// 随导出/备份导入被引用校验放大。与 SET 同事务删除（幂等：无 TCP 规则时
	// 零行命中）。历史修复（历史）parity 钉测试逐字比对两侧 DELETE 字面量。
	pathRes, err := tx.Exec(`DELETE FROM path_rules WHERE rule_id IN (SELECT caddy_id FROM lb_rules WHERE protocol='tcp')`)
	if err != nil {
		return fmt.Errorf("failed to delete TCP rule path rules: %w", err)
	}
	removedPathRules, err := pathRes.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to read deleted TCP path rule count: %w", err)
	}
	if affected > 0 || removedPathRules > 0 {
		// 快照缓存随版本失效；bump 让从端下一轮拉到归一后 canonical，
		// rules 节哈希两侧收敛（「分区滞后」自愈）。
		if _, err := tx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
			return fmt.Errorf("failed to bump cluster_version after TCP dead-field cleanup: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit TCP dead-field cleanup: %w", err)
	}
	committed = true
	if affected > 0 || removedPathRules > 0 {
		// 历史问题：用户规则数据被改写须留痕（与 TCP stale DNS / legacy HTTPS /
		// 孤儿 upstream 三个姊妹迁移同口径，聚合一行+计数）。
		detail := fmt.Sprintf("存量 TCP 规则 HTTP 专属死字段已清零：%d 条（含路径规则 %d 条；主端库/导出 canonical/从端落库三面同值）", affected, removedPathRules)
		log.Print(detail)
		recordSystemAudit("启动迁移", "系统配置", detail)
	}
	return nil
}
