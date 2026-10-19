package models

import (
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

var ErrInvalidClusterAccessURL = errors.New("访问地址必须是无凭证、查询参数或片段的 HTTP 或 HTTPS URL")

// ErrInvalidClusterNodeName 归一后为空的节点名（仅含空白/控制字符）——handler
// 映射 400（客户端可修正），区别于服务端故障。
var ErrInvalidClusterNodeName = errors.New("节点名不能为空")

// ClusterNodeNameMaxLen 节点名长度上限（与 nodes.name VARCHAR(100) 一致）。
// HTTP 入口由 binding max=100 拦截，服务层落库前经 NormalizeClusterNodeName
// 再归一（控制字符剥离 + 截断），两侧共用同一上限。
const ClusterNodeNameMaxLen = 100

type ClusterRegisterRequest struct {
	Token     string `json:"token" binding:"required"`
	Name      string `json:"name" binding:"required,max=100"`
	IPAddress string `json:"ip_address" binding:"required,ip"`
	Port      int    `json:"port" binding:"omitempty,min=1,max=65535"`
	Protocol  string `json:"protocol" binding:"omitempty,oneof=http https"`
	AccessURL string `json:"access_url"`
}

type ClusterNodeAccessURLRequest struct {
	AccessURL string `json:"access_url"`
}

// ClusterNodeSiteRequest 主节点为指定从节点配置大屏站点坐标（node-local 下发）。
type ClusterNodeSiteRequest struct {
	ServerMapLat *float64 `json:"server_map_lat"`
	ServerMapLon *float64 `json:"server_map_lon"`
}

func ValidateClusterAccessURL(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidClusterAccessURL
	}
	return nil
}

// NormalizeClusterNodeName 节点名落库侧单源归一（历史问题-05）：去首尾空白、
// 剥离控制字符、按 schema VARCHAR(100) 上限截断到合法 UTF-8 边界。HTTP 入口
// 由 binding max=100 拦截；服务层直调与旧客户端仍需同一兜底（SQLite 不强制
// VARCHAR 长度），否则 16KB 注册体可把超长/带换行的名字写进 nodes 并回显。
func NormalizeClusterNodeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.Map(func(r rune) rune {
		// C0、DEL 与 C1（0x80-0x9F）均为控制字符；旧实现漏 C1，注释口径
		// 与行为不一致（历史 历史问题-2）。
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, name)
	name = strings.TrimSpace(name)
	if utf8.RuneCountInString(name) > ClusterNodeNameMaxLen {
		name = string([]rune(name)[:ClusterNodeNameMaxLen])
	}
	return name
}

// ClusterAccessURLHostMatchesIP 判定自述访问地址的主机是否即注册来源 IP
// （历史问题-06 信任边界）：access_url 是能力票据（服务控制/登录票据）的投递
// 地址，注册方自述值只在与来源 IP 一致时可信；其余必须由管理员经节点访问
// 地址端点显式配置，避免已发注册令牌把票据引向任意第三方主机。
func ClusterAccessURLHostMatchesIP(accessURL, ipAddress string) bool {
	if accessURL == "" {
		return true
	}
	parsed, err := url.Parse(accessURL)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	if host == "" {
		return false
	}
	if strings.EqualFold(host, ipAddress) {
		return true
	}
	parsedIP := net.ParseIP(host)
	return parsedIP != nil && parsedIP.Equal(net.ParseIP(ipAddress))
}

// ClusterAccessURLTargetsNode 尽力识别主节点地址是否指向本机监听端口。
// 仅接受明确的 loopback/localhost 或本机出口 IP，不做 DNS 解析；主机别名与
// 反向代理后的自环无法可靠识别，调用方不得把 false 当作安全保证。
func ClusterAccessURLTargetsNode(accessURL, ipAddress string, port int) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	parsed, err := url.Parse(accessURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" {
		return false
	}
	targetPort := parsed.Port()
	if targetPort == "" {
		switch parsed.Scheme {
		case "http":
			targetPort = "80"
		case "https":
			targetPort = "443"
		}
	}
	if targetPort != strconv.Itoa(port) {
		return false
	}
	host := parsed.Hostname()
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return true
	}
	return ClusterAccessURLHostMatchesIP(accessURL, ipAddress)
}

type ClusterLoginTicketRequest struct {
	Ticket string `json:"ticket" binding:"required"`
}

type ClusterLoginTicketClaims struct {
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	NodeID    int    `json:"node_id"`
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"expires_at"`
}

// 集群服务控制动作（主节点 → 从节点）：Caddy 进程启停与应用进程重启。
const (
	ClusterServiceActionStartCaddy   = "start_caddy"
	ClusterServiceActionStopCaddy    = "stop_caddy"
	ClusterServiceActionRestartCaddy = "restart_caddy"
	ClusterServiceActionRestartApp   = "restart_app"
)

// IsValidClusterServiceAction 判定动作是否在受控集合内（主从两侧共用同一口径）。
func IsValidClusterServiceAction(action string) bool {
	switch action {
	case ClusterServiceActionStartCaddy, ClusterServiceActionStopCaddy, ClusterServiceActionRestartCaddy, ClusterServiceActionRestartApp:
		return true
	}
	return false
}

// ClusterNodeServiceRequest 主节点服务控制端点请求体。
type ClusterNodeServiceRequest struct {
	Action string `json:"action" binding:"required"`
}

// ClusterServiceControlRequest 从节点服务控制端点请求体：票据即凭证
// （HMAC-SHA256，密钥为集群令牌哈希，90 秒一次性，与动作绑定）。
type ClusterServiceControlRequest struct {
	Action string `json:"action" binding:"required"`
	Ticket string `json:"ticket" binding:"required"`
	// Operator 是主节点侧实际操作人用户名(经票据保护的转发链传递,从节点
	// 审计记录真实操作人而非「system」;空串回退「主节点」)。
	Operator string `json:"operator,omitempty"`
}

// ClusterServiceControlClaims 服务控制票据载荷。
type ClusterServiceControlClaims struct {
	NodeID    int    `json:"node_id"`
	Action    string `json:"action"`
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"expires_at"`
}

// ClusterServiceControlIssue 主节点签发结果：票据 + 目标从节点信息（不跨网络传输）。
type ClusterServiceControlIssue struct {
	Ticket   string
	NodeName string
	URL      string
}

type ClusterLoginTicketResponse struct {
	Ticket string `json:"ticket"`
	URL    string `json:"url"`
	// NodeName 仅供主端本地使用(审计事件带节点名),不随响应下发。
	NodeName string `json:"-"`
}

type ClusterModeRequest struct {
	Mode          string `json:"mode" binding:"required,oneof=master slave"`
	MasterURL     string `json:"master_url"`
	RegisterToken string `json:"register_token"`
	NodeName      string `json:"node_name" binding:"omitempty,max=100"`
}

type ClusterSettingsRequest struct {
	// SyncInterval 范围校验（10-86400）在 ClusterService.UpdateSettings 完成，
	// 以便返回「同步间隔需在 10-86400 秒之间」的具体文案；binding 层不再拦截（历史问题 发现1）。
	// 三分类合并(2026-09-19):sync_global_config/sync_waf_files 字段随开关
	// 列删除(全局配置并入系统数据、规则库并入安全防护)。
	SyncInterval *int  `json:"sync_interval"`
	SyncUsers    *bool `json:"sync_users"`
	SyncRules    *bool `json:"sync_rules"`
	SyncSecurity *bool `json:"sync_security"`
}

type ClusterRegistration struct {
	RegistrationID     int    `json:"registration_id"`
	RegistrationSecret string `json:"registration_secret"`
	// OverwrittenNodeID/OverwrittenNodeName 在重复 ip:port 注册命中「已批准」
	// 节点时回填（历史问题，历史）：upsert 是既有兼容路径，但静默重置审批
	// 与令牌会让运营方误以为是新节点——响应与审计必须点名被覆盖的节点。
	OverwrittenNodeID   int    `json:"overwritten_node_id,omitempty"`
	OverwrittenNodeName string `json:"overwritten_node_name,omitempty"`
	// AccessURLIgnored 表示注册请求自述的 access_url 与来源 IP 不一致而被忽略
	// （历史问题-06：access_url 是能力票据投递地址，只接受与注册来源一致的
	// 自述值；其余必须由管理员经节点访问地址端点显式配置）。
	AccessURLIgnored bool `json:"access_url_ignored,omitempty"`
}

type ClusterRegistrationStatus struct {
	Status       string `json:"status"`
	ClusterToken string `json:"cluster_token,omitempty"`
}

type SyncErrorCode string

const (
	SyncErrorCodeSchemaTooNew     SyncErrorCode = "schema_too_new"
	SyncErrorCodeSchemaTooOld     SyncErrorCode = "schema_too_old"
	SyncErrorCodeSignatureInvalid SyncErrorCode = "signature_invalid"
	SyncErrorCodePinMismatch      SyncErrorCode = "pin_mismatch"
	SyncErrorCodeValidationFailed SyncErrorCode = "validation_failed"
	SyncErrorCodeApplyFailed      SyncErrorCode = "apply_failed"
	SyncErrorCodeTransportError   SyncErrorCode = "transport_error"
)

type ClusterHealth struct {
	CaddyOK          bool          `json:"caddy_ok"`
	RulesCount       int           `json:"rules_count"`
	CertsExpiring30d int           `json:"certs_expiring_30d"`
	LastSyncAt       string        `json:"last_sync_at"`
	LastSyncError    string        `json:"last_sync_error"`
	SyncErrorCode    SyncErrorCode `json:"sync_error_code,omitempty"`
	UptimeSec        int64         `json:"uptime_sec"`
	// v2.3.0(2026-09-18 用户裁定):从节点规则库版本随上报上送——主节点集群
	// 管理节点列表状态列 hover 可见,替代登录从节点查看。
	CRSVersion   string `json:"crs_version,omitempty"`
	IP2RegionTag string `json:"ip2region_version,omitempty"`
}

type ClusterReport struct {
	AppliedVersion int `json:"applied_version" binding:"min=0"`
	// ServiceStatus 保留（历史 历史问题 裁定：有意设计-保留）：主节点
	// 当前不消费该字段（cluster_status.go 的节点视图不读它，前端亦无渲染点），
	// 但 binding 强校验仍要求从节点上报 ok/degraded。删除会破坏旧主/旧从
	// 滚动升级期的上报契约（旧主节点对缺字段的绑定校验直接 400），故保留到
	// 协议版本升级时再清理。
	ServiceStatus string        `json:"service_status" binding:"required,oneof=ok degraded"`
	Health        ClusterHealth `json:"health"`
	LastSyncAt    string        `json:"last_sync_at"`
	LastSyncError string        `json:"last_sync_error"`
	SyncErrorCode SyncErrorCode `json:"sync_error_code,omitempty" binding:"omitempty,oneof=schema_too_new schema_too_old signature_invalid pin_mismatch validation_failed apply_failed transport_error"`
	// SectionHashes 携带从节点 cluster_applied_sections 的已应用节哈希（本地
	// 当前已落库口径），供主节点聚合 per-section 同步状态。旧版本从节点不上
	// 报（nil，omitempty 省略字段），主节点据此展示「旧版本从节点」占位。
	SectionHashes map[string]string `json:"section_hashes,omitempty"`
	// Detached 为真表示从节点已提升脱离，请求主节点删除本节点记录（令牌随行撤销）。
	Detached bool `json:"detached"`
}

// ClusterSectionSyncStatus 是主节点状态端点聚合的单个同步节比对结果：
// Hash 为从节点上报的本地哈希，MasterHash 为主节点自身快照节哈希，
// Synced 仅在两者非空且一致时为真（从节点缺记录按滞后处理）。
type ClusterSectionSyncStatus struct {
	Section    string `json:"section"`
	Label      string `json:"label"`
	Hash       string `json:"hash"`
	MasterHash string `json:"master_hash"`
	Synced     bool   `json:"synced"`
}

type ClusterBasicSettings struct {
	LogLevel *string `json:"log_level,omitempty"`
	// BrandingJSON 是主节点 branding.json 原文镜像(2026-09-11 裁定):随
	// 快照下发,从节点落盘本地文件后生效。三分类合并后随系统数据节
	// (恒同步)恒携带。指针区分旧主端缺席与显式空串。
	BrandingJSON         *string `json:"branding_json,omitempty"`
	AccessLogJSON        *bool   `json:"access_log_json,omitempty"`
	AccessLogFormat      *string `json:"access_log_format,omitempty"`
	TaskLogSizeMB        *int    `json:"task_log_size_mb,omitempty"`
	AuditLogSizeMB       *int    `json:"audit_log_size_mb,omitempty"`
	RuntimeLogSizeMB     *int    `json:"runtime_log_size_mb,omitempty"`
	AuditRetentionMonths *int    `json:"audit_retention_months,omitempty"`
	// v2.3.8 安全事件保留与流量采样：随 users 节同步（从节点/升主后
	// 保留策略与大屏采样口径与主节点一致）；指针+omitempty 用于旧主端
	// 快照缺席时保留从端本地值。ThreatTrafficSampleN：-1=自适应 / 0=关闭 /
	// 1=全量（历史契约）——固定 2..64 已废除，旧主端快照携带的 2..64
	// 由从端读侧/迁移归 -1。
	SecurityEventsRetentionDays *int    `json:"security_events_retention_days,omitempty"`
	SecurityEventsRowCap        *int    `json:"security_events_row_cap,omitempty"`
	ThreatTrafficSampleN        *int    `json:"threat_traffic_sample_n,omitempty"`
	JWTExpireMinutes            *int    `json:"jwt_expire_minutes,omitempty"`
	Timezone                    *string `json:"timezone,omitempty"`
	ACMEEmail                   *string `json:"acme_email,omitempty"`
	CertExpiryDays              *int    `json:"cert_expiry_days,omitempty"`
	CertRenewalDays             *int    `json:"cert_renewal_days,omitempty"`
	CertRenewalAttempts         *int    `json:"cert_renewal_attempts,omitempty"`
	DefaultCAProviderID         *int    `json:"default_ca_provider_id,omitempty"`
	DNSProvider                 *string `json:"dns_provider,omitempty"`
	DNSCredentials              *string `json:"dns_credentials,omitempty"`
	SyncInterval                *int    `json:"sync_interval,omitempty"`
	CaddyLogLevel               *string `json:"caddy_log_level,omitempty"`
	CaddyLogSizeMB              *int    `json:"caddy_log_size_mb,omitempty"`
	RequestBodyMaxSizeMB        *int    `json:"request_body_max_size_mb,omitempty"`
	HTTPReadTimeout             *int    `json:"http_read_timeout,omitempty"`
	HTTPWriteTimeout            *int    `json:"http_write_timeout,omitempty"`
	HTTPIdleTimeout             *int    `json:"http_idle_timeout,omitempty"`
	UpstreamKeepaliveTimeout    *int    `json:"upstream_keepalive_timeout,omitempty"`
	ProxyDialTimeout            *int    `json:"proxy_dial_timeout,omitempty"`
	ProxyResponseHeaderTimeout  *int    `json:"proxy_response_header_timeout,omitempty"`
	ProxyReadTimeout            *int    `json:"proxy_read_timeout,omitempty"`
	ProxyWriteTimeout           *int    `json:"proxy_write_timeout,omitempty"`
	ProxyStreamTimeout          *int    `json:"proxy_stream_timeout,omitempty"`
	ProxyFlushInterval          *int    `json:"proxy_flush_interval,omitempty"`
	ProxyStreamCloseDelay       *int    `json:"proxy_stream_close_delay,omitempty"`
	GitHubProxyURL              *string `json:"github_proxy_url,omitempty"`
	ServerTokensHidden          *bool   `json:"server_tokens_hidden,omitempty"`
	// v2.3.x 受信代理（CDN 真实 IP）：随 Caddy 全局轴同步——从节点渲染层
	// （servers.trusted_proxies）与数据面取值与主节点一致。range_refs 为
	// 引用的 IP 地址列表 id（JSON 数组文本，2026-10-12），引用的名单本体
	// 在 security 节同步——从端渲染同样投影（tp.txt/lb_file 热路径，2026-10-15）。
	TrustedProxyEnabled   *bool   `json:"trusted_proxy_enabled,omitempty"`
	TrustedProxyRanges    *string `json:"trusted_proxy_ranges,omitempty"`
	TrustedProxyRangeRefs *string `json:"trusted_proxy_range_refs,omitempty"`
	TrustedProxyHeaders   *string `json:"trusted_proxy_headers,omitempty"`
	TrustedProxyStrict    *bool   `json:"trusted_proxy_strict,omitempty"`
	AdminTLSEnabled       *bool   `json:"admin_tls_enabled,omitempty"`
	AdminTLSMode          *string `json:"admin_tls_mode,omitempty"`
	AdminTLSCert          *string `json:"admin_tls_cert,omitempty"`
	AdminTLSKey           *string `json:"admin_tls_key,omitempty"`
	// v2.1.8 MFA 全局开关（决策3：从节点行为与主节点一致）。
	MFAWriteGuard *bool `json:"mfa_write_guard,omitempty"`
	// v2.3.0:OIDC 配置(原样 JSON 字符串)随 global 节同步——从节点回调独立
	// 闭环需要本地可读 issuer/client 凭证(JWKS 验签在从节点本地完成)。
	OIDCConfig        *string `json:"oidc_config,omitempty"`
	MFALockoutEnabled *bool   `json:"mfa_lockout_enabled,omitempty"`
	// v2.3.x 历史问题:自动备份设置随 users 节同步——从节点提升为主节点后调度
	// 直接生效,无需重启。指针+omitempty 缺席语义(镜像 branding_json
	// d55a675 偏斜处理):旧主端快照缺该组字段时从端 apply 跳过写入、保留
	// 本地设置,不清零;新主端装载恒非 nil(COALESCE 兜底),快照恒携带。
	// last_run 为节点本地运行态,不在同步列(调度器每次备份推进,入列会让
	// 触发器每轮备份 bump cluster_version)。
	AutoBackupEnabled   *bool   `json:"auto_backup_enabled,omitempty"`
	AutoBackupFrequency *string `json:"auto_backup_frequency,omitempty"`
	AutoBackupTime      *string `json:"auto_backup_time,omitempty"`
	AutoBackupDay       *int    `json:"auto_backup_day,omitempty"`
	AutoBackupKeep      *int    `json:"auto_backup_keep,omitempty"`
	AutoBackupSections  *string `json:"auto_backup_sections,omitempty"`
	// 历史问题-01（历史）：威胁库任务级排程三列随 users 节同步——从节点
	// 提升为主后调度直接生效（镜像 历史问题 自动备份组）。指针+omitempty 缺席
	// 语义：旧主端快照缺该组时从端 apply 跳过写入、保留本地设置，不清零；
	// 新主端装载恒非 nil（COALESCE 兜底），快照恒携带。
	ThreatAutoUpdate   *bool   `json:"threat_auto_update,omitempty"`
	ThreatScheduleDays *string `json:"threat_schedule_days,omitempty"`
	ThreatScheduleTime *string `json:"threat_schedule_time,omitempty"`
	// 爬虫地址库独立总闸与排程三列（与 threat_* 完全分离）。
	CrawlerAutoUpdate   *bool   `json:"crawler_auto_update,omitempty"`
	CrawlerScheduleDays *string `json:"crawler_schedule_days,omitempty"`
	CrawlerScheduleTime *string `json:"crawler_schedule_time,omitempty"`
	// D1（历史）：自动封禁六项配置随 users 节同步——从节点提升为主节点
	// 后调度按主端配置直接生效（镜像 历史问题 自动备份组/历史问题-01 威胁排程组）。
	// 指针+omitempty 缺席语义：旧主端快照缺该组时从端 apply 跳过写入、保留本地
	// 设置，不清零；新主端装载恒非 nil（COALESCE 兜底），快照恒携带。此前六列
	// 不入快照：从端恒默认值（名单传播而配置不传播），升主后按陈旧配置静默运行。
	AutobanEnabled       *bool   `json:"autoban_enabled,omitempty"`
	AutobanThreshold     *int    `json:"autoban_threshold,omitempty"`
	AutobanWindowMinutes *int    `json:"autoban_window_minutes,omitempty"`
	AutobanDuration      *string `json:"autoban_duration,omitempty"`
	AutobanScope         *string `json:"autoban_scope,omitempty"`
	AutobanDryRun        *bool   `json:"autoban_dry_run,omitempty"`
}

type ClusterUser struct {
	ID                int          `json:"id"`
	Username          string       `json:"username"`
	PasswordHash      string       `json:"password_hash"`
	Role              string       `json:"role"`
	DisplayName       string       `json:"display_name"`
	IsEnabled         bool         `json:"is_enabled"`
	PasswordVersion   int64        `json:"password_version"`
	PasswordChangedAt *string      `json:"password_changed_at"`
	CreatedAt         time.Time    `json:"created_at"`
	LastLogin         JSONNullTime `json:"last_login"`
	// v2.1.8 MFA（决策3）：随快照同步——从节点本地验证 TOTP，无需回主节点。
	MFAEnabled       bool   `json:"mfa_enabled"`
	MFASecret        string `json:"mfa_secret"`
	MFARecoveryCodes string `json:"mfa_recovery_codes"`
	MFALastTimestep  int64  `json:"mfa_last_timestep"`
	// v2.3.0 OIDC:身份三列随快照同步——缺列会让从节点把 OIDC 用户当本地账号
	// (空 password_hash 在本地语义=不可登录,OIDC 登录也因 auth_provider 丢失而失效)。
	AuthProvider string `json:"auth_provider,omitempty"`
	OIDCSubject  string `json:"oidc_subject,omitempty"`
	OIDCIssuer   string `json:"oidc_issuer,omitempty"`

	// pending 密钥不跨节点（绑定向导是节点本地交互；半途切换面板属可重做流程）。
}

// ClusterLockedUser 是主节点活跃登录锁的同步载荷（SC-4 修订）：主节点账号被锁
// 状态必须传播到从节点（从节点本地锁定独立生效）。走快照独立顶层载荷
// locked_users 而非 users 节列——login_* 不在 users 触发器快照列/节哈希/漂移
// 守卫内，避免每次登录失败触发 users/api_keys 全量重放与漂移循环。只携带
// 未来时间的活跃锁（与 loginLockedNow 同口径），自然过期后条目自动从快照消失。
type ClusterLockedUser struct {
	Username    string `json:"username"`
	LockedUntil string `json:"locked_until"`
}

type ClusterAPIKey struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	KeyHash        string       `json:"key_hash"`
	KeyPrefix      string       `json:"key_prefix"`
	CreatedBy      int          `json:"created_by"`
	LastUsed       JSONNullTime `json:"last_used"`
	ExpiresAt      string       `json:"expires_at"`
	IsEnabled      bool         `json:"is_enabled"`
	MCPEnabled     bool         `json:"mcp_enabled"`
	ReadOnly       bool         `json:"read_only"`
	MCPIPWhitelist []string     `json:"mcp_ip_whitelist"`
	CreatedAt      time.Time    `json:"created_at"`
}

type ClusterCertificate struct {
	RuleID           string       `json:"rule_id"`
	Domain           string       `json:"domain,omitempty"`
	CertPEM          string       `json:"cert_pem"`
	KeyPEM           string       `json:"key_pem"`
	ExpiresAt        string       `json:"expires_at"`
	CAProviderID     int          `json:"ca_provider_id,omitempty"`
	SourceStatus     string       `json:"source_status,omitempty"`
	RenewalAttempts  int          `json:"renewal_attempts,omitempty"`
	CAAvailableAfter JSONNullTime `json:"ca_available_after"`
	LastErrorCode    string       `json:"last_error_code,omitempty"`
}

type ClusterACMEState struct {
	CAProviders        []CAProvider        `json:"ca_providers"`
	CertificateConfigs []CertificateConfig `json:"certificate_configs"`
	DNSOwnership       json.RawMessage     `json:"dns_ownership"`
}

type ClusterSnapshot struct {
	Version             int                  `json:"version"`
	SchemaVersion       int                  `json:"schema_version,omitempty"`
	MinReaderVersion    int                  `json:"min_reader_version,omitempty"`
	Fingerprint         string               `json:"fingerprint"`
	Signature           string               `json:"signature,omitempty"`
	CanonicalPayload    json.RawMessage      `json:"canonical_payload,omitempty"`
	Rules               []LbRule             `json:"rules"`
	Users               []ClusterUser        `json:"users"`
	APIKeys             []ClusterAPIKey      `json:"api_keys"`
	BasicSettings       ClusterBasicSettings `json:"basic_settings"`
	CaddyConfig         *string              `json:"caddy_config,omitempty"`
	Certs               []ClusterCertificate `json:"certs"`
	ACME                *ClusterACMEState    `json:"acme,omitempty"`
	SecurityPolicies    json.RawMessage      `json:"security_policies,omitempty"`
	SecurityBindings    json.RawMessage      `json:"security_bindings,omitempty"`
	SecurityCustomRules []SecurityCustomRule `json:"security_custom_rules,omitempty"`
	SecurityBlockPages  []SecurityBlockPage  `json:"security_block_pages,omitempty"`
	// SecurityIPLists（v2.3.0）：可复用 IP 地址列表全量 dump（行结构与
	// security_policies 同款 map 形态）；策略 ip_acl_list_refs/
	// ip_whitelist_refs 以 id 引用本表，随 security 节一起全量替换。
	SecurityIPLists          json.RawMessage                   `json:"security_ip_lists,omitempty"`
	SecurityCRSVersion       []ClusterSecurityCRSVersion       `json:"security_crs_version,omitempty"`
	SecurityIP2RegionVersion []ClusterSecurityIP2RegionVersion `json:"security_ip2region_version,omitempty"`
	WafFiles                 *ClusterWafFilesRef               `json:"waf_files,omitempty"`
	// 威胁情报库源行（v2.3.x）：随 security 节同步（多行状态机表，
	// 开关/计数/版本全量镜像）。
	SecurityThreatSources json.RawMessage `json:"security_threat_sources,omitempty"`
	// 爬虫地址库独立源行（v2.3.8）：随 security 节同步，不再借威胁源表通道。
	SecurityCrawlerSources json.RawMessage   `json:"security_crawler_sources,omitempty"`
	SectionHashes          map[string]string `json:"section_hashes,omitempty"`
	// MasterSyncSwitches 为主节点三类同步开关（users/rules/security，2026-09-19
	// 三分类归一；CL-R1 历史修正「五类」陈旧注释），随快照下发；从节点跳过判定
	// 以此为准（从节点本地开关列不参与，避免永远默认全开导致开关失效）。
	MasterSyncSwitches *ClusterSyncSwitchesPayload `json:"master_sync_switches,omitempty"`
	// LockedUsers（SC-4 修订）：主节点活跃登录锁，独立顶层载荷——不参与任何
	// 节哈希/漂移守卫（避免登录失败触发 users 全量重放）；从端只延长不清除。
	// 加性可选字段、omitempty：旧主端缺省 → 从端 no-op；旧从端忽略未知字段
	// （先例：MasterSyncSwitches/WafFiles），故不 bump CurrentSnapshotSchema。
	LockedUsers []ClusterLockedUser `json:"locked_users,omitempty"`
	// NodeSites 为主节点为每个从节点配置的大屏站点坐标（node_id → 坐标）。
	// 从节点按本地 registration_id 取自己的一项应用；加性可选字段，旧从端
	// 忽略未知字段，旧主端缺省时新从端保持本地现值（先例 LockedUsers）。
	NodeSites map[int]ClusterNodeSite `json:"node_sites,omitempty"`
}

// ClusterNodeSite 是单节点的威胁大屏站点坐标（0,0=未设置）。
type ClusterNodeSite struct {
	ServerMapLat float64 `json:"server_map_lat"`
	ServerMapLon float64 `json:"server_map_lon"`
}

// ClusterSyncSwitchesPayload 是主节点同步开关随快照下发的形态(三分类合并
// 后仅 users/rules/security 三键;集群双端同版本升级,不做旧版从节点兼容)。
type ClusterSyncSwitchesPayload struct {
	Users    bool `json:"users"`
	Rules    bool `json:"rules"`
	Security bool `json:"security"`
}

// ClusterWafFilesRef 是快照携带的 WAF 规则文件哈希引用（不含内容）：
// 从节点比对本地哈希，不一致才向主节点 /cluster/sync/waf-files 拉取，
// 规则等 DB 变更引发的快照传输不再搭车 MB 级文件内容。
type ClusterWafFilesRef struct {
	CRSVersion   string `json:"crs_version"`
	CRSSha256    string `json:"crs_sha256"`
	IP2RegionTag string `json:"ip2region_version"`
	IP2RegionSha string `json:"ip2region_sha256"`
	// RDB 文件化：威胁库 .fast 二进制文件哈希（源名 → sha256）
	ThreatSha256s map[string]string `json:"threat_sha256s,omitempty"`
}

// ThreatFileEntry 是单个威胁库 .fast 文件条目（bundle 内嵌传输用）。
type ThreatFileEntry struct {
	Name    string `json:"name"` // 源名（ustc/firehol1/et_compromised）
	Sha256  string `json:"sha256"`
	Content []byte `json:"content,omitempty"` // .fast 二进制内容
}

type ClusterSecurityCRSVersion struct {
	ID           int    `json:"id"`
	Version      string `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
	Trigger      string `json:"trigger"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	// 历史问题-01（历史）：定时更新排程两列随版本行同步（升主即生效）。
	ScheduleDays string `json:"schedule_days"`
	ScheduleTime string `json:"schedule_time"`
}

type ClusterSecurityIP2RegionVersion struct {
	ID           int    `json:"id"`
	Version      string `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
	Trigger      string `json:"trigger"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
	// 历史问题-01（历史）：定时更新排程两列随版本行同步（升主即生效）。
	ScheduleDays string `json:"schedule_days"`
	ScheduleTime string `json:"schedule_time"`
}

func (snapshot ClusterSnapshot) MarshalJSON() ([]byte, error) {
	type snapshotAlias ClusterSnapshot
	if snapshot.SchemaVersion < 3 || len(snapshot.CanonicalPayload) == 0 {
		return json.Marshal(snapshotAlias(snapshot))
	}
	return json.Marshal(struct {
		SchemaVersion    int             `json:"schema_version"`
		MinReaderVersion int             `json:"min_reader_version"`
		Version          int             `json:"version"`
		Fingerprint      string          `json:"fingerprint"`
		Signature        string          `json:"signature"`
		CanonicalPayload json.RawMessage `json:"canonical_payload"`
	}{
		SchemaVersion:    snapshot.SchemaVersion,
		MinReaderVersion: snapshot.MinReaderVersion,
		Version:          snapshot.Version,
		Fingerprint:      snapshot.Fingerprint,
		Signature:        snapshot.Signature,
		CanonicalPayload: snapshot.CanonicalPayload,
	})
}

type ClusterNodeView struct {
	ID              int            `json:"id"`
	Name            string         `json:"name"`
	IPAddress       string         `json:"ip_address"`
	Port            int            `json:"port"`
	Protocol        string         `json:"protocol"`
	AccessURL       string         `json:"access_url"`
	Status          string         `json:"status"`
	IsApproved      bool           `json:"is_approved"`
	ReportedVersion int            `json:"reported_version"`
	CurrentVersion  int            `json:"current_version"`
	Health          *ClusterHealth `json:"health"`
	LastSeen        string         `json:"last_seen"`
	CreatedAt       string         `json:"created_at"`
	ServerMapLat    float64        `json:"server_map_lat"`
	ServerMapLon    float64        `json:"server_map_lon"`
	// SiteInherited 表示该节点未单独配置坐标，当前展示的是主节点默认坐标。
	SiteInherited bool `json:"site_inherited"`
	// SectionSync 为主节点聚合的 per-section 同步状态，仅包含主节点同步开关
	// 开启的节；旧版本从节点无上报时为 nil（JSON 省略），前端展示占位文案。
	SectionSync []ClusterSectionSyncStatus `json:"section_sync,omitempty"`
}

type ClusterStatus struct {
	NodeMode       string        `json:"node_mode"`
	ClusterVersion int           `json:"cluster_version"`
	MasterURL      string        `json:"master_url"`
	SyncInterval   int           `json:"sync_interval"`
	SyncUsers      bool          `json:"sync_users"`
	SyncRules      bool          `json:"sync_rules"`
	SyncSecurity   bool          `json:"sync_security"`
	ClusterActive  bool          `json:"cluster_active"`
	AppliedVersion int           `json:"applied_version"`
	LastSyncAt     string        `json:"last_sync_at"`
	LastSyncError  string        `json:"last_sync_error"`
	SyncErrorCode  SyncErrorCode `json:"sync_error_code,omitempty"`
	PendingCount   int           `json:"pending_count"`
	ApprovedCount  int           `json:"approved_count"`
	// TransportInsecure 表示从节点→主节点链路为明文 HTTP（快照承载证书私钥
	// 与 CA/DNS 凭据、服务控制票据为 Bearer，且 HTTP 下无 TOFU 指纹防护）。
	// 注册时刻的一次性告警之外，UI 据此常驻提示（历史问题-09）。
	TransportInsecure bool `json:"transport_insecure"`
}
