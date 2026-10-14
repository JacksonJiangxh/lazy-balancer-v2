package services

// 规则传输规范（2026-10-11 用户裁定「如果没有就都应该没有，同步后就应该一致」）：
// 单一事实源 normalizeRuleForTransport——主端快照导出（snapshotRules）、从端快照
// 应用（insertSnapshotRules）、备份导入后置归一共用的规则归一函数。
//
// 历史事故根因：从端 insertSnapshotRules 新增 TCP 七字段归零时，导出侧
// snapshotRules 的平行手写归一块未同步——主端 canonical 与从端落库数据不同形，
// 从端本地重建哈希（56e3）≠主端快照哈希（9855），drifted 分支落本地口径后面板
// 「分区滞后」在版本相同、fingerprint 304 稳态下永不自愈。
// 结构性防治：归一逻辑只此一份，任何消费方（导出/应用/导入）都调它。
//
// 时间戳说明：快照模型时间为 time.Time——主从 DB 字符串（RFC3339 Z / Go time
// +00:00 / SQLite 平面）解析为同一 UTC 时刻后 json.Marshal 输出相同，天然同构；
// DB 存储格式的统一（消除三种并存）由迁移层 normalizeRuleTimestampsMigration
// 与从端写入侧（平面格式直写）承担，与本函数正交。

import (
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// normalizeRuleForTransport 规则传输归一（单一事实源）：
// ① body 上限钳 [0,4096]（历史问题 C-F1）；
// ② TCP+TLS 死形态清除（历史问题 A-N1）；
// ③ TCP 行 HTTP 专属七字段归零（LBH-A-U1 同族，2026-10-11 裁定并入导出侧）。
// ④ 健康检查族/tcp_try_interval 值型列回填（库值唯一真相批 1+2，2026-10-14
//
//	用户裁定）：<=0 归治理默认（db.Default* 常量）——主端带外脏行/旧版本
//	主端快照在传输门归一，三面（导出/从端落库/备份导入）同构，rules 节哈希
//	主从相等的不变量基础；渲染层对这批列已零兜底，脏值不允许越过本门。
//
// 调用方：snapshotRules（主端导出）、insertSnapshotRules（从端落库）、
// 备份导入后置归一——三面同构是 rules 节哈希主从相等的不变量基础。
//
// CORE-2（历史裁定，采用头注声明防重报）：传输族刻意窄于保存族
// （rules.go 保存/更新路径的 TCP 零值化清单还含 tls_source/acme_config_id/
// ca_provider_id/tls_http_redirect 与 stage 拦截页 4 列）——传输/导入/迁移产生
// 的 TCP 行残留这些列已推演为惰性无害：全部 ACME 消费方（签发/续签/证书
// 回插）都以 enable_tls=1 联合门控，而 enable_tls 在本函数与迁移侧恒归 0，
// 残留引用不可达；stage 页 4 列同理仅 HTTP 渲染消费。不为清单收敛而扩面
// （扩面会改变 canonical 哈希基线，触发一轮全量重放），残留列由下次规则
// 编辑经保存族归一自愈。
func normalizeRuleForTransport(rule *models.LbRule) {
	if rule.RequestBodyMaxSizeMB < 0 {
		rule.RequestBodyMaxSizeMB = 0
	} else if rule.RequestBodyMaxSizeMB > 4096 {
		rule.RequestBodyMaxSizeMB = 4096
	}
	// ④ 健康检查族/tcp_try_interval 值型列回填（库值唯一真相批 1+2）：渲染层
	// 零兜底，脏值在传输门归治理默认。仅规范 <=0；用户已设有效值不触碰。
	if rule.HealthCheckInterval <= 0 {
		rule.HealthCheckInterval = db.DefaultHealthCheckInterval
	}
	if rule.HealthCheckTimeout <= 0 {
		rule.HealthCheckTimeout = db.DefaultHealthCheckTimeout
	}
	if rule.HealthCheckUnhealthyThreshold <= 0 {
		rule.HealthCheckUnhealthyThreshold = db.DefaultHealthCheckUnhealthyThreshold
	}
	if rule.HealthCheckHealthyThreshold <= 0 {
		rule.HealthCheckHealthyThreshold = db.DefaultHealthCheckHealthyThreshold
	}
	if rule.TCPTryInterval <= 0 {
		rule.TCPTryInterval = db.DefaultTCPTryInterval
	}
	if rule.Protocol == "tcp" {
		if rule.EnableTLS {
			rule.EnableTLS = false
			rule.TLSCert, rule.TLSKey = "", ""
		}
		// TCP 渲染零消费字段族（buildTCPServer/buildTCPProxyRoute）——
		// 「没有就都应该没有」：主端存储、导出、从端落库三面全零。
		rule.HostHeader = ""
		rule.HealthCheckPath = ""
		rule.EnableCompress = false
		rule.CompressTypes = ""
		rule.RequestBodyMaxSizeMB = 0
		rule.UpstreamKeepaliveTimeout = 0
		rule.ServerTokensHidden = 0
		// NTLM 兼容仅 HTTP 语义（2026-10-12）——与保存族/迁移族同一归一口径。
		rule.NTLMCompatible = 0
		rule.UpstreamForceHTTP1 = 0
	}
}
