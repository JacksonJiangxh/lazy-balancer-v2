/**
 * 导入/还原预览摘要的中文标签单源。
 *
 * 后端校验响应的 summary 以**表名**为键（internal/handlers/config_import_v1.go
 * 遍历 backup.Tables 逐个 len(rows)），表集即 configBackupTables
 * （internal/handlers/config_backup.go）的 18 张表。前端曾只覆盖其中 12 个键，
 * 其余按 `labels[key] || key` 回退——用户会在预览里看到
 * 「security_policies·3」「path_rules·2」这类内部表名，无法判断覆盖范围。
 *
 * 覆盖完整性由 tests/importPreview.spec.ts 跨栈钉住（解析 Go 的
 * configBackupTables 与本节键集比对），新增表时必须同时补标签。
 */
const IMPORT_SUMMARY_LABELS: Readonly<Record<string, string>> = {
  // 负载均衡
  lb_rules: '规则',
  upstreams: '上游',
  path_rules: '自定义路由',
  // 凭证与证书
  users: '用户',
  api_keys: 'API 密钥',
  ca_providers: 'CA 提供商',
  certificate_configs: 'DNS 提供商',
  cert_jobs: '证书任务',
  // 安全防护
  security_policies: '安全策略',
  security_policy_bindings: '策略绑定',
  security_custom_rules: '自定义规则',
  security_block_pages: '拦截页',
  security_ip_lists: 'IP 地址列表',
  security_crs_version: 'CRS 版本',
  security_ip2region_version: 'IP2Region 版本',
  security_threat_sources: '威胁情报源',
  security_crawler_sources: '爬虫地址源',
  // 集群
  nodes: '节点拓扑',
  // 旧版预览的派生键（非表名）：保留以免旧响应回退成英文键
  rules: '规则',
  tls_rules: '其中 TLS 规则',
}

/** 摘要键的中文标签；未知键回退原键（fail-visible：新表未登记时立刻可见）。 */
export const importSummaryLabel = (key: string): string => IMPORT_SUMMARY_LABELS[key] || key
