// 安全策略保存载荷组装（单源纯函数）。
//
// 载荷组装原先内联在 SecurityPolicies.handleSave，只能靠源码文本钉；
// 字段语义（阶段外字段裁剪、引用列表随开关释放、stage0 信任恒启用、空名单保留）
// 都是后端契约，抽成纯函数后由 policyPayload.spec.ts 行为钉住。
//
// 契约要点（与 internal/models/security.go UpdateSecurityPolicyRequest 对齐）：
//  - 显式 policy_type 提交后服务端把阶段外字段归一为零值；mixed 不显式提交
//  （兼容组仅存量可编辑，省略=后端按内容推断）。
//  - ip_acl_list_refs / ip_whitelist_refs 随开关释放（'[]'）——开关关闭时引用列表
//    的真实占用必须释放，否则列表页引用数虚高且阻塞删除；内联名单保留不丢数据。
//  - geoip_enabled 是编辑器本地派生开关，后端无此字段，不下发；geoip_mode 关闭时
//    提交 'off'（后端零发射）。
//  - 空名单不清空（关闭开关再打开不丢配置）。

export interface PolicyPayloadInput {
  name: string
  description: string
  enabled: boolean
  mode: string
  anomalyThreshold: number
  ipAclEnabled: boolean
  ipAclMode: string
  ipAclList: readonly string[]
  ipAclListRefs: readonly number[]
  ipWhitelist: readonly string[]
  ipWhitelistRefs: readonly number[]
  /** 编辑器三态开关（stage0 恒启用——见 policyType 分支） */
  ipWhitelistEnabled: boolean
  rateLimitEnabled: boolean
  rateLimitRps: number
  rateLimitBurst: number
  crsRuleGroups: readonly string[]
  /** 已归一（去空行/去重/按 scope 剥离残留）的排除规则对象数组 */
  crsExcludedRules: readonly unknown[]
  customRuleIds: readonly number[]
  blockPageId: number
  blockStatusCode: number
  geoipCountries: readonly string[]
  geoipEnabled: boolean
  /** geoip_enabled 为真时提交的生效模式（deny/allow；'off' 归一为 deny） */
  geoipMode: string
  geoipCrawlerExempt: boolean
  geoipCrawlerEngines: readonly string[]
  wafCheckResponse: boolean
  logRequestBody: boolean
  trustDetection: boolean
  /** 编辑器类型（mixed 不显式提交） */
  policyType: string
}

export interface PolicyPayload {
  name: string
  description: string
  enabled: boolean
  mode: string
  anomaly_threshold: number
  ip_acl_enabled: boolean
  ip_acl_mode: string
  ip_acl_list: string
  ip_whitelist: string
  ip_whitelist_enabled: boolean
  ip_acl_list_refs: string
  ip_whitelist_refs: string
  rate_limit_enabled: boolean
  rate_limit_rps: number
  rate_limit_burst: number
  crs_rule_groups: string
  crs_excluded_rules: string
  custom_rules: string
  block_page_id: number
  block_status_code: number
  geoip_countries: string
  geoip_mode: string
  geoip_crawler_exempt: boolean
  geoip_crawler_engines: string
  waf_check_response: boolean
  log_request_body: boolean
  trust_detection: boolean
  policy_type?: string
}

export const buildPolicyPayload = (input: PolicyPayloadInput): PolicyPayload => {
  const trustAlwaysEnabled = input.policyType === 'stage0'
  const trustEnabled = trustAlwaysEnabled || input.ipWhitelistEnabled
  return {
    name: input.name,
    description: input.description,
    enabled: input.enabled,
    mode: input.mode,
    anomaly_threshold: input.anomalyThreshold,
    ip_acl_enabled: input.ipAclEnabled,
    ip_acl_mode: input.ipAclMode,
    ip_acl_list: JSON.stringify(input.ipAclList),
    ip_whitelist: JSON.stringify(input.ipWhitelist),
    // 阶段 0 信任名单策略：名单非空即生效（恒启用）；其余类型按开关三态语义
    ip_whitelist_enabled: trustEnabled,
    // 开关关闭即释放引用（共享列表的占用可见性；内联名单按三态语义保留）
    ip_acl_list_refs: input.ipAclEnabled ? JSON.stringify(input.ipAclListRefs) : '[]',
    ip_whitelist_refs: trustEnabled ? JSON.stringify(input.ipWhitelistRefs) : '[]',
    rate_limit_enabled: input.rateLimitEnabled,
    rate_limit_rps: input.rateLimitRps,
    rate_limit_burst: input.rateLimitBurst,
    crs_rule_groups: JSON.stringify(input.crsRuleGroups),
    crs_excluded_rules: JSON.stringify(input.crsExcludedRules),
    custom_rules: JSON.stringify(input.customRuleIds),
    block_page_id: input.blockPageId,
    block_status_code: input.blockStatusCode,
    geoip_countries: JSON.stringify(input.geoipCountries),
    // geoip_enabled=false → 'off'（后端零发射）；开启但模式为 off 的中间态归一为 deny
    geoip_mode: input.geoipEnabled ? (input.geoipMode === 'off' ? 'deny' : input.geoipMode) : 'off',
    geoip_crawler_exempt: input.geoipEnabled && input.geoipCrawlerExempt,
    geoip_crawler_engines: JSON.stringify(input.geoipCrawlerEngines),
    waf_check_response: input.wafCheckResponse,
    log_request_body: input.logRequestBody,
    // 阶段 0：保留检测记录开关（false=直通上游零安全事件；true=事件动作=检测）
    trust_detection: input.trustDetection,
    // mixed 不允许显式提交（省略=后端按内容推断）
    policy_type: input.policyType === 'mixed' ? undefined : input.policyType,
  }
}

/**
 * 爬虫豁免「空引擎」守卫。
 *
 * 后端渲染器 `crawlerEngineSelected` 对空集返回 true（空集 = 全部引擎，为兼容
 * 存量不允许改语义：internal/services/caddy.go）；而 UI 复选框「全不选」的直觉
 * 语义是「不豁免任何引擎」。两者相反——豁免开启且未勾选任何引擎时必须阻断保存，
 * 否则用户以为已收紧、实际放宽到全部 15 个引擎。
 *
 * 返回 true 表示该形态不可保存。
 */
export const crawlerExemptionNeedsEngines = (state: {
  geoipEnabled: boolean
  crawlerExempt: boolean
  engines: readonly string[]
}): boolean => state.geoipEnabled && state.crawlerExempt && state.engines.length === 0
