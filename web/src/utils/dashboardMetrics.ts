export const buildRuleMetricsUnavailable = (
  rules: ReadonlyArray<{ caddy_id: string; enabled: boolean }>,
  metrics: Readonly<Record<string, unknown>> | null | undefined,
  metricsAvailable: boolean,
): Record<string, boolean> => Object.fromEntries(rules.map((rule) => [
  rule.caddy_id,
  rule.enabled && (!metricsAvailable || metrics?.[rule.caddy_id] === undefined),
]))

// 问题：TCP 单规则指标按上游地址汇总——caddy-l4（v0.1.2）L4 指标
//（caddy_layer4_proxy_connections_total/active_connections）仅携带 upstream
// 标签，无 server/listener/rule 级标签，引擎层面无法按规则拆分；多条 TCP
// 规则共享同一上游地址时各规则显示同一跨规则合计值。UI 必须明示该口径
// （裁定：不硬造规则级标签）。HTTP/HTTPS 规则由 lb_rule_metrics 插件按
// caddy_id 精确归集，不受影响。
export const TCP_UPSTREAM_GRANULARITY_NOTE = 'TCP 指标按上游地址汇总；多规则共享同一上游地址时为合计值'

// 规则级与全局请求计数来自 Caddy 进程内的 Prometheus registry：每次配置重载
//（/load，任意规则保存/启用/禁用/策略保存/设置变更都会触发）都会重建
// registry → 计数归零。这是 Caddy 自身语义（429 计数与威胁事件计数已在各自
// 位置披露同一口径），但请求总数/规则请求数两处此前未披露——运维会把一次
// 保存后的归零误读为流量中断，或把当前基数当作生命周期累计。
export const METRIC_RELOAD_RESET_NOTE = '自最近一次配置重载以来累计（保存规则/设置触发重载即归零）'

// ruleMetricCellTitle 规则指标单元格 hover 文案单源（请求数/处理中两列共用）：
// 禁用/采集失败优先，TCP 行追加口径明示（值括注保留）。
export const ruleMetricCellTitle = (options: {
  disabled: boolean
  unavailable: boolean
  tcp: boolean
  value: string
}): string => {
  if (options.disabled) return '已禁用'
  if (options.unavailable) return '采集失败'
  if (options.tcp) return `${TCP_UPSTREAM_GRANULARITY_NOTE}；${METRIC_RELOAD_RESET_NOTE}（${options.value}）`
  return `${options.value}；${METRIC_RELOAD_RESET_NOTE}`
}
