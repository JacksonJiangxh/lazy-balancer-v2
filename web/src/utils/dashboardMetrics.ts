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
  if (options.tcp) return `${TCP_UPSTREAM_GRANULARITY_NOTE}（${options.value}）`
  return options.value
}
