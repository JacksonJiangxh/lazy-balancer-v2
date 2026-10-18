export const buildRuleMetricsUnavailable = (
  rules: ReadonlyArray<{ caddy_id: string; enabled: boolean }>,
  metrics: Readonly<Record<string, unknown>> | null | undefined,
  metricsAvailable: boolean,
): Record<string, boolean> => Object.fromEntries(rules.map((rule) => [
  rule.caddy_id,
  rule.enabled && (!metricsAvailable || metrics?.[rule.caddy_id] === undefined),
]))
