// 操作日志筛选参数单源：从 AuditLog.vue 抽出的纯函数，便于 node
// 行为测试（原实现内联在 SFC，只能源码钉空转）。
//
// 契约（与 internal/handlers/auditlog.go buildAuditLogFilters 对齐）：
// - 空串/纯空白筛选值不上送（后端对空值不加条件）；
// - 时间范围两端各自独立，仅非空端上送（半开区间可用）；
// - 筛选值两端空白剥离后再上送（后端另有 LIKE 转义）。

interface AuditLogFilterState {
  timeRange: readonly [string, string] | null
  username: string
  action: string
  resource: string
  ip: string
  keyword: string
}

/** 文本筛选键（顺序即上送顺序，保持与既有请求参数外观一致）。 */
const AUDIT_LOG_TEXT_FILTER_KEYS = ['username', 'action', 'resource', 'ip', 'keyword'] as const

export const buildAuditLogParams = (
  filters: AuditLogFilterState,
  page: number,
  pageSize: number,
): Record<string, string | number> => {
  const params: Record<string, string | number> = { page, page_size: pageSize }
  if (filters.timeRange?.[0]) params.start_time = filters.timeRange[0]
  if (filters.timeRange?.[1]) params.end_time = filters.timeRange[1]
  for (const key of AUDIT_LOG_TEXT_FILTER_KEYS) {
    const value = filters[key].trim()
    if (value) params[key] = value
  }
  return params
}
