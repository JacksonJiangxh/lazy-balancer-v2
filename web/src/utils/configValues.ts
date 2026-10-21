// 配置值的展示口径单源（前端只做展示归一，不承担写侧兜底）。
// 库值唯一真相：写侧/迁移负责落库默认值，展示层只解释「0=自动」这类显式语义。

/**
 * 安全事件行数上限展示值（历史问题-07）：后端合法值域 0..100000000，
 * 0=自动（内置默认 1,000,000）。1..999 等小值是合法配置，必须原样展示——
 * 前端不得夹到 1000/1,000,000（静默改值后保存会把导入/API 设置覆盖掉）。
 */
export function displaySecurityEventsRowCap(value: number | null | undefined): number {
  return value !== null && value !== undefined && value > 0 ? value : 1_000_000
}

/**
 * 安全事件保留/行数上限的保存载荷（历史问题-05）：仅在用户**实际编辑过**时携带
 * 该字段。库值 0=自动 是合法哨兵，展示层归一会把 0 显示为 90 天 / 1,000,000 行；
 * 若无条件随保存回传，任何一次基础设置保存都会把展示归一值物化进库（丢失自动
 * 哨兵，内置默认调整后不再跟随）。未编辑 → 省略键，后端 COALESCE 保持现值。
 */
export function securityEventsWritePayload(input: {
  retentionDays: number
  retentionDirty: boolean
  rowCap: number
  rowCapDirty: boolean
}): { security_events_retention_days?: number; security_events_row_cap?: number } {
  return {
    ...(input.retentionDirty ? { security_events_retention_days: input.retentionDays } : {}),
    ...(input.rowCapDirty ? { security_events_row_cap: input.rowCap } : {}),
  }
}
