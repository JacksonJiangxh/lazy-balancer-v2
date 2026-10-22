// 配置值的展示口径单源（前端只做展示归一，不承担写侧兜底）。
// 库值唯一真相：写侧/迁移负责落库默认值，展示层只解释「0=自动」这类显式语义。

/**
 * 安全事件保留天数展示值：0=自动（后端内置默认 90 天，见 db.DefaultSecurityEventsRetentionDays），
 * 其余正数原样展示。此前 BasicSettings 内联 `d > 0 ? d : 90` 属第二份实现。
 */
export function displaySecurityEventsRetentionDays(value: number | null | undefined): number {
  return value !== null && value !== undefined && value > 0 ? value : 90
}

/**
 * 安全事件行数上限展示值：后端写侧合法值域 1..100000000（0 为 legacy 自动
 * 哨兵，启动迁移收敛为显式默认），0=自动（内置默认 1,000,000，
 * db.DefaultSecurityEventsRowCap）。1..999 等小值是合法配置，必须原样展示——
 * 前端不得夹到 1000/1,000,000（静默改值后保存会把导入/API 设置覆盖掉）。
 */
export function displaySecurityEventsRowCap(value: number | null | undefined): number {
  return value !== null && value !== undefined && value > 0 ? value : 1_000_000
}

/**
 * 安全事件保留/行数上限的保存载荷：仅在用户**实际编辑过**时携带
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
