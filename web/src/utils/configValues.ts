// 配置值的展示口径单源（前端只做展示归一，不承担写侧兜底）。
// 库值唯一真相：写侧/迁移负责落库默认值，展示层只解释「0=自动」这类显式语义。

/**
 * 证书自动重签天数默认值：与后端 db.DefaultCertRenewalDays 同源（跨栈钉见
 * configValues.spec）。`/config` 未下发或下发 ≤0 时前端按此展示——CertJobs 的
 * 「自动重签时间」列直接由它推导，两侧漂移会让整列日期偏移 N 天。
 */
export const DEFAULT_CERT_RENEWAL_DAYS = 30

/**
 * 证书自动重签天数的写侧上界：与后端 services.CertRenewalDaysMax 同值
 * （90 天规划寿命 − 2 天，见 services/certinfo.go），写侧门/导入钳制/读侧
 * 生效窗口共用该上限。
 *
 * 表单控件必须与写侧门对齐：控件上限窄于写侧门时，API/MCP/导入写入的合法值
 * 会在管理员点一下 spinner/失焦后被静默夹回控件边界并随保存落库——库值被
 * 前端无提示改写。产品上「建议 ≤60」只是建议，写在提示文案里，不作硬上限。
 * 跨栈钉见 configValues.spec。
 */
export const CERT_RENEWAL_DAYS_MAX = 88

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
 * 威胁大屏视觉模式展示值：库值仅 'globe' 有效，其余（含缺失/未知）按 'map'
 * 展示。原三处各自 `=== 'globe' ? 'globe' : 'map'`（设置父模型、基础设置
 * 响应式回填、大屏 /config 读取）属第二/三份实现。
 */
export type ThreatScreenMode = 'map' | 'globe'

export function displayThreatScreenMode(value: string | null | undefined): ThreatScreenMode {
  return value === 'globe' ? 'globe' : 'map'
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
