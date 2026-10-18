// 配置值的展示口径单源（前端只做展示归一，不承担写侧兜底）。
// 库值唯一真相：写侧/迁移负责落库默认值，展示层只解释「0=自动」这类显式语义。

/**
 * 安全事件行数上限展示值（审计 81 历史问题-07）：后端合法值域 0..100000000，
 * 0=自动（内置默认 1,000,000）。1..999 等小值是合法配置，必须原样展示——
 * 前端不得夹到 1000/1,000,000（静默改值后保存会把导入/API 设置覆盖掉）。
 */
export function displaySecurityEventsRowCap(value: number | null | undefined): number {
  return value !== null && value !== undefined && value > 0 ? value : 1_000_000
}
