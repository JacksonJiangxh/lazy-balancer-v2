// 威胁大屏光流视觉单源：2D 地图 / 3D 地球 / Vue 图例共用。
// 颜色、线宽、聚合阈值、聚合标签、飞行时长只在这里定义，避免两引擎漂移。

export const FLOW_NORMAL_COLOR = '#38bdf8'
export const FLOW_ATTACK_COLOR = '#e25454'

/** 同一地区同一秒超过该条数才合并为一条加权光流/弹框。 */
export const FLOW_AGGREGATE_THRESHOLD = 10

/** 单次飞行时长（毫秒）；2D 地图换算为秒，3D 地球直接用作 dash 周期。 */
export const FLOW_FLIGHT_MS = 950

/** 3D 弧线使用 rgba 渐变；与 hex 颜色保持同源。 */
export const FLOW_NORMAL_ARC_COLORS = ['rgba(56, 189, 248, 0.1)', 'rgba(56, 189, 248, 0.85)'] as const
export const FLOW_ATTACK_ARC_COLORS = ['rgba(226, 84, 84, 0.1)', 'rgba(226, 84, 84, 0.95)'] as const

/** 普通请求线宽：固定基础 + log 聚合增益。 */
export function flowNormalWidth(count: number): number {
  return 1.2 + Math.min(1.4, Math.log10(Math.max(1, count)))
}

/** 攻击光流线宽：2×(0.6+log)，上限 4。 */
export function flowAttackWidth(count: number): number {
  return Math.min(4, 2 * (0.6 + Math.log10(Math.max(1, count))))
}

/** 聚合标签：仅在超过阈值时显示 ×N。 */
export function flowArcLabel(count: number): string | undefined {
  return count > FLOW_AGGREGATE_THRESHOLD ? `×${Math.round(count)}` : undefined
}
