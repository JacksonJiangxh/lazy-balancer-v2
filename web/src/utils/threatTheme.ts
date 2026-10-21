// 威胁大屏光流视觉单源：2D 地图 / 3D 地球 / Vue 图例共用。
// 颜色、线宽、聚合阈值、聚合标签、飞行时长只在这里定义，避免两引擎漂移。

export const FLOW_NORMAL_COLOR = '#38bdf8'
export const FLOW_ATTACK_COLOR = '#e25454'

/** 同一地区同一秒超过 3 条（>=4）才进入聚合出弧；>8 为更粗档。 */
export const FLOW_AGGREGATE_THRESHOLD = 3

/** 单次飞行时长（毫秒）；2D 地图换算为秒，3D 地球直接用作 dash 周期。 */
export const FLOW_FLIGHT_MS = 950

/** 3D 弧线使用 rgba 渐变；与 hex 颜色保持同源。 */
export const FLOW_NORMAL_ARC_COLORS = ['rgba(56, 189, 248, 0.1)', 'rgba(56, 189, 248, 0.85)'] as const
export const FLOW_ATTACK_ARC_COLORS = ['rgba(226, 84, 84, 0.1)', 'rgba(226, 84, 84, 0.95)'] as const

/** 光流线宽档位：采样后 1-3 逐条细、4-8 合并中粗、>8 合并最粗。 */
export type FlowArcTier = 'thin' | 'coarse' | 'dense'

export const FLOW_THIN_ARC_WIDTH = 1.2
export const FLOW_COARSE_ARC_WIDTH = 2.8
export const FLOW_DENSE_ARC_WIDTH = 4.2

export function flowArcTierWidth(tier: FlowArcTier): number {
  if (tier === 'dense') return FLOW_DENSE_ARC_WIDTH
  if (tier === 'coarse') return FLOW_COARSE_ARC_WIDTH
  return FLOW_THIN_ARC_WIDTH
}

/** 聚合标签：聚合弧显示 ×N；逐条弧即使 weight>1 也不显示，避免把采样还原值误读成聚合组。 */
export function flowArcLabel(count: number, aggregated = count > FLOW_AGGREGATE_THRESHOLD): string | undefined {
  return aggregated ? `×${Math.round(count)}` : undefined
}
