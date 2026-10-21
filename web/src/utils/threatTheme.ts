// 威胁大屏光流视觉单源：2D 地图 / 3D 地球 / Vue 图例共用。
// 颜色、线宽、聚合阈值、聚合标签、飞行时长、缓动与到站脉冲参数只在这里定义，
// 避免两引擎漂移（历史问题：easeOutCubic/涟漪/浮签字色/地域键四组曾各写一份）。

export const FLOW_NORMAL_COLOR = '#38bdf8'
export const FLOW_ATTACK_COLOR = '#e25454'

/** 同一地区同一秒超过 3 条（>=4）才进入聚合出弧；>8 为更粗档。 */
export const FLOW_AGGREGATE_THRESHOLD = 3

/** 单次飞行时长（毫秒）；2D 地图换算为秒，3D 地球直接用作 dash 周期。 */
export const FLOW_FLIGHT_MS = 950

/** 悬停浮签字色（两引擎同源；历史问题：地图 #e2e8f0 / 地球 #e2ecff 漂移）。 */
export const FLOW_HOVER_TIP_COLOR = '#e2ecff'

/** 光流线宽档位：采样后 1-3 逐条细、4-8 合并中粗、>8 合并最粗。 */
export type FlowArcTier = 'thin' | 'coarse' | 'dense'

const FLOW_THIN_ARC_WIDTH = 1.2
const FLOW_COARSE_ARC_WIDTH = 2.8
const FLOW_DENSE_ARC_WIDTH = 4.2

export function flowArcTierWidth(tier: FlowArcTier): number {
  if (tier === 'dense') return FLOW_DENSE_ARC_WIDTH
  if (tier === 'coarse') return FLOW_COARSE_ARC_WIDTH
  return FLOW_THIN_ARC_WIDTH
}

/** 聚合标签：聚合弧显示 ×N；逐条弧即使 weight>1 也不显示，避免把采样还原值误读成聚合组。 */
export function flowArcLabel(count: number, aggregated = count > FLOW_AGGREGATE_THRESHOLD): string | undefined {
  return aggregated ? `×${Math.round(count)}` : undefined
}

/** 光流头部缓动（两引擎单源；入参钳 0..1，地图/地球同一时间曲线）。 */
export function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - Math.min(1, Math.max(0, t)), 3)
}

/** 到站脉冲参数（两引擎单源）：1.8s 内半径 3→29 线性增长，描边 1.5。 */
export const FLOW_RIPPLE_SECONDS = 1.8
export const FLOW_RIPPLE_START_RADIUS = 3
export const FLOW_RIPPLE_GROWTH_RADIUS = 26
export const FLOW_RIPPLE_LINE_WIDTH = 1.5
export const FLOW_RIPPLE_ALPHA = 0.85
