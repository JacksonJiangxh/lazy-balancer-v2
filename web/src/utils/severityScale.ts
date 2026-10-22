// anomaly_score 危险等级分档单源：威胁大屏事件定级与事件列表评分着色共用。
//
// 列表原用 ≥15/≥5、大屏用 ≥12/≥6——同一评分两页结论打架。统一为大屏口径
//（2026-10-17 用户裁定：≥12 高 / ≥6 中 / <6 低，检测模式降一级由消费方处理）。

export const ANOMALY_SCORE_HIGH = 12
export const ANOMALY_SCORE_MID = 6

export type AnomalySeverity = 'high' | 'mid' | 'low'

/** 评分 → 三档定级（不含检测模式降级——降级是动作语义，由消费方叠加）。 */
export const anomalySeverity = (score: number): AnomalySeverity =>
  score >= ANOMALY_SCORE_HIGH ? 'high' : score >= ANOMALY_SCORE_MID ? 'mid' : 'low'
