// 威胁大屏展示指标纯函数（历史 历史问题/历史问题/历史问题）：
//   - trafficDelta：normal/attack 双桶计数器差分。首轮只建基线（原实现
//     prev=0 → 首帧 delta=进程累计值），QPS 按真实采样间隔计算。
//     历史 历史问题：计数已是**抽样还原后**的真值（caddygeoip 生产端在
//     1/N 抽样时按 N 累加），前端不得再乘 sample_n（旧实现二次放大，N=8 时
//     QPS/光流最高高估 8 倍）。sample_n 仅用于基线重建判定（抽样比切换时
//     计数口径改变，必须重置基线避免尖峰）。
//   - threatIndex：24h 全局事件总量 → 0-100 仪表标尺（展示「事件量指数」，
//     不再宣称风险等级）。

export interface TrafficBaseline {
  readonly counts: ReadonlyMap<string, { normal: number; attack: number }>
  /** 采样时刻（与 now 同源）。 */
  readonly at: number
  /** 本基线对应的 Caddy 抽样比（>1 表示 1/N 抽样）。 */
  readonly sampleN: number
}

export interface TrafficDeltaResult {
  /** 本轮只建立/重建基线（不产生流量增量）。 */
  readonly baseline: boolean
  /** 计数器回退或抽样比变化——曲线应断开并重建基线。 */
  readonly reset: boolean
  readonly normalDeltas: { name: string; count: number }[]
  readonly attackDeltas: { name: string; count: number }[]
  readonly normalTotal: number
  readonly attackTotal: number
  /** 按真实采样间隔折算的每秒请求数（计数已由生产端抽样还原）。 */
  readonly normalQps: number
  readonly attackQps: number
  readonly sampleN: number
}

export function trafficDelta(
  prev: TrafficBaseline | null,
  countries: Record<string, { normal?: number; attack?: number }>,
  now: number,
  sampleN = 1,
): TrafficDeltaResult {
  const safeSample = Number.isFinite(sampleN) && sampleN >= 1 ? sampleN : 1
  const counts = new Map<string, { normal: number; attack: number }>()
  let reset = false
  let normalTotal = 0
  let attackTotal = 0
  const normalDeltas: { name: string; count: number }[] = []
  const attackDeltas: { name: string; count: number }[] = []
  for (const [name, entry] of Object.entries(countries)) {
    const normal = typeof entry?.normal === 'number' && Number.isFinite(entry.normal) ? entry.normal : 0
    const attack = typeof entry?.attack === 'number' && Number.isFinite(entry.attack) ? entry.attack : 0
    counts.set(name, { normal, attack })
    if (!prev) continue
    const before = prev.counts.get(name)
    // 基线中不存在的新国家不计差分：其累计值不是「本间隔内新增」
    if (before === undefined) continue
    const normalDelta = normal - before.normal
    const attackDelta = attack - before.attack
    if (normalDelta < 0 || attackDelta < 0) reset = true
    else {
      if (normalDelta > 0) {
        normalDeltas.push({ name, count: normalDelta })
        normalTotal += normalDelta
      }
      if (attackDelta > 0) {
        attackDeltas.push({ name, count: attackDelta })
        attackTotal += attackDelta
      }
    }
  }
  if (!prev) return { baseline: true, reset: false, normalDeltas: [], attackDeltas: [], normalTotal: 0, attackTotal: 0, normalQps: 0, attackQps: 0, sampleN: safeSample }
  if (prev.sampleN !== safeSample) reset = true
  if (reset) return { baseline: true, reset: true, normalDeltas: [], attackDeltas: [], normalTotal: 0, attackTotal: 0, normalQps: 0, attackQps: 0, sampleN: safeSample }
  const elapsedSec = (now - prev.at) / 1000
  const normalQps = elapsedSec > 0 ? normalTotal / elapsedSec : 0
  const attackQps = elapsedSec > 0 ? attackTotal / elapsedSec : 0
  return { baseline: false, reset: false, normalDeltas, attackDeltas, normalTotal, attackTotal, normalQps, attackQps, sampleN: safeSample }
}

/** 全局事件总量 → 仪表百分比（log 标尺 10 万≈满分，下限 2 避免「有事件但显示 0」）。 */
export function threatIndex(total: number): number {
  if (!Number.isFinite(total) || total <= 0) return 0
  return Math.min(100, Math.max(2, Math.round((Math.log10(total) / 5) * 100)))
}

/** 拦截/分钟展示：后端已是一位小数，UI 用 ×10 整数动画后还原。 */
export function formatRecentRate(raw: number): string {
  if (!Number.isFinite(raw) || raw < 0) return '0.0'
  return (Math.round(raw * 10) / 10).toFixed(1)
}

/**
 * 趋势桶 tooltip：后端槽标签已是最终展示形态（≤24h 为真实 HH:MM，>24h 为
 * MM-DD），不再补 `:00`。窗口参数保留以兼容调用方；非法/缺失标签回退空串。
 */
export function hourlyBucketLabel(name: string, _hours: number): string {
  return typeof name === 'string' ? name : ''
}
