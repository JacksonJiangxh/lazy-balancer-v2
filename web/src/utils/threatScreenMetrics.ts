// 威胁大屏展示指标纯函数
//   - trafficDelta：normal/attack 双桶计数器差分。首轮只建基线（原实现
//     prev=0 → 首帧 delta=进程累计值），QPS 按真实采样间隔计算。
//     计数已是**抽样还原后**的真值（caddygeoip 生产端在
//     1/N 抽样时按 N 累加），前端不得再乘 sample_n（旧实现二次放大，N=8 时
//     QPS/光流最高高估 8 倍）。sample_n 仅用于基线重建判定（抽样比切换时
//     计数口径改变，必须重置基线避免尖峰）。
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
  /** 本轮**归一后**的计数（缺失/非数值已按 0 处理）：调用方必须用它与
   *  `at`/`sampleN` 直接组装下一轮 `TrafficBaseline`，不得再从原始响应重建
   *  （原实现两侧各自归一，原始响应缺字段时基线存 undefined → 差分恒 NaN
   * 静默丢弃该国）。*/
  readonly counts: ReadonlyMap<string, { normal: number; attack: number }>
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
    // 基线中不存在的新国家按 0 起步：计数器快照只包含非零国家，
    // 缺失即基线时刻尚无请求；其当前累计值就是本间隔新增。旧实现 continue
    // 会丢掉每个国家/地区首次出现的请求（慢速流量统计漏计）。
    const before = prev.counts.get(name) ?? { normal: 0, attack: 0 }
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
  if (!prev) return { baseline: true, reset: false, counts, normalDeltas: [], attackDeltas: [], normalTotal: 0, attackTotal: 0, normalQps: 0, attackQps: 0, sampleN: safeSample }
  if (prev.sampleN !== safeSample) reset = true
  if (reset) return { baseline: true, reset: true, counts, normalDeltas: [], attackDeltas: [], normalTotal: 0, attackTotal: 0, normalQps: 0, attackQps: 0, sampleN: safeSample }
  const elapsedSec = (now - prev.at) / 1000
  const normalQps = elapsedSec > 0 ? normalTotal / elapsedSec : 0
  const attackQps = elapsedSec > 0 ? attackTotal / elapsedSec : 0
  return { baseline: false, reset: false, counts, normalDeltas, attackDeltas, normalTotal, attackTotal, normalQps, attackQps, sampleN: safeSample }
}

/** 拦截/分钟展示：后端已是一位小数，UI 用 ×10 整数动画后还原。 */
export function formatRecentRate(raw: number): string {
  if (!Number.isFinite(raw) || raw < 0) return '0.0'
  return (Math.round(raw * 10) / 10).toFixed(1)
}

/**
 * 趋势桶 tooltip：后端槽标签已是最终展示形态（≤24h 为真实 HH:MM，>24h 为
 * MM-DD），不再补 `:00`。非法/缺失标签回退空串。
 */
export function hourlyBucketLabel(name: string): string {
  return typeof name === 'string' ? name : ''
}
