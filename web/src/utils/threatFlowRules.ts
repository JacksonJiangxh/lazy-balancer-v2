// 威胁大屏光流/弹框聚合单源（纯函数，node:test 可覆盖）。
// 口径：攻击类型不区分，只按地域；中国精确到省；同一地区同一秒为一桶。
import { FLOW_AGGREGATE_THRESHOLD } from './threatTheme.ts'

export interface FlowGroup<T> {
  /** 聚合地域 key（中国精确到省，其余国家） */
  region: string
  /** 秒级时间桶（Unix 秒） */
  bucket: number
  /** region|bucket，供 Map 去重 */
  key: string
  items: T[]
}

/** DB datetime 无时区时按 UTC 解析（与 utils/date.ts 同口径）。 */
export function flowTimestamp(value: string): number {
  if (!value) return NaN
  const s = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(value) ? `${value.replace(' ', 'T')}Z` : value
  const t = Date.parse(s)
  return Number.isFinite(t) ? t : NaN
}

/** 增量批次动效（流光/弹框）的实时性上限（历史问题-03）：入库延迟/轮转回填会把
 *  数小时前的事件塞进增量批次，直接绘制会表现为「正在发生」。列表仍按窗口展示。 */
export const FLOW_REALTIME_MAX_AGE_MS = 5 * 60_000

/** 攻击只按地域聚合；中国精确到省（地图/地球同一口径）。 */
export function flowRegionKey(ipLocation: string | undefined): string {
  if (!ipLocation) return '未知'
  const [country, province] = ipLocation.split('·')
  if (!country) return '未知'
  if (country === '中国' && province) return `${country}·${province}`
  return country
}

export function flowBucket(ts: number, now = Date.now()): number {
  return Number.isFinite(ts) ? Math.floor(ts / 1000) : Math.floor(now / 1000)
}

export function flowBucketKey(region: string, bucket: number): string {
  return `${region}|${bucket}`
}

/**
 * 后端采样契约：-1=自适应、0=关闭逐请求光流。全量档已退役（自适应本身从
 * 1/1 起步，低流量等价全量）；存量/外来 1 与固定 2-64 一律归一为自适应。
 */
export function normalizeTrafficSampleN(value: number | null | undefined): number {
  return value === 0 ? 0 : -1
}

/** 序号回退或采集关闭表示租约/事件缓冲区已重置；下轮必须从 0 重新追赶。 */
export function nextFlowCursor(previous: number, data: { enabled?: boolean; next_seq?: number }): number {
  if (!data.enabled) return 0
  if (typeof data.next_seq === 'number' && data.next_seq < previous) return 0
  return typeof data.next_seq === 'number' ? data.next_seq : previous
}

/** 自适应档位取值集合（1/4/8）曾是零消费导出常量，A85WA-历史问题 移除；
 *  档位语义由 nextAdaptiveSampleN/stepAdaptiveSample 承载。 */

/**
 * 自适应切换阈值（事件/秒，用服务端 sample_n 还原后的真实速率）：
 * 1→4 高于 180、4→1 低于 120；4→8 高于 720、8→4 低于 480。
 * 上下阈值留滞回带，避免在边界附近来回抖动。
 */
export const ADAPTIVE_SAMPLE_THRESHOLDS = {
  upTo4: 180,
  downTo1: 120,
  upTo8: 720,
  downTo4: 480,
} as const

/** 连续多少次采样同向才允许换档（配合 1s 轮询）。 */
export const ADAPTIVE_SAMPLE_CONFIRM_SAMPLES = 2
/** 两次换档之间的最小间隔（毫秒）。 */
export const ADAPTIVE_SAMPLE_MIN_SWITCH_INTERVAL_MS = 4000

/** 用服务端回报的采样因子还原真实事件速率（events 已被按 sample_n 缩小）。 */
export function reconstructObservedRate(eventCount: number, sampleN: number, fallbackSampleN = 1): number {
  const factor = sampleN > 0 ? sampleN : fallbackSampleN > 0 ? fallbackSampleN : 1
  return eventCount * factor
}

/** 自适应目标档位（含滞回带）：仅返回 1/4/8。 */
export function nextAdaptiveSampleN(current: number, observedRate: number): number {
  if (current === 8) return observedRate < ADAPTIVE_SAMPLE_THRESHOLDS.downTo4 ? 4 : 8
  if (current === 4) {
    if (observedRate > ADAPTIVE_SAMPLE_THRESHOLDS.upTo8) return 8
    if (observedRate < ADAPTIVE_SAMPLE_THRESHOLDS.downTo1) return 1
    return 4
  }
  return observedRate > ADAPTIVE_SAMPLE_THRESHOLDS.upTo4 ? 4 : 1
}

export interface AdaptiveSampleState {
  /** 当前生效档位（1/4/8） */
  active: number
  /** 已连续确认的**同一目标**采样次数 */
  stable: number
  /** 上次换档时刻（ms；0=尚未换过档） */
  lastSwitch: number
  /** 正在累计确认的目标档位（0=尚未累计）。目标变化即视为方向反转，计数重来。 */
  pendingTarget?: number
}

export interface AdaptiveSampleOutcome extends AdaptiveSampleState {
  changed: boolean
}

/**
 * 自适应采样单步状态机：连续 2 次采样**同向**且距上次换档 ≥4s 才换档。
 * 同向=两次采样算出的目标档位一致（`pendingTarget`）；目标改变（含高→低反转）
 * 时确认计数从 1 重新累计——只按次数累加会把「突发一次+骤停一次」误判为
 * 连续确认（WT87-06）。目标与当前一致时清空确认计数（但保留上次换档时刻——
 * 回摆同样受 4s 门约束）。
 */
export function stepAdaptiveSample(state: AdaptiveSampleState, observedRate: number, now: number): AdaptiveSampleOutcome {
  if (state.active !== 1 && state.active !== 4 && state.active !== 8) {
    return { ...state, changed: false }
  }
  const target = nextAdaptiveSampleN(state.active, observedRate)
  if (target === state.active) {
    return { active: state.active, stable: 0, pendingTarget: 0, lastSwitch: state.lastSwitch, changed: false }
  }
  const stable = state.pendingTarget === target ? state.stable + 1 : 1
  if (stable >= ADAPTIVE_SAMPLE_CONFIRM_SAMPLES && now - state.lastSwitch >= ADAPTIVE_SAMPLE_MIN_SWITCH_INTERVAL_MS) {
    return { active: target, stable: 0, pendingTarget: 0, lastSwitch: now, changed: true }
  }
  return { active: state.active, stable, pendingTarget: target, lastSwitch: state.lastSwitch, changed: false }
}

/** 正常流事件的最小形状（caddygeoip 事件流）：at 为 Unix 毫秒。 */
export interface NormalFlowLike {
  country?: string
  province?: string
  at?: number
}

/** 正常流与攻击流共用分组：地区键 + 秒桶，跨秒绝不合并。 */
export function groupNormalFlowEvents<T extends NormalFlowLike>(
  events: readonly T[],
  now = Date.now(),
): FlowGroup<T>[] {
  const groups = new Map<string, FlowGroup<T>>()
  for (const event of events) {
    if (!event.country) continue
    const region = flowRegionKey(event.province ? `${event.country}·${event.province}` : event.country)
    const at = typeof event.at === 'number' && Number.isFinite(event.at) && event.at > 0 ? event.at : now
    const bucket = flowBucket(at, now)
    const key = flowBucketKey(region, bucket)
    const group = groups.get(key)
    if (group) group.items.push(event)
    else groups.set(key, { region, bucket, key, items: [event] })
  }
  return [...groups.values()]
}

/** 单轮最多新增光流数；正常流与攻击流共用同一预算。 */
export const FLOW_MAX_ARCS_PER_FLUSH = 12

export interface FlowArcPlan {
  key: string
  /** 弧线 weight（线宽/×N 标签口径）：采样还原后的量级。 */
  weight: number
  /** 是否来自聚合（4-8/ >8）；仅用于语义，不改变引擎线宽。 */
  aggregated: boolean
}

export interface FlowArcGroupLike {
  /** 聚合地域 key（地区+秒桶；洪峰期仅地区）。 */
  key: string
  /** 采样后事件条数；是否聚合只用它判断，不用 weight。 */
  count: number
  /** 还原量级（count × sample_n / sum(weight)）。 */
  weight?: number
}

/**
 * 正常/攻击共用出弧计划：
 * - 1-3 条（采样后）逐条出弧；
 * - 4-8 条合并为一条粗光流；
 * - >8 条合并为一条更粗光流（weight 仍连续，由 flowArcWidth 决定粗细）；
 * - 单轮预算用尽即停止；weight 不参与是否聚合，避免 1/8 采样下 1 条事件
 *   被误判成 8 条而吃掉全部预算。
 */
export function planFlowArcs(
  groups: readonly FlowArcGroupLike[],
  maxArcs = FLOW_MAX_ARCS_PER_FLUSH,
): FlowArcPlan[] {
  const ordered = [...groups].sort((a, b) => (b.weight ?? b.count) - (a.weight ?? a.count) || a.key.localeCompare(b.key))
  const plan: FlowArcPlan[] = []
  let budget = Math.max(0, maxArcs)
  for (const group of ordered) {
    if (budget <= 0) break
    const count = Math.max(0, Math.floor(group.count))
    const weight = group.weight ?? group.count
    if (count <= 0 || weight <= 0) continue
    if (count > FLOW_AGGREGATE_THRESHOLD) {
      plan.push({ key: group.key, weight, aggregated: true })
      budget--
      continue
    }
    const n = Math.min(count, budget)
    const per = weight / count
    for (let i = 0; i < n; i++) plan.push({ key: group.key, weight: per, aggregated: false })
    budget -= n
  }
  return plan
}
