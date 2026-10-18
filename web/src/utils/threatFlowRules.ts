// 威胁大屏光流/弹框聚合单源（纯函数，node:test 可覆盖）。
// 口径：攻击类型不区分，只按地域；中国精确到省；同一地区同一秒为一桶。
import { FLOW_AGGREGATE_THRESHOLD } from './threatTheme.ts'

export interface FlowEventLike {
  id?: number
  ip_location?: string
  event_time?: string
  action?: string
}

export interface FlowGroup<T extends FlowEventLike> {
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

export function shouldAggregate(count: number): boolean {
  return count > FLOW_AGGREGATE_THRESHOLD
}

/** 后端采样契约：-1=自适应、0=关闭、1=全量、2-64=固定 1/N。 */
export function normalizeTrafficSampleN(value: number | null | undefined): number {
  return typeof value === 'number' && Number.isInteger(value) && value >= -1 && value <= 64 ? value : -1
}

/** 按 region + 秒桶分组；保持输入顺序，供光流和弹框共同消费。 */
export function flowGroupEvents<T extends FlowEventLike>(events: readonly T[], now = Date.now()): FlowGroup<T>[] {
  const groups = new Map<string, FlowGroup<T>>()
  for (const event of events) {
    const region = flowRegionKey(event.ip_location)
    const bucket = flowBucket(flowTimestamp(event.event_time ?? ''), now)
    const key = flowBucketKey(region, bucket)
    const group = groups.get(key)
    if (group) {
      group.items.push(event)
    } else {
      groups.set(key, { region, bucket, key, items: [event] })
    }
  }
  return [...groups.values()]
}
