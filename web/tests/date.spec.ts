// date.ts 行为验收（生产热路径：规则/安全事件/仪表盘/证书任务全部经它格式化）：
//   - DB 墙钟串（UTC 存储）解析 + `+Z` 规范化（Safari `NaN` 回归守卫）
//   - 非 ISO 串原样透传 / 解析失败返回空串（不猜、不抛）
//   - 配置时区格式化（date / short / 图表轴 HH:mm:ss，h23）
//   - 模块级 formatter 缓存（同 时区×形态 只构造一次）
//   - 非法配置时区回退 DEFAULT_TZ 且只 warn 一次
//
// date.ts 依赖 @/stores/auth（pinia 链）。测试用 registerModuleHooks 把它替换为
// 读取 globalThis.__tz 的替身，并把时区格式化模块替换为「计数构造次数」的
// 等价实现（缓存行为可观测）；真实格式化口径由 timeZoneFormat.spec 覆盖。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'

type Harness = { __tz: string; __formatCalls: number }
const g = globalThis as unknown as Harness
g.__tz = 'Asia/Shanghai'
g.__formatCalls = 0

const dataModule = (code: string): string => `data:text/javascript,${encodeURIComponent(code)}`

const stubAuth = dataModule(`
export const useAuthStore = () => ({ timezone: globalThis.__tz })
`)

// 与 utils/timeZoneFormat 等价的实现，额外统计 createTzFormatter 构造次数——
// 用来验证 date.ts 的模块级 formatter 缓存（构造次数不随调用次数增长）。
const countingFormat = dataModule(`
export const DEFAULT_TZ = 'Asia/Shanghai'
export const createTzFormatter = (timeZone, withTime) => {
  globalThis.__formatCalls++
  return new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    ...(withTime ? { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' } : {}),
  })
}
export const formatDateParts = (d, formatter, withTime) => {
  const parts = formatter.formatToParts(d)
  const get = (type) => parts.find((p) => p.type === type)?.value ?? ''
  const date = get('year') + '-' + get('month') + '-' + get('day')
  return withTime ? date + ' ' + get('hour') + ':' + get('minute') + ':' + get('second') : date
}
`)

registerModuleHooks({
  '@/stores/auth': stubAuth,
  '@/utils/timeZoneFormat': countingFormat,
})

const date = await import('../src/utils/date.ts')

test('DB 墙钟串按 UTC 解析（+Z 规范化，Safari NaN 回归守卫）', () => {
  const expected = Date.UTC(2026, 7, 11, 8, 23, 21)
  const parsed = date.parseDbTimeMs('2026-08-11 08:23:21')
  assert.equal(parsed, expected)
  assert.ok(Number.isFinite(parsed), '不得返回 NaN（Safari 裸 new Date 空格格式的回归）')
  // 秒可省略
  assert.equal(date.parseDbTimeMs('2026-08-11 08:23'), Date.UTC(2026, 7, 11, 8, 23))
  // 已带时区的 RFC3339 原样解析（不重复追加 Z）
  assert.equal(date.parseDbTimeMs('2026-08-11T08:23:21Z'), expected)
  assert.equal(date.parseDbTimeMs('2026-08-11T16:23:21+08:00'), expected)
})

test('不可解析/非字符串一律 null（不猜、不抛）', () => {
  for (const value of [null, undefined, '', 'not-a-date', '2026-08-11', 123, {}, []]) {
    assert.equal(date.parseDbTimeMs(value), null, `${JSON.stringify(value)} 应解析失败`)
  }
})

test('formatDate：DB 墙钟串转配置时区；非 ISO 文本原样透传；空值返回空串', () => {
  // 08:23:21Z → Asia/Shanghai 16:23:21
  assert.equal(date.formatDate('2026-08-11 08:23:21'), '2026-08-11 16:23:21')
  // 后端已是人读文本 / 前端已格式化：原样返回，不再当时间解析
  assert.equal(date.formatDate('刚刚'), '刚刚')
  assert.equal(date.formatDate(null), '')
  assert.equal(date.formatDate(undefined), '')
  assert.equal(date.formatDate({}), '')
})

test('formatDateShort：仅日期（配置时区），非 ISO 文本同样透传', () => {
  assert.equal(date.formatDateShort('2026-08-11 16:30:00'), '2026-08-12')
  assert.equal(date.formatDateShort('2026-08-11T01:00:00Z'), '2026-08-11')
  assert.equal(date.formatDateShort('昨天'), '昨天')
  assert.equal(date.formatDateShort(''), '')
})

test('formatChartTimeInConfigTz：h23 的 HH:mm:ss（午夜不显示 24 点）', () => {
  // 2026-01-01T16:05:09Z → 北京 2026-01-02 00:05:09
  assert.equal(date.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 16, 5, 9)), '00:05:09')
  assert.equal(date.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 15, 59, 59)), '23:59:59')
})

test('formatter 缓存：同 时区×形态 只构造一次（轮询高频调用不重复建 Intl）', async () => {
  // 缓存是模块实例状态：独立实例从冷启动验证「首次构造一次、之后命中」。
  const fresh = await import(`../src/utils/date.ts?cache=${Date.now()}`)
  const before = g.__formatCalls
  fresh.formatDate('2026-08-11 08:23:21')
  fresh.formatDate('2026-09-01 00:00:00')
  fresh.formatChartTimeInConfigTz(Date.UTC(2026, 0, 1, 12, 0, 0))
  assert.equal(g.__formatCalls, before + 1, 'withTime 形态首次构造一次、后续命中缓存')

  fresh.formatDateShort('2026-08-11 08:23:21')
  assert.equal(g.__formatCalls, before + 2, 'date-only 形态首次构造一次')
  fresh.formatDateShort('2026-09-01 00:00:00')
  assert.equal(g.__formatCalls, before + 2, 'date-only 形态后续命中缓存')
})

test('非法配置时区：回退 DEFAULT_TZ 且只 warn 一次（不刷屏、不抛）', async () => {
  g.__tz = 'Mars/Olympus'
  const warnings: string[] = []
  const originalWarn = console.warn
  console.warn = (message?: unknown) => { warnings.push(String(message)) }
  try {
    // 模块级 warnedInvalidTz / 缓存是实例状态：独立查询串加载新实例
    const fresh = await import(`../src/utils/date.ts?invalid-tz=${Date.now()}`)
    assert.equal(fresh.formatDate('2026-08-11 08:23:21'), '2026-08-11 16:23:21')
    assert.equal(fresh.formatDate('2026-09-01 00:00:00'), '2026-09-01 08:00:00')
    assert.equal(fresh.formatDateShort('2026-08-11 08:23:21'), '2026-08-11')
    assert.equal(warnings.length, 1, '同一实例只 warn 一次')
    assert.match(warnings[0], /Mars\/Olympus/)
    assert.match(warnings[0], /Asia\/Shanghai/)
  } finally {
    console.warn = originalWarn
    g.__tz = 'Asia/Shanghai'
  }
})
