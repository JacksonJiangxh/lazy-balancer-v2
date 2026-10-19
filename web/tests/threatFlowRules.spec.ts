// 光流聚合规则纯函数测试（node --test）：地域 key、秒桶、阈值、弹框/光流共用分组。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  ADAPTIVE_SAMPLE_CONFIRM_SAMPLES,
  ADAPTIVE_SAMPLE_MIN_SWITCH_INTERVAL_MS,
  flowBucket,
  flowBucketKey,
  flowGroupEvents,
  flowRegionKey,
  flowTimestamp,
  isRealtimeFlowEvent,
  nextAdaptiveSampleN,
  nextFlowCursor,
  reconstructObservedRate,
  shouldAggregate,
  stepAdaptiveSample,
  normalizeTrafficSampleN,
} from '../src/utils/threatFlowRules.ts'

test('流量采样配置：仅保留 -1/0/1，固定 2-64 已退役并归一为自适应（历史问题-04/历史问题-历史问题）', () => {
  for (const value of [-1, 0, 1]) assert.equal(normalizeTrafficSampleN(value), value)
  for (const value of [2, 4, 8, 64, -2, 65, 1.5, Number.NaN, undefined, null]) {
    assert.equal(normalizeTrafficSampleN(value), -1, `值 ${String(value)} 必须归一为自适应`)
  }
})

test('自适应档位滞回阈值：1↔4 用 180/120，4↔8 用 720/480（边界值不切换）', () => {
  // 1 → 4：高于 180 才升档
  assert.equal(nextAdaptiveSampleN(1, 180), 1)
  assert.equal(nextAdaptiveSampleN(1, 181), 4)
  // 4 → 1：低于 120 才降档
  assert.equal(nextAdaptiveSampleN(4, 120), 4)
  assert.equal(nextAdaptiveSampleN(4, 119), 1)
  // 4 → 8：高于 720 才升档
  assert.equal(nextAdaptiveSampleN(4, 720), 4)
  assert.equal(nextAdaptiveSampleN(4, 721), 8)
  // 8 → 4：低于 480 才降档
  assert.equal(nextAdaptiveSampleN(8, 480), 8)
  assert.equal(nextAdaptiveSampleN(8, 479), 4)
  // 8 不再升档（最高档即 1/8）
  assert.equal(nextAdaptiveSampleN(8, 1e9), 8)
})

test('自适应切换：连续 2 次采样同向才换档，单次尖峰不生效', () => {
  let state = { active: 1, stable: 0, lastSwitch: 0 }
  let outcome = stepAdaptiveSample(state, 500, 10_000)
  assert.deepEqual(outcome, { active: 1, stable: 1, pendingTarget: 4, lastSwitch: 0, changed: false })
  // 第二次同向 → 换到 1/4
  outcome = stepAdaptiveSample(outcome, 500, 11_000)
  assert.deepEqual(outcome, { active: 4, stable: 0, pendingTarget: 0, lastSwitch: 11_000, changed: true })
  // 单次低速后回到中间带：确认计数清零，不降档
  state = { active: 4, stable: 1, lastSwitch: 0 }
  outcome = stepAdaptiveSample(state, 200, 12_000)
  assert.deepEqual(outcome, { active: 4, stable: 0, pendingTarget: 0, lastSwitch: 0, changed: false })
})

test('自适应切换：两次换档间隔必须 ≥4s（回摆同样受限）', () => {
  const lastSwitch = 20_000
  // 距上次换档不足 4s：即使连续确认也不换
  let outcome = stepAdaptiveSample({ active: 4, stable: 0, lastSwitch }, 900, lastSwitch + 1000)
  assert.equal(outcome.changed, false)
  assert.equal(outcome.stable, 1)
  outcome = stepAdaptiveSample(outcome, 900, lastSwitch + 2000)
  assert.equal(outcome.changed, false, '间隔 2s 未达 4s 门')
  assert.equal(outcome.stable, ADAPTIVE_SAMPLE_CONFIRM_SAMPLES)
  // 达到 4s 门 → 允许换到 1/8
  outcome = stepAdaptiveSample(outcome, 900, lastSwitch + ADAPTIVE_SAMPLE_MIN_SWITCH_INTERVAL_MS)
  assert.deepEqual(outcome, { active: 8, stable: 0, pendingTarget: 0, lastSwitch: lastSwitch + 4000, changed: true })
})

test('自适应切换：档位与目标一致时清空确认计数但保留上次换档时刻', () => {
  const matched = stepAdaptiveSample({ active: 8, stable: 1, lastSwitch: 30_000 }, 900, 31_000)
  assert.deepEqual(matched, { active: 8, stable: 0, pendingTarget: 0, lastSwitch: 30_000, changed: false })
  // 之后转低速：需重新累计 2 次确认且跨过 4s 门
  const first = stepAdaptiveSample(matched, 100, 32_000)
  assert.deepEqual(first, { active: 8, stable: 1, pendingTarget: 4, lastSwitch: 30_000, changed: false })
  const second = stepAdaptiveSample(first, 100, 33_000)
  assert.deepEqual(second, { active: 8, stable: 2, pendingTarget: 4, lastSwitch: 30_000, changed: false }, '间隔不足 4s')
  const third = stepAdaptiveSample(second, 100, 34_000)
  assert.deepEqual(third, { active: 4, stable: 0, pendingTarget: 0, lastSwitch: 34_000, changed: true })
})

test('自适应切换：方向反转不累计（突发+骤停不得直接跳档，WT87-06）', () => {
  // 高流量一次 → 目标 8；随后骤停一次 → 目标 1。旧实现只按次数累加，
  // 在 4s 门已过时会把这两次相反采样当作「连续 2 次同向」直接切到 1/1。
  let outcome = stepAdaptiveSample({ active: 4, stable: 0, lastSwitch: 0 }, 900, 10_000)
  assert.deepEqual(outcome, { active: 4, stable: 1, pendingTarget: 8, lastSwitch: 0, changed: false })
  outcome = stepAdaptiveSample(outcome, 100, 11_000)
  assert.equal(outcome.changed, false, '方向反转不得换档')
  assert.equal(outcome.active, 4)
  assert.equal(outcome.stable, 1, '确认计数必须从 1 重新累计')
  assert.equal(outcome.pendingTarget, 1)
  // 第二次同向（低）→ 才允许降档
  const confirmed = stepAdaptiveSample(outcome, 100, 12_000)
  assert.deepEqual(confirmed, { active: 1, stable: 0, pendingTarget: 0, lastSwitch: 12_000, changed: true })
})

test('自适应切换：非自适应档位（0=关闭）不参与换档', () => {
  const outcome = stepAdaptiveSample({ active: 0, stable: 0, lastSwitch: 0 }, 10_000, 1_000)
  assert.deepEqual(outcome, { active: 0, stable: 0, lastSwitch: 0, changed: false })
})

test('速率还原：events.length × 服务端 sample_n，sample_n 缺失时回退当前档位', () => {
  assert.equal(reconstructObservedRate(125, 8), 1000, '1/8 档 125 条 = 真实 1000 条/秒')
  assert.equal(reconstructObservedRate(125, 8, 1), 1000)
  assert.equal(reconstructObservedRate(100, 0, 4), 400, '服务端未回报时用当前档位还原')
  assert.equal(reconstructObservedRate(0, 0, 0), 0)
})

test('地域 key：中国精确到省，其他国家/未知归一', () => {
  assert.equal(flowRegionKey('中国·广东省·深圳市'), '中国·广东省')
  assert.equal(flowRegionKey('美国·California'), '美国')
  assert.equal(flowRegionKey(''), '未知')
})

test('时间解析：无时区 DB 时间按 UTC；同一秒归同桶', () => {
  assert.equal(flowTimestamp('2026-10-18 00:00:00'), Date.parse('2026-10-18T00:00:00Z'))
  assert.equal(flowBucket(flowTimestamp('2026-10-18T00:00:00Z')), 1792281600)
  assert.equal(flowBucketKey('中国·广东省', 1792281600), '中国·广东省|1792281600')
})

test('阈值：10 条不聚合，11 条聚合', () => {
  assert.equal(shouldAggregate(10), false)
  assert.equal(shouldAggregate(11), true)
})

test('同地区同秒聚合，跨秒不混合', () => {
  const events = [
    { id: 1, ip_location: '中国·广东省', event_time: '2026-10-18T00:00:00Z', action: 'blocked' },
    { id: 2, ip_location: '中国·广东省', event_time: '2026-10-18T00:00:00Z', action: 'logged' },
    { id: 3, ip_location: '中国·广东省', event_time: '2026-10-18T00:00:01Z', action: 'blocked' },
    { id: 4, ip_location: '美国', event_time: '2026-10-18T00:00:00Z', action: 'blocked' },
  ]
  const groups = flowGroupEvents(events)
  assert.equal(groups.length, 3)
  const gd = groups.find((g) => g.key === '中国·广东省|1792281600')
  assert.ok(gd)
  assert.equal(gd.items.length, 2)
  assert.equal(new Set(gd.items.map((e) => e.action)).size, 2)
})

test('历史问题-5：采集租约重置后游标回零，正常递增与缺失值保持', () => {
  assert.equal(nextFlowCursor(500, { enabled: true, next_seq: 4 }), 0)
  assert.equal(nextFlowCursor(500, { enabled: false, next_seq: 501 }), 0)
  assert.equal(nextFlowCursor(500, { enabled: true, next_seq: 501 }), 501)
  assert.equal(nextFlowCursor(500, { enabled: true, next_seq: 500 }), 500)
  assert.equal(nextFlowCursor(500, { enabled: true }), 500)
})


test('历史问题-03：增量批次动效实时性门——回填/延迟到达的历史事件不得冒充实时攻击', () => {
  const now = Date.parse('2026-10-19T12:00:00Z')
  // 新鲜：2 分钟前 / 边界 5 分钟前
  assert.equal(isRealtimeFlowEvent('2026-10-19 11:58:00', now), true)
  assert.equal(isRealtimeFlowEvent('2026-10-19 11:55:00', now), true)
  // 陈旧：5 分 1 秒前 / 数小时前（轮转回填）
  assert.equal(isRealtimeFlowEvent('2026-10-19 11:54:59', now), false)
  assert.equal(isRealtimeFlowEvent('2026-10-19 03:00:00', now), false)
  // 无法解析的时间不得绘制为实时
  assert.equal(isRealtimeFlowEvent('', now), false)
  assert.equal(isRealtimeFlowEvent(undefined, now), false)
  assert.equal(isRealtimeFlowEvent('not-a-date', now), false)
  // RFC3339 与 DB 墙钟串同口径（均按 UTC）
  assert.equal(isRealtimeFlowEvent('2026-10-19T11:59:30Z', now), true)
})
