// 光流聚合规则纯函数测试（node --test）：地域 key、秒桶、阈值、弹框/光流共用分组。
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  flowBucket,
  flowBucketKey,
  flowGroupEvents,
  flowRegionKey,
  flowTimestamp,
  shouldAggregate,
  normalizeTrafficSampleN,
} from '../src/utils/threatFlowRules.ts'

test('流量采样配置：保留后端 -1/0/1/2-64 全契约，拒绝越界与非整数（历史问题）', () => {
  for (const value of [-1, 0, 1, 2, 4, 8, 64]) assert.equal(normalizeTrafficSampleN(value), value)
  for (const value of [-2, 65, 1.5, Number.NaN, undefined, null]) assert.equal(normalizeTrafficSampleN(value), -1)
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
