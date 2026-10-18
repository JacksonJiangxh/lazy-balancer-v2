// 威胁大屏流量/事件量指数纯函数验收：
//   A. trafficDelta 首轮基线、normal/attack 双桶、真实间隔、
//      抽样还原计数不二次放大（历史问题）、计数器回退/抽样比变化、新增国家不尖峰
//   B. threatIndex 单调且 1/2/9/1000 有区分度、0 分不显示进度
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { trafficDelta, threatIndex, formatRecentRate, hourlyBucketLabel, type TrafficBaseline } from '../src/utils/threatScreenMetrics.ts'

function baseline(counts: Record<string, { normal: number; attack?: number }>, at: number, sampleN = 1): TrafficBaseline {
  return {
    counts: new Map(Object.entries(counts).map(([name, v]) => [name, { normal: v.normal, attack: v.attack ?? 0 }])),
    at,
    sampleN,
  }
}

test('A1 首轮只建基线：不产生增量（原实现把进程累计值当首帧 delta）', () => {
  const first = trafficDelta(null, { 中国: { normal: 120000, attack: 30 }, 美国: { normal: 500 } }, 1000)
  assert.equal(first.baseline, true)
  assert.equal(first.normalTotal, 0)
  assert.equal(first.attackTotal, 0)
  assert.equal(first.normalQps, 0)
  assert.deepEqual(first.normalDeltas, [])
  assert.deepEqual(first.attackDeltas, [])
})

test('A2 正常增量按真实间隔折算 QPS（不再恒除 1.5s）', () => {
  const prev = baseline({ 中国: { normal: 100 }, 美国: { normal: 20 } }, 0)
  const at1_5s = trafficDelta(prev, { 中国: { normal: 400 }, 美国: { normal: 50 } }, 1500)
  assert.equal(at1_5s.baseline, false)
  assert.equal(at1_5s.normalTotal, 330)
  assert.equal(at1_5s.normalQps, 220)
  assert.deepEqual(at1_5s.normalDeltas, [{ name: '中国', count: 300 }, { name: '美国', count: 30 }])
  const at300s = trafficDelta(prev, { 中国: { normal: 400 }, 美国: { normal: 50 } }, 300_000)
  assert.equal(at300s.normalQps, 1.1)
})

test('A3 计数器回退：标记 reset 并重建基线，不静默丢负数', () => {
  const prev = baseline({ 中国: { normal: 900 } }, 0)
  const after = trafficDelta(prev, { 中国: { normal: 3 } }, 1500)
  assert.equal(after.reset, true)
  assert.equal(after.baseline, true)
  assert.equal(after.normalTotal, 0)
  assert.deepEqual(after.normalDeltas, [])
})

test('A4 新出现国家不计差分（其累计值不是本间隔新增）', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 0)
  const next = trafficDelta(prev, { 中国: { normal: 110 }, 德国: { normal: 999 } }, 1000)
  assert.equal(next.normalTotal, 10)
  assert.deepEqual(next.normalDeltas, [{ name: '中国', count: 10 }])
})

test('A5 attack 桶独立差分（实时攻击速率不再被丢弃）', () => {
  const prev = baseline({ 中国: { normal: 100, attack: 10 }, 美国: { normal: 20, attack: 1 } }, 0)
  const next = trafficDelta(prev, { 中国: { normal: 160, attack: 18 }, 美国: { normal: 20, attack: 4 } }, 2000)
  assert.equal(next.normalTotal, 60)
  assert.equal(next.attackTotal, 11)
  assert.equal(next.normalQps, 30)
  assert.equal(next.attackQps, 5.5)
  assert.deepEqual(next.attackDeltas, [{ name: '中国', count: 8 }, { name: '美国', count: 3 }])
})

test('A6 抽样计数已是还原值时不得二次乘 sample_n（历史问题）', () => {
  // 生产端 1/N 抽样时每个请求按 N 累加：counter 增量 10 即真实 10 次。
  const prev = baseline({ 中国: { normal: 100 } }, 0, 8)
  const next = trafficDelta(prev, { 中国: { normal: 110 } }, 1000, 8)
  assert.equal(next.normalTotal, 10, '已还原计数不得再乘 8')
  assert.equal(next.normalQps, 10)
  assert.deepEqual(next.normalDeltas, [{ name: '中国', count: 10 }])
})

test('A7 抽样比变化必须重建基线，避免 1↔8 切换尖峰', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 0, 1)
  const next = trafficDelta(prev, { 中国: { normal: 110 } }, 1000, 8)
  assert.equal(next.baseline, true)
  assert.equal(next.reset, true)
  assert.equal(next.normalTotal, 0)
})

test('A8 无间隔（同一时刻重复采样）不除以零', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 500)
  const same = trafficDelta(prev, { 中国: { normal: 120 } }, 500)
  assert.equal(same.normalQps, 0)
})

test('A9 脏值按 0 处理（缺失/非数值不产生 NaN）', () => {
  const prev = baseline({ 中国: { normal: 100 } }, 0)
  const dirty = trafficDelta(prev, { 中国: {} as { normal?: number; attack?: number } }, 1000)
  assert.equal(dirty.reset, true)
  assert.equal(Number.isNaN(dirty.normalQps), false)
  assert.equal(Number.isNaN(dirty.attackQps), false)
})

test('B 事件量指数：0→0、有量下限 2、单调且 1/2/9/1000 可区分', () => {
  assert.equal(threatIndex(0), 0)
  assert.equal(threatIndex(-5), 0)
  const marks = [1, 2, 9, 100, 1000, 10000, 100000]
  const values = marks.map(threatIndex)
  for (let i = 1; i < values.length; i++) {
    assert.ok(values[i] > values[i - 1], `标尺非单调: ${marks[i - 1]}→${values[i - 1]} / ${marks[i]}→${values[i]}`)
  }
  assert.equal(threatIndex(1), 2, '有事件不得显示 0（下限 2）')
  assert.ok(threatIndex(9) > threatIndex(2))
  assert.ok(threatIndex(1000) >= 55, '千次量级应进入中高分区')
  assert.equal(threatIndex(100000), 100)
  assert.equal(threatIndex(1_000_000), 100, '上限钳制 100')
})

test('C 拦截/分钟展示只还原一次 10 倍定点，不再放大', () => {
  assert.equal(formatRecentRate(12.3), '12.3')
  assert.equal(formatRecentRate(0), '0.0')
  assert.equal(formatRecentRate(-1), '0.0')
})

test('D 趋势桶 tooltip 按窗口形态区分小时/日桶', () => {
  assert.equal(hourlyBucketLabel('14:00', 24), '14:00:00')
  assert.equal(hourlyBucketLabel('10-12', 168), '10-12')
})
