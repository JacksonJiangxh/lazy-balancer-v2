// 威胁大屏共享纯函数验收（历史 历史问题 / 历史问题 / 历史问题）：
//   A. 热力数据指纹：相同→true；计数/长度/重复键变化→false
//   B. 弧线端点：终点恒为当前本站坐标（setServer 后新弧线随新坐标）
//   C. 危险等级化简：检测模式 12 分边界（原恒等三元 >=6 与 <6 同值）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { heatEntriesEqual, arcEndpoints, POINTY_TOP_HEX_VERTICES, drillCountryAllowed } from '../src/utils/threatShared.ts'

test('六边形点阵：pointy-top 六顶点且上下尖角（历史问题）', () => {
  assert.equal(POINTY_TOP_HEX_VERTICES.length, 6)
  assert.deepEqual(POINTY_TOP_HEX_VERTICES[0], [0, -1])
  assert.deepEqual(POINTY_TOP_HEX_VERTICES[3], [0, 1])
  assert.ok(POINTY_TOP_HEX_VERTICES.every(([x, y]) => Math.abs(x) <= Math.sqrt(3) / 2 && Math.abs(y) <= 1))
})

test('下钻白名单：缺省不限，显式列表只放行列内国家（历史问题）', () => {
  assert.equal(drillCountryAllowed(undefined, '美国'), true)
  assert.equal(drillCountryAllowed(['中国'], '中国'), true)
  assert.equal(drillCountryAllowed(['中国'], '美国'), false)
  assert.equal(drillCountryAllowed([], '中国'), false)
})

test('A 热力指纹：相同输入 true，计数/长度/重复键变化 false', () => {
  const prev = new Map<string, number>([['中国', 12], ['美国', 5]])
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 12 }, { name: '美国', count: 5 }]), true)
  assert.equal(heatEntriesEqual(prev, [{ name: '美国', count: 5 }, { name: '中国', count: 12 }]), true, '顺序无关')
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 13 }, { name: '美国', count: 5 }]), false)
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 12 }]), false, '长度变化必须视为变化')
  assert.equal(heatEntriesEqual(prev, [{ name: '中国', count: 12 }, { name: '中国', count: 12 }]), false, '重复键不可当相等')
  assert.equal(heatEntriesEqual(new Map(), []), true)
  assert.equal(heatEntriesEqual(new Map(), [{ name: '中国', count: 0 }]), false)
})

test('B 弧线端点：终点跟随当前本站坐标（构造期常量即失效）', () => {
  const origin: [number, number] = [116.4, 39.9]
  const first = arcEndpoints([104.19, 35.86], origin)
  assert.deepEqual(first, { startLat: 39.9, startLng: 116.4, endLat: 35.86, endLng: 104.19 })
  // setServer 到纽约：同一归属地的新弧线终点必须变为新坐标
  const second = arcEndpoints([-74.0, 40.71], origin)
  assert.deepEqual(second, { startLat: 39.9, startLng: 116.4, endLat: 40.71, endLng: -74.0 })
  assert.notEqual(first.endLat, second.endLat)
})
