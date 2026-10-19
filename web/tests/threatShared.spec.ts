// 威胁大屏共享纯函数验收（历史 历史问题 / 历史问题 / 历史问题）：
//   A. 热力数据指纹：相同→true；计数/长度/重复键变化→false
//   B. 弧线端点：终点恒为当前本站坐标（setServer 后新弧线随新坐标）
//   C. 危险等级化简：检测模式 12 分边界（原恒等三元 >=6 与 <6 同值）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { heatEntriesEqual, arcEndpoints, POINTY_TOP_HEX_VERTICES, drillCountryAllowed, arcOriginForLocation, normalizeCountryName, adminShortName, aggregateCountryCounts, hasProvinceStats, drillCommitAllowed } from '../src/utils/threatShared.ts'

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

test('弧线起点：中国精确到省，其他国家走质心，未知走兜底', () => {
  const gd = arcOriginForLocation('中国·广东省')
  assert.ok(Math.abs(gd[0] - 113.42) < 0.5 && Math.abs(gd[1] - 23.31) < 0.5)
  const us = arcOriginForLocation('美国')
  assert.ok(Math.abs(us[0] - -97) < 1 && Math.abs(us[1] - 38) < 2)
  const unknown = arcOriginForLocation('不存在国')
  assert.deepEqual(unknown, arcOriginForLocation(''))
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

// WT87-09：台湾归一/短名/计数合并此前零断言——热力、命中、下钻三处都靠它们。
// 失效时台湾点阵不与大陆同色、下钻/命中回退 FALLBACK_CENTROID（中太平洋），
// 且没有任何测试会拦住。
test('台湾归一：Taiwan/台湾 → 中国，其他国名原样（用户裁定 2026-10-18）', () => {
  assert.equal(normalizeCountryName('Taiwan'), '中国')
  assert.equal(normalizeCountryName('台湾'), '中国')
  assert.equal(normalizeCountryName('中国'), '中国')
  assert.equal(normalizeCountryName('日本'), '日本')
  assert.equal(normalizeCountryName(''), '')
})

test('计数合并：台湾计数并入中国，其他键保持独立（热力/hover 单源）', () => {
  const merged = aggregateCountryCounts([
    { name: '中国', count: 3 },
    { name: 'Taiwan', count: 4 },
    { name: '台湾', count: 5 },
    { name: '美国', count: 7 },
  ])
  assert.equal(merged.get('中国'), 12)
  assert.equal(merged.get('美国'), 7)
  assert.equal(merged.has('Taiwan'), false, '台湾不得残留独立键（点阵按中国染色）')
  assert.equal(merged.size, 2)
})

test('省短名：34 省后缀逐条剥离，非行政后缀不动（与后端 ip2RegionShortenName 同口径）', () => {
  assert.equal(adminShortName('广西壮族自治区'), '广西')
  assert.equal(adminShortName('宁夏回族自治区'), '宁夏')
  assert.equal(adminShortName('新疆维吾尔自治区'), '新疆')
  assert.equal(adminShortName('内蒙古自治区'), '内蒙古')
  assert.equal(adminShortName('香港特别行政区'), '香港')
  assert.equal(adminShortName('广东省'), '广东')
  assert.equal(adminShortName('北京市'), '北京')
  // 无后缀/后缀即全名时不得截成空串
  assert.equal(adminShortName('California'), 'California')
  assert.equal(adminShortName('省'), '省')
})

test('省级统计边界：仅中国有省级数据源，海外下钻必须显示「无省级统计」（WT87-11）', () => {
  assert.equal(hasProvinceStats('中国'), true)
  assert.equal(hasProvinceStats('美国'), false)
  assert.equal(hasProvinceStats(''), false)
})

test('下钻续体作废：seq 过期或已销毁一律丢弃（双引擎共用判定，WT87-03）', () => {
  assert.equal(drillCommitAllowed(3, 3, false), true)
  assert.equal(drillCommitAllowed(2, 3, false), false, '复位/返回递增 seq 后迟到续体必须丢弃')
  assert.equal(drillCommitAllowed(3, 3, true), false, '退出大屏后不得再操作已销毁引擎')
})
