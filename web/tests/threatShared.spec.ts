// 威胁大屏共享纯函数验收
//   A. 热力数据指纹：相同→true；计数/长度/重复键变化→false
//   B. 弧线端点：终点恒为当前本站坐标（setServer 后新弧线随新坐标）
//   C. 危险等级化简：检测模式 12 分边界（原恒等三元 >=6 与 <6 同值）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { heatEntriesEqual, heatCss, DOT_LAND, arcEndpoints, POINTY_TOP_HEX_VERTICES, drillCountryAllowed, arcOriginForLocation, normalizeCountryName, adminShortName, aggregateCountryCounts, hasProvinceStats, drillCommitAllowed } from '../src/utils/threatShared.ts'

test('六边形点阵：pointy-top 六顶点且上下尖角', () => {
  assert.equal(POINTY_TOP_HEX_VERTICES.length, 6)
  assert.deepEqual(POINTY_TOP_HEX_VERTICES[0], [0, -1])
  assert.deepEqual(POINTY_TOP_HEX_VERTICES[3], [0, 1])
  assert.ok(POINTY_TOP_HEX_VERTICES.every(([x, y]) => Math.abs(x) <= Math.sqrt(3) / 2 && Math.abs(y) <= 1))
})

test('下钻白名单：缺省不限，显式列表只放行列内国家', () => {
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

test('热力阶梯首色=陆地底色：命中 1 次不得比 0 次更暗', () => {
  const parse = (css: string): number[] => css.slice(4, -1).split(',').map(Number)
  assert.equal(heatCss(0), DOT_LAND, 'count=0 与未命中点阵同色')
  assert.equal(heatCss(1), DOT_LAND, 'count=1（log10=0）落在阶梯首色=底色，不得比 0 次更暗')
  const base = parse(DOT_LAND)
  for (const count of [2, 5, 50, 500, 5000]) {
    const [r, g, b] = parse(heatCss(count))
    assert.ok(r + g + b > base[0] + base[1] + base[2], `count=${count} 亮度必须高于底色`)
  }
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

// 台湾归一/短名/计数合并此前零断言——热力、命中、下钻三处都靠它们。
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

test('省级统计边界：仅中国有省级数据源，海外下钻必须显示「无省级统计」', () => {
  assert.equal(hasProvinceStats('中国'), true)
  assert.equal(hasProvinceStats('美国'), false)
  assert.equal(hasProvinceStats(''), false)
})

test('下钻续体作废：seq 过期或已销毁一律丢弃（双引擎共用判定）', () => {
  assert.equal(drillCommitAllowed(3, 3, false), true)
  assert.equal(drillCommitAllowed(2, 3, false), false, '复位/返回递增 seq 后迟到续体必须丢弃')
  assert.equal(drillCommitAllowed(3, 3, true), false, '退出大屏后不得再操作已销毁引擎')
})

// 省点阵 bbox 预筛钉测——预筛只是跳点优化，产出必须与无预筛
// 形态逐点一致（宽幅国家下 34 省 × 全网格直接 pointInPolys 是首次下钻长任务，
// 与 threatScene.ts 省级 bbox 预筛同构）。
import { provinceDotGrid } from '../src/utils/threatShared.ts'
import { pointInPolys } from '../src/utils/threatShared.ts'
import { WORLD_COUNTRIES } from '../src/utils/worldBorders.ts'
import { ADMIN1_PROVINCES } from '../src/utils/admin1Provinces.ts'
import { CHINA_PROVINCES } from '../src/utils/chinaProvinces.ts'

function rectPoly(minLon: number, minLat: number, maxLon: number, maxLat: number): number[][][] {
  return [[[minLon, minLat, maxLon, minLat, maxLon, maxLat, minLon, maxLat, minLon, minLat]]]
}

/** 无预筛参照实现：与 provinceDotGrid 同网格语义，但逐格点对全部省份做射线判定。 */
function provinceDotGridNoPrefilter(
  source: readonly { name: string; polys: number[][][] }[],
  step: number,
): { lat: number; lng: number; key: string }[] {
  let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
  for (const pv of source) {
    for (const poly of pv.polys) for (const ring of poly) for (let k = 0; k + 1 < ring.length; k += 2) {
      if (ring[k] < minLon) minLon = ring[k]
      if (ring[k] > maxLon) maxLon = ring[k]
      if (ring[k + 1] < minLat) minLat = ring[k + 1]
      if (ring[k + 1] > maxLat) maxLat = ring[k + 1]
    }
  }
  const dots: { lat: number; lng: number; key: string }[] = []
  let row = 0
  for (let lat = minLat; lat <= maxLat; lat += step, row++) {
    const offset = row % 2 === 1 ? step / 2 : 0
    for (let lon = minLon + offset; lon <= maxLon; lon += step) {
      for (const pv of source) {
        if (!pointInPolys(lon, lat, pv.polys)) continue
        dots.push({ lat, lng: lon, key: adminShortName(pv.name) })
        break
      }
    }
  }
  return dots
}

test('省点阵 bbox 预筛与无预筛形态产出逐点一致（宽幅/远距/多边形组）', () => {
  const source = [
    // 宽幅省：横跨大部分经度域（预筛几乎不跳点，回归形状）
    { name: '宽幅省', polys: rectPoly(-170, 40, 170, 60) },
    // 远距小省：绝大部分格点被 bbox 预筛跳过（目标形状）
    { name: '小岛省', polys: rectPoly(10, -20, 12.5, -17.5) },
    // 多边形组省：两段分离多边形（畸形形状：bbox 大于实际覆盖）
    { name: '双片省', polys: [...rectPoly(-60, -40, -55, -35), ...rectPoly(60, 0, 65, 5)] },
  ]
  for (const step of [2.5, 5]) {
    assert.deepEqual(
      provinceDotGrid(source, step),
      provinceDotGridNoPrefilter(source, step),
      `step=${step} 预筛产出必须与无预筛一致`,
    )
  }
  // 键名走共享短名口径
  const dots = provinceDotGrid([{ name: '广东省', polys: rectPoly(110, 20, 112, 22) }], 1)
  assert.ok(dots.length > 0)
  assert.equal(dots[0].key, '广东')
})

test('真实国界孔洞：莱索托不计入南非，南非本土仍命中', () => {
  const southAfrica = WORLD_COUNTRIES.find((country) => country.name === '南非')
  const lesotho = WORLD_COUNTRIES.find((country) => country.name === '莱索托')
  assert.ok(southAfrica)
  assert.ok(lesotho)
  assert.equal(pointInPolys(28.23, -29.58, southAfrica.polys), false)
  assert.equal(pointInPolys(28.23, -29.58, lesotho.polys), true)
  assert.equal(pointInPolys(25.0, -28.0, southAfrica.polys), true)
})

test('真实省界孔洞：维也纳不计入下奥地利州，州内其他点仍命中', () => {
  const provinces = ADMIN1_PROVINCES['奥地利']
  assert.ok(provinces)
  const lowerAustria = provinces.find((province) => province.name === 'Niederösterreich')
  const vienna = provinces.find((province) => province.name === 'Wien')
  assert.ok(lowerAustria)
  assert.ok(vienna)
  assert.equal(pointInPolys(16.37, 48.21, lowerAustria.polys), false)
  assert.equal(pointInPolys(16.37, 48.21, vienna.polys), true)
  assert.equal(pointInPolys(15.6, 48.4, lowerAustria.polys), true)
})

test('中国省界回归：北京与天津不被河北孔洞吸收，河北本土仍命中', () => {
  const beijing = CHINA_PROVINCES.find((province) => province.name === '北京市')
  const tianjin = CHINA_PROVINCES.find((province) => province.name === '天津市')
  const hebei = CHINA_PROVINCES.find((province) => province.name === '河北省')
  assert.ok(beijing)
  assert.ok(tianjin)
  assert.ok(hebei)
  assert.equal(pointInPolys(116.4, 39.9, beijing.polys), true)
  assert.equal(pointInPolys(116.4, 39.9, hebei.polys), false)
  assert.equal(pointInPolys(117.35, 39.28, tianjin.polys), true)
  assert.equal(pointInPolys(117.35, 39.28, hebei.polys), false)
  assert.equal(pointInPolys(114.5, 38.0, hebei.polys), true)
})
