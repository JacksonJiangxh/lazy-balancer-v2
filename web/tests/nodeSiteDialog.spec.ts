import { test } from 'node:test'
import assert from 'node:assert/strict'

import { initialNodeSiteForm, nearestSiteLocation, nodeSiteCoordsChanged } from '../src/utils/siteLocation.ts'

// A86 历史问题：继承主节点默认坐标的节点（site_inherited=true，列表接口返回的
// server_map_lat/lon 是主节点坐标副本），弹框初值必须还原为 0,0 + 空选择——
// 不得把继承值预填为可保存值（原样保存会把继承静默固化为显式坐标）。
test('A86 历史问题：继承节点表单初值还原为 0,0 + 空选择', () => {
  const form = initialNodeSiteForm({ server_map_lat: 35.19, server_map_lon: 108.87, site_inherited: true })
  assert.equal(form.lat, 0)
  assert.equal(form.lon, 0)
  assert.equal(form.siteLocationKey, '')
})

test('A86 历史问题：显式坐标节点表单初值保留自身坐标并回显最近地点', () => {
  const form = initialNodeSiteForm({ server_map_lat: 40.19, server_map_lon: 116.42, site_inherited: false })
  assert.equal(form.lat, 40.19)
  assert.equal(form.lon, 116.42)
  assert.equal(form.siteLocationKey, nearestSiteLocation(40.19, 116.42))
  assert.notEqual(form.siteLocationKey, '')
})

test('A86 历史问题：无变更保存判定为 no-op（直接关闭，不发 PUT 不 bump）', () => {
  assert.equal(nodeSiteCoordsChanged({ lat: 0, lon: 0 }, { lat: 0, lon: 0 }), false)
  assert.equal(nodeSiteCoordsChanged({ lat: 31.23, lon: 121.47 }, { lat: 31.23, lon: 121.47 }), false)
  assert.equal(nodeSiteCoordsChanged({ lat: 0, lon: 0 }, { lat: 31.23, lon: 121.47 }), true)
  assert.equal(nodeSiteCoordsChanged({ lat: 31.23, lon: 121.47 }, { lat: 0, lon: 0 }), true)
})
