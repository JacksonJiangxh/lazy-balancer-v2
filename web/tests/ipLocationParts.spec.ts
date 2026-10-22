// 归属地文本拆分单源：光流地域键与弧线起点共用同一 split('·') 规则——两处各自
// 拆分会在分隔符/段数变化时让「键里的省」与「端点用的省」漂移。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { parseIpLocation } from '../src/utils/ipLocationParts.ts'

test('国内联值取前两段（国家/省），第三段及以后忽略', () => {
  assert.deepEqual(parseIpLocation('中国·广东省·深圳市'), { country: '中国', province: '广东省' })
  assert.deepEqual(parseIpLocation('中国·北京市'), { country: '中国', province: '北京市' })
})

test('海外两段与单段：缺省补空串', () => {
  assert.deepEqual(parseIpLocation('美国·California'), { country: '美国', province: 'California' })
  assert.deepEqual(parseIpLocation('日本'), { country: '日本', province: '' })
})

test('空/缺失输入回退两空串（不炸渲染路径）', () => {
  assert.deepEqual(parseIpLocation(''), { country: '', province: '' })
  assert.deepEqual(parseIpLocation(undefined), { country: '', province: '' })
  // 空段保留空串：`中国··深圳市` 的省位不得被后续段顶替
  assert.deepEqual(parseIpLocation('中国··深圳市'), { country: '中国', province: '' })
})
