import { test } from 'node:test'
import assert from 'node:assert/strict'

import { normalizeRateLimitBlocks } from '../src/utils/rateLimitBlocks.ts'
import { source } from './_helpers.ts'

test('null data -> empty hosts, total 0', () => {
  assert.deepEqual(normalizeRateLimitBlocks(null), { total: 0, hosts: [] })
})

test('hosts:null from legacy backend -> empty array (no .length crash)', () => {
  assert.deepEqual(normalizeRateLimitBlocks({ total: 0, hosts: null }), { total: 0, hosts: [] })
})

test('valid hosts are preserved and sorted data untouched', () => {
  assert.deepEqual(
    normalizeRateLimitBlocks({ total: 21, hosts: [{ host: 'a.example', count: 14 }, { host: 'b.example', count: 7 }] }),
    { total: 21, hosts: [{ host: 'a.example', count: 14 }, { host: 'b.example', count: 7 }] },
  )
})

test('legacy null total falls back to the visible host sum', () => {
  assert.deepEqual(
    normalizeRateLimitBlocks({ total: null, hosts: [{ host: 'x', count: 9 }] }),
    { total: 9, hosts: [{ host: 'x', count: 9 }] },
  )
})

test('malformed host entries are dropped without throwing', () => {
  assert.deepEqual(
    normalizeRateLimitBlocks({ total: 3, hosts: [null, { host: 'ok.example', count: 3 }, { count: 9 }] } as unknown),
    { total: 3, hosts: [{ host: 'ok.example', count: 3 }] },
  )
})

// 消费侧接线：视图模板直接读 rateLimitBlocks.hosts.length——归一被删后 legacy
// hosts:null 响应会在渲染期抛错（纯函数用例拦不住）。
test('安全概览把接口响应经归一后落库（视图不直接消费原始载荷）', () => {
  const overview = source('src/views/security/SecurityOverview.vue')
  assert.match(
    overview,
    /rateLimitBlocks\.value = normalizeRateLimitBlocks\(res\.data\)/,
    '限流聚合必须经 normalizeRateLimitBlocks 归一后赋值',
  )
})
