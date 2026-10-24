import { test } from 'node:test'
import assert from 'node:assert/strict'

import { normalizeRateLimitBlocks } from '../src/utils/rateLimitBlocks.ts'
import { source } from './_helpers.ts'

test('空数据：无主机、总数 0', () => {
  assert.deepEqual(normalizeRateLimitBlocks(null), { total: 0, hosts: [] })
})

test('旧后端 hosts:null 归一为空数组（不因 .length 崩溃）', () => {
  assert.deepEqual(normalizeRateLimitBlocks({ total: 0, hosts: null }), { total: 0, hosts: [] })
})

test('合法主机原样保留且不重排', () => {
  assert.deepEqual(
    normalizeRateLimitBlocks({ total: 21, hosts: [{ host: 'a.example', count: 14 }, { host: 'b.example', count: 7 }] }),
    { total: 21, hosts: [{ host: 'a.example', count: 14 }, { host: 'b.example', count: 7 }] },
  )
})

test('旧形态 total 为 null 时回退为可见主机计数之和', () => {
  assert.deepEqual(
    normalizeRateLimitBlocks({ total: null, hosts: [{ host: 'x', count: 9 }] }),
    { total: 9, hosts: [{ host: 'x', count: 9 }] },
  )
})

test('畸形主机条目丢弃且不抛错', () => {
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
