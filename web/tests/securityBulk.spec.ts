// 后端批量端点上限镜像与冲突检测求交（历史问题-06/历史问题-09）：
//   A. chunkForBulk 按上限切分、顺序保持、空输入不产生请求
//   B. entriesIntersect 复用 Set 语义且与 filter/includes 结果一致（去重、保序）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  MAX_POLICIES_PER_RULE,
  SECURITY_BULK_LIMITS,
  chunkForBulk,
  entriesIntersect,
} from '../src/utils/securityStages.ts'
import { CADDY_APPLY_FAILED_MARKER, mergeBulkResults } from '../src/utils/bulkApplyResult.ts'

test('A1 分片：按上限切分且保持原顺序（策略绑定 100 / 批量拦截页 500）', () => {
  const bindings = Array.from({ length: 250 }, (_, i) => `lb_${i}`)
  const chunks = chunkForBulk(bindings, SECURITY_BULK_LIMITS.policyBindings)
  assert.deepEqual(chunks.map((c) => c.length), [100, 100, 50])
  assert.deepEqual(chunks.flat(), bindings, '分片拼接必须等于原序列')
  const pages = Array.from({ length: 1001 }, (_, i) => `lb_${i}`)
  assert.deepEqual(chunkForBulk(pages, SECURITY_BULK_LIMITS.ruleBlockPages).map((c) => c.length), [500, 500, 1])
})

test('A2 分片：单次合计不超过后端上限（每片 ≤100 才满足 bind+unbind 合计门）', () => {
  for (const size of [1, 99, 100, 101, 1000]) {
    const chunks = chunkForBulk(Array.from({ length: size }, (_, i) => i), SECURITY_BULK_LIMITS.policyBindings)
    for (const chunk of chunks) assert.ok(chunk.length <= SECURITY_BULK_LIMITS.policyBindings)
    assert.equal(chunks.reduce((sum, c) => sum + c.length, 0), size)
  }
})

test('A3 分片：空输入/非法上限不产生请求', () => {
  assert.deepEqual(chunkForBulk([], 100), [])
  assert.deepEqual(chunkForBulk(['a'], 0), [])
})

test('B1 求交：与 filter+includes 结果一致（保序、去重），Set 查表不改变语义', () => {
  const allow = ['10.0.0.1', '10.0.0.2', '10.0.0.1', '10.0.0.3']
  const deny = new Set(['10.0.0.3', '10.0.0.1'])
  const expected = [...new Set(allow.filter((e) => deny.has(e)))]
  assert.deepEqual(entriesIntersect(allow, deny), expected)
  assert.deepEqual(entriesIntersect(allow, deny), ['10.0.0.1', '10.0.0.3'])
})

test('B2 求交：无重叠返回空数组，不误报冲突', () => {
  assert.deepEqual(entriesIntersect(['1.1.1.1'], new Set(['2.2.2.2'])), [])
  assert.deepEqual(entriesIntersect([], new Set(['2.2.2.2'])), [])
})

// —— 分片响应汇总（历史问题）——
// 退化 200（DB 已提交、Caddy 应用失败）必须常驻警告：原实现把每片响应赋给
// 同一变量，只有末片进入 showSaveResult，早先分片的失败提示被覆盖丢失。
const DEGRADED = `绑定已提交；但${CADDY_APPLY_FAILED_MARKER}：重载中断`

test('C1 分片响应：首片退化 200 不被末片成功覆盖', () => {
  const merged = mergeBulkResults([{ message: DEGRADED }, { message: '已更新 100 条规则的绑定' }])
  assert.equal(merged?.message, DEGRADED)
  assert.ok(merged?.message?.includes(CADDY_APPLY_FAILED_MARKER))
})

test('C2 分片响应：多片退化合并为一条并标注片数，重复后缀去重', () => {
  const duplicated = mergeBulkResults([{ message: DEGRADED }, undefined, { message: DEGRADED }])
  assert.equal(duplicated?.message, DEGRADED)
  const distinct = mergeBulkResults([
    { message: DEGRADED },
    { message: `已提交；但${CADDY_APPLY_FAILED_MARKER}：超时` },
  ])
  assert.ok(distinct?.message?.startsWith(DEGRADED))
  assert.match(distinct?.message ?? '', /另有 1 个分片同样应用失败/)
})

test('C3 分片响应：无退化时保持末片文案；空输入返回 undefined', () => {
  assert.deepEqual(mergeBulkResults([{ message: 'a' }, { message: 'b' }]), { message: 'b' })
  assert.equal(mergeBulkResults([]), undefined)
  assert.equal(mergeBulkResults([undefined, undefined]), undefined)
  assert.ok(!(mergeBulkResults([{ message: 'ok' }])?.message ?? '').includes(CADDY_APPLY_FAILED_MARKER))
})

test('D1 绑定上限单源：与后端 maxBindingsPerRule 同值', () => {
  assert.equal(MAX_POLICIES_PER_RULE, 8)
})
