import { test } from 'node:test'
import assert from 'node:assert/strict'

import { certJobEffectiveNotAfter, certJobRenewalAt } from '../src/utils/certJobExpiry.ts'

// 后端 expires_at 为 null、not_after 由 PEM 派生的形态（导入/旧备份/集群回插）：
// UI 必须以 not_after 为门，否则任务页显示「-」而规则页显示「剩 N 天」。
test('not_after 优先于 expires_at（expires_at=null 仍可显示有效期/重签时间）', () => {
  const job = { expires_at: null, not_after: '2026-12-31T00:00:00Z' }
  assert.equal(certJobEffectiveNotAfter(job), '2026-12-31T00:00:00Z')
  assert.equal(certJobRenewalAt(job, 30), '2026-12-01T00:00:00.000Z')
})

test('旧版响应缺 not_after 时回退 expires_at', () => {
  const job = { expires_at: '2026-11-20T12:00:00Z' }
  assert.equal(certJobEffectiveNotAfter(job), '2026-11-20T12:00:00Z')
  assert.equal(certJobRenewalAt(job, 10), '2026-11-10T12:00:00.000Z')
})

test('两列都缺失或畸形时返回空串（渲染「-」而非抛错）', () => {
  assert.equal(certJobEffectiveNotAfter({}), '')
  assert.equal(certJobRenewalAt({}, 30), '')
  assert.equal(certJobEffectiveNotAfter({ expires_at: null, not_after: null }), '')
  assert.equal(certJobRenewalAt({ not_after: 'not-a-date' }, 30), '')
  // 非法续签天数不得让 new Date(…).toISOString() 抛 RangeError 中断整行渲染
  assert.equal(certJobRenewalAt({ not_after: '2026-12-31T00:00:00Z' }, Number.NaN), '')
})

// 形状缺口（P3）：两条现状语义必须被显式钉住，否则未来会被当 bug「修复」。
test('not_after 非空但不可解析时不得回退 expires_at（fail-visible 有意设计）', () => {
  // `||` 选择：非法非空值会遮蔽合法回退值——这是有意的可见降级（渲染「-」并
  // 让畸形行暴露），不是缺陷。若改为「回退」，畸形 not_after 会被静默掩盖。
  const job = { not_after: 'not-a-date', expires_at: '2026-11-20T12:00:00Z' }
  assert.equal(certJobEffectiveNotAfter(job), 'not-a-date')
  assert.equal(certJobRenewalAt(job, 10), '', '畸形 not_after 必须 fail-visible（空串→「-」）')
})

test('续签天数为 0/负数时按字面量计算（调用方负责钳制）', () => {
  const job = { not_after: '2026-12-31T00:00:00Z' }
  assert.equal(certJobRenewalAt(job, 0), '2026-12-31T00:00:00.000Z')
  // 负数会把重签时间推到到期之后（未来），因此调用方（auth store 的
  // `renewalDays > 0 ? … : DEFAULT`）是唯一防线——本用例把该约束钉成契约。
  assert.equal(certJobRenewalAt(job, -5), '2027-01-05T00:00:00.000Z')
})
