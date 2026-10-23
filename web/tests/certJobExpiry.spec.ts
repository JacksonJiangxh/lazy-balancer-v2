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
