import { test } from 'node:test'
import assert from 'node:assert/strict'

import { certJobRetryReady } from '../src/utils/certJobStatus.ts'

const now = Date.parse('2026-10-19T00:00:00Z')
const updatedAt = '2026-10-19T00:00:00Z'

test('历史问题-04：重试冷却时长由后端字段驱动，不再由状态常量驱动', () => {
  assert.equal(certJobRetryReady(null, updatedAt, now), false, 'disabled=null 永不可重试')
  assert.equal(certJobRetryReady(0, updatedAt, now), true, '零冷却立即可重试')
  assert.equal(certJobRetryReady(900, updatedAt, now + 14*60*1000 + 59*1000), false)
  assert.equal(certJobRetryReady(900, updatedAt, now + 15*60*1000), true)
  assert.equal(certJobRetryReady(300, updatedAt, now + 4*60*1000), false)
  assert.equal(certJobRetryReady(300, updatedAt, now + 5*60*1000), true)
})

test('历史问题-04：缺失或畸形时间戳维持既有 fail-open 边界', () => {
  assert.equal(certJobRetryReady(120, undefined, now), true)
  assert.equal(certJobRetryReady(120, 'not-a-date', now), true)
})
