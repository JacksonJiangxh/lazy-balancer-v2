import { test } from 'node:test'
import assert from 'node:assert/strict'

import { certJobRetryReady } from '../src/utils/certJobStatus.ts'
import { section, source } from './_helpers.ts'

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

// WS-19：状态 label/tone 全表覆盖后端 db.certJobStatuses（26 态，DB CHECK 单源）。
// 前端枚举漂移会静默落入 unknown 分支（标签显示原始 token、tone 退 info），
// 且无任何用例会失败——本条把两侧声明对表。
test('WS-19：证书任务状态枚举覆盖后端 db.certJobStatuses 全 26 态', () => {
  const go = source('../internal/db/db.go')
  const goBlock = section(go, 'var certJobStatuses = []string{', '\n}\n')
  const backend = [...goBlock.matchAll(/"([a-z_]+)"/g)].map((m) => m[1])
  const ts = source('src/utils/certJobStatus.ts')
  const tsBlock = section(ts, 'export type CertJobStatus =', '\n\nexport const certJobStatusLabel')
  const frontend = [...tsBlock.matchAll(/'([a-z_]+)'/g)].map((m) => m[1])
  assert.equal(backend.length, 26, '后端枚举应为 26 态（DB CHECK 单源）')
  assert.deepEqual([...frontend].sort(), [...backend].sort(), '证书状态前后端枚举漂移')
})
