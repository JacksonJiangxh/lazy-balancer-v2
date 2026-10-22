// 采集健康位三面同源（事件列表/安全总览/威胁大屏）+ 后端字段契约。
// 判据/文案只允许出现在 src/utils/ingestionHealth.ts；视图只消费同一 helper。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source, repoSource } from './_helpers.ts'
import { ingestionWarningMessage } from '../src/utils/ingestionHealth.ts'

const healthy = {
  observed: true,
  healthy: true,
  consecutive_failures: 0,
  task_state: 'running',
  task_running: true,
}

test('健康位正常时不提示', () => {
  assert.equal(ingestionWarningMessage(healthy), '')
  assert.equal(ingestionWarningMessage(undefined), '')
  assert.equal(ingestionWarningMessage({ observed: false, healthy: false, consecutive_failures: 0 }), '')
})

test('任务已停 → 明确提示「已停止」而非数据滞后', () => {
  const message = ingestionWarningMessage({ ...healthy, healthy: false, task_state: 'stopped', task_running: false })
  assert.match(message, /任务已停止/)
  assert.doesNotMatch(message, /连续失败/)
})

test('审计写侧降级 → 披露丢弃/写盘错误计数', () => {
  const message = ingestionWarningMessage({
    ...healthy,
    healthy: false,
    writer_degraded: true,
    writer_dropped: 7,
    writer_io_errors: 2,
  })
  assert.match(message, /丢弃 7 条/)
  assert.match(message, /写盘错误 2 次/)
})

test('连续失败 → 携带次数与末次错误', () => {
  const message = ingestionWarningMessage({
    ...healthy,
    healthy: false,
    consecutive_failures: 4,
    last_error: 'read offset: permission denied',
  })
  assert.match(message, /连续失败 4 次/)
  assert.match(message, /read offset: permission denied/)
})

test('三处视图消费同源 helper（禁止各自判定）', () => {
  for (const file of [
    'src/views/security/SecurityEvents.vue',
    'src/views/security/SecurityOverview.vue',
    'src/views/security/ThreatScreen.vue',
  ]) {
    const text = source(file)
    assert.match(text, /import \{ ingestionWarningMessage, type IngestionHealth \} from '@\/utils\/ingestionHealth'/, `${file} 必须导入同源 helper`)
    assert.match(text, /ingestionWarningMessage\(/, `${file} 必须调用同源 helper`)
    // 提示条只用全局 info-note-bar 体系（禁止新造/局部覆盖样式）。
    const template = text.slice(0, text.indexOf('<script'))
    assert.match(template, /class="info-note-bar[^"]*"[\s\S]*?ingestionWarning/, `${file} 提示条必须复用全局 info-note-bar 类`)
  }
})

test('总览/大屏从各自响应消费 ingestion 字段（后端同名字段）', () => {
  const overview = source('src/views/security/SecurityOverview.vue')
  assert.match(overview, /ingestion\?: IngestionHealth/)
  assert.match(overview, /ingestionWarningMessage\(overview\.value\.ingestion\)/)
  const threat = source('src/views/security/ThreatScreen.vue')
  const threatStats = section(threat, 'interface ThreatScreenStats', 'interface FeedEvent')
  assert.match(threatStats, /ingestion\?: IngestionHealth/)
  assert.match(threat, /ingestionWarningMessage\(stats\.value\?\.ingestion\)/)
})

test('前后端字段契约：Go JSON tag 覆盖前端 IngestionHealth 读取面', () => {
  const go = repoSource('internal/services/securityevents.go')
  const statusBlock = section(go, 'type SecurityEventsIngestionStatus struct', '\n}')
  for (const tag of [
    'json:"observed"',
    'json:"healthy"',
    'json:"consecutive_failures"',
    'json:"last_error,omitempty"',
    'json:"task_state"',
    'json:"task_running"',
    'json:"writer_dropped"',
    'json:"writer_io_errors"',
    'json:"writer_degraded"',
    'json:"writer_last_failure_at,omitempty"',
  ]) {
    assert.ok(statusBlock.includes(tag), `后端状态缺少 ${tag}（前端 ingestionHealth.ts 已消费）`)
  }
  // 插件侧车路径契约与根服务读取面必须同后缀（跨 Go module 无共享包）。
  const plugin = repoSource('caddygeoip/auditwriter.go')
  assert.match(plugin, /auditWriterStatsSuffix\s*=\s*"\.writer-stats\.json"/)
  assert.match(go, /securityEventsAuditWriterStatsSuffix\s*=\s*"\.writer-stats\.json"/)
})
