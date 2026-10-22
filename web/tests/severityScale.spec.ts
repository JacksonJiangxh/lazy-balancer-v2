// anomaly_score 危险分档单源验收：事件列表评分着色与大屏定级必须同阈值。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { section, source, stripComments } from './_helpers.ts'
import { ANOMALY_SCORE_HIGH, ANOMALY_SCORE_MID, anomalySeverity } from '../src/utils/severityScale.ts'

test('分档阈值：≥12 高 / ≥6 中 / 其余低（2026-10-17 大屏裁定口径）', () => {
  assert.equal(ANOMALY_SCORE_HIGH, 12)
  assert.equal(ANOMALY_SCORE_MID, 6)
  assert.equal(anomalySeverity(12), 'high')
  assert.equal(anomalySeverity(11), 'mid')
  assert.equal(anomalySeverity(6), 'mid')
  assert.equal(anomalySeverity(5), 'low')
  assert.equal(anomalySeverity(0), 'low')
})

test('事件列表评分着色引用同一阈值（不得回流 15/5 双口径）', () => {
  const events = source('src/views/security/SecurityEvents.vue')
  const column = section(events, '<el-table-column label="评分"', '</el-table-column>')
  assert.match(column, /row\.anomaly_score >= ANOMALY_SCORE_HIGH/)
  assert.match(column, /row\.anomaly_score >= ANOMALY_SCORE_MID/)
  assert.doesNotMatch(column, /anomaly_score >= 15/, '列表旧阈值不得回流')
  assert.doesNotMatch(column, /anomaly_score >= 5"/, '列表旧阈值不得回流')
})

test('大屏定级消费同一分档函数（0 分行回退保留存量语义）', () => {
  const screen = source('src/views/security/ThreatScreen.vue')
  const sevOf = section(screen, 'function sevOf(', '\nfunction sevLabel')
  const sevCode = stripComments(sevOf)
  // 分级本体=单源函数；检测模式降级由消费方叠加（高→中、中→低）
  assert.match(sevCode, /anomalySeverity\(score\)/)
  assert.doesNotMatch(sevCode, /score >= 12/)
  assert.doesNotMatch(sevCode, /score >= 6/)
  assert.doesNotMatch(sevCode, /ANOMALY_SCORE_HIGH|ANOMALY_SCORE_MID/)
  // 481-484 是 HTTP 阻断状态码，不是 rule_triggered 值——死分支已删除
  assert.doesNotMatch(sevCode, /\^48\[123\]\$/)
  // 8 与 8xxxxx 保留为存量 0 分行粗粒度回退（注释注明仅存量）
  assert.match(sevCode, /rt === '8' \|\| \/\^8\\d\{5\}\$\/\.test\(rt\)/)
  assert.match(sevOf, /仅存量/)
})
