// 规则库展示单源验收（历史问题-F1/F2）：
//   F1 IP 地理库「未安装」不得再显示「已最新/正常」——状态/健康标签显式表达
//   F2 SecurityRules 与 SecurityOverview 的聚合/状态映射单源，空源列表两端同结论
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  libraryHealthTag,
  librarySourceHealthTag,
  libraryStatusLabel,
  libraryStatusTagType,
  summarizeLibrarySources,
} from '../src/utils/securityLibraries.ts'

test('状态词表：未安装/缺失/未更新不再伪装为已最新', () => {
  assert.equal(libraryStatusLabel('not-installed'), '未安装')
  assert.equal(libraryStatusLabel('missing'), '缺失')
  assert.equal(libraryStatusLabel('never'), '未更新')
  assert.notEqual(libraryStatusLabel('not-installed'), libraryStatusLabel('idle'))
  assert.equal(libraryStatusTagType('not-installed'), 'info')
  assert.equal(libraryStatusTagType('missing'), 'danger')
  assert.equal(libraryStatusTagType('failed'), 'danger')
  assert.equal(libraryStatusTagType('success'), 'success')
})

test('多源聚合：空源列表统一为 never（两页面不再一处已最新一处无标签）', () => {
  const summary = summarizeLibrarySources([])
  assert.equal(summary.status, 'never')
  assert.equal(summary.latestVersion, '')
  assert.equal(summary.totalEntries, 0)
  assert.equal(summary.lastChecked, '—')
  assert.equal(summary.nextUpdate, '—')
  assert.equal(libraryStatusLabel(summary.status), '未更新')
})

test('多源聚合：状态优先级 更新中>失败>成功>未更新', () => {
  const base = { version: '2026.10.01', update_status: 'success', entry_count: 2 }
  assert.equal(summarizeLibrarySources([base, { ...base, update_status: 'failed' }]).status, 'failed')
  assert.equal(summarizeLibrarySources([base, { ...base, update_status: 'running' }]).status, 'running')
  assert.equal(summarizeLibrarySources([base]).status, 'success')
})

test('多源聚合：版本取最近、条目求和、日期取两端', () => {
  const summary = summarizeLibrarySources([
    { version: '2026.09.01', update_status: 'success', entry_count: 10, last_checked: '2026-09-01', next_update: '2026-10-01' },
    { version: '2026.10.15', update_status: 'success', entry_count: 5, last_checked: '2026-10-15', next_update: '2026-10-20' },
  ])
  assert.equal(summary.latestVersion, '2026.10.15')
  assert.equal(summary.totalEntries, 15)
  assert.equal(summary.lastChecked, '2026-10-15')
  assert.equal(summary.nextUpdate, '2026-10-01')
})

test('单库健康标签：IP 地理库未安装 → 未安装警示（不再「正常」）', () => {
  const tag = libraryHealthTag('IP 地理库', { loadError: false, available: true, status: 'not-installed' })
  assert.deepEqual(tag, { label: 'IP 地理库 · 未安装', type: 'warning' })
  assert.deepEqual(
    libraryHealthTag('IP 地理库', { loadError: true, available: true, status: 'failed' }),
    { label: 'IP 地理库 · 加载失败', type: 'danger' },
  )
  assert.deepEqual(
    libraryHealthTag('IP 地理库', { loadError: false, available: false, status: 'missing' }),
    { label: 'IP 地理库 · 缺失', type: 'danger' },
  )
  assert.deepEqual(
    libraryHealthTag('CRS 规则库', { loadError: false, available: true, status: 'success' }),
    { label: 'CRS 规则库 · 正常', type: 'success' },
  )
})

test('多源库健康标签：未配置源不再显示正常', () => {
  assert.deepEqual(librarySourceHealthTag('威胁情报库', [], false), { label: '威胁情报库 · 未配置', type: 'warning' })
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [{ update_status: 'failed' }, { update_status: 'success' }], false),
    { label: '威胁情报库 · 1 源更新失败', type: 'warning' },
  )
  assert.deepEqual(
    librarySourceHealthTag('威胁情报库', [{ update_status: 'success' }], false),
    { label: '威胁情报库 · 正常', type: 'success' },
  )
})
