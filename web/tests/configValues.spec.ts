// 配置值展示口径（注释校正）：合法正值原样展示；
// 0/负数/缺省（undefined/null）一律落内置默认 1,000,000（实现为 >0 直通，
// 其余全落默认——负数仅可能来自遗留/带外数据，后端写侧拒绝 0/负数）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { displaySecurityEventsRowCap, securityEventsWritePayload } from '../src/utils/configValues.ts'
import { section, source, repoSource } from './_helpers.ts'

test('行数上限：1..999 等合法小值原样展示，不被夹到 1000/1,000,000', () => {
  for (const value of [1, 2, 500, 999, 1000, 5000, 100000000]) {
    assert.equal(displaySecurityEventsRowCap(value), value)
  }
})

test('行数上限：0/负数/缺省按自动口径展示内置默认 1,000,000', () => {
  assert.equal(displaySecurityEventsRowCap(0), 1_000_000)
  assert.equal(displaySecurityEventsRowCap(-1), 1_000_000)
  assert.equal(displaySecurityEventsRowCap(undefined), 1_000_000)
  assert.equal(displaySecurityEventsRowCap(null), 1_000_000)
})

test('保存载荷：未编辑不携带保留/行数上限——0=自动 哨兵不得被展示归一值物化', () => {
  // 仅回显（库值 0=自动，表单显示 90 天 / 1,000,000 行）→ 载荷省略两键，
  // 后端 COALESCE 保持现值。此前无条件回传会把 90/1,000,000 写进库。
  assert.deepEqual(
    securityEventsWritePayload({ retentionDays: 90, retentionDirty: false, rowCap: 1_000_000, rowCapDirty: false }),
    {},
  )
  // 用户实际编辑 → 只携带编辑过的字段（原值，含 1..999 合法小值不夹紧）。
  assert.deepEqual(
    securityEventsWritePayload({ retentionDays: 30, retentionDirty: true, rowCap: 1_000_000, rowCapDirty: false }),
    { security_events_retention_days: 30 },
  )
  assert.deepEqual(
    securityEventsWritePayload({ retentionDays: 90, retentionDirty: false, rowCap: 999, rowCapDirty: true }),
    { security_events_row_cap: 999 },
  )
  assert.deepEqual(
    securityEventsWritePayload({ retentionDays: 180, retentionDirty: true, rowCap: 2_000_000, rowCapDirty: true }),
    { security_events_retention_days: 180, security_events_row_cap: 2_000_000 },
  )
})

// Caddy 全局配置保存键集与后端审计归因映射必须同集——两侧此前仅靠人工
// 核对（22 键），漂移会静默改变保存载荷覆盖面/审计归因段落。
test('CADDY_CONFIG_KEYS ⇄ ConfigFieldSections「Caddy配置」键集一致', () => {
  const vue = source('src/views/settings/CaddyGlobalSettings.vue')
  const keysBlock = section(vue, 'const CADDY_CONFIG_KEYS = [', '] as const')
  const frontend = [...keysBlock.matchAll(/'([a-z0-9_]+)'/g)].map((m) => m[1])
  const go = repoSource('internal/services/auditlog.go')
  const mapBlock = section(go, 'var ConfigFieldSections = map[string]string{', '\n}\n')
  const backend = [...mapBlock.matchAll(/"([a-z0-9_]+)":\s*"Caddy配置"/g)].map((m) => m[1])
  assert.ok(frontend.length > 0 && backend.length > 0)
  assert.deepEqual([...frontend].sort(), [...backend].sort(), 'Caddy 配置保存键集与审计归因映射漂移')
})
