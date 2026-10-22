// 配置值展示口径：合法正值原样展示；0/负数/缺省一律落内置默认
// （保留 90 天 / 行数 1,000,000）。后端写侧合法值域为保留天数 1-3650、
// 行数 1-100000000（0 为 legacy 自动哨兵，启动迁移收敛为显式默认），
// 展示归一不承担写侧兜底。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { displaySecurityEventsRetentionDays, displaySecurityEventsRowCap, securityEventsWritePayload } from '../src/utils/configValues.ts'
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

test('编辑态 0 原样携带（不夹紧）——写侧拒绝由后端负责，UI 下限已挡住', () => {
  // 口径钉死：载荷侧不做 0 钳制（保留用户显式输入，避免静默改值）。
  // 后端写侧合法值域为保留天数 1-3650、行数 1-1e8，0 会 400——UI 的
  // el-input-number min=1 使编辑态 0 不可能产生；带外/脚本调用得到显式 400
  // 而非被前端悄悄改成默认值。
  assert.deepEqual(
    securityEventsWritePayload({ retentionDays: 0, retentionDirty: true, rowCap: 1_000_000, rowCapDirty: false }),
    { security_events_retention_days: 0 },
  )
  assert.deepEqual(
    securityEventsWritePayload({ retentionDays: 90, retentionDirty: false, rowCap: 0, rowCapDirty: true }),
    { security_events_row_cap: 0 },
  )
  const vue = source('src/views/settings/BasicSettings.vue')
  assert.match(vue, /v-model="seRetentionDays"[^>]*:min="1"/, '保留天数控件下限必须为 1（否则编辑态 0 会 400）')
  assert.match(vue, /v-model="seRowCap"[^>]*:min="1"/, '行数上限控件下限必须为 1')
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

test('展示默认值与后端 db.go 常量同源（跨栈钉）', () => {
  // 前端展示归一的 90 天 / 1,000,000 行必须等于后端内置默认——任一侧调整
  // 另一侧不同步时，UI 会把「自动」显示成错误默认值并被用户当真。
  const go = repoSource('internal/db/db.go')
  assert.ok(go.includes('DefaultSecurityEventsRetentionDays = 90'), '保留天数默认漂移')
  assert.ok(go.includes('DefaultSecurityEventsRowCap        = 1000000'), '行数上限默认漂移')
  assert.equal(displaySecurityEventsRetentionDays(0), 90)
  assert.equal(displaySecurityEventsRetentionDays(3650), 3650)
  assert.equal(displaySecurityEventsRowCap(0), 1_000_000)
})

test('保留天数展示：0/缺省落 90，正值原样（不再 SFC 内联第二实现）', () => {
  for (const value of [1, 30, 90, 3650]) assert.equal(displaySecurityEventsRetentionDays(value), value)
  assert.equal(displaySecurityEventsRetentionDays(0), 90)
  assert.equal(displaySecurityEventsRetentionDays(-1), 90)
  assert.equal(displaySecurityEventsRetentionDays(null), 90)
  assert.equal(displaySecurityEventsRetentionDays(undefined), 90)
  const vue = source('src/views/settings/BasicSettings.vue')
  assert.match(vue, /seRetentionDays\.value = displaySecurityEventsRetentionDays\(d\)/, 'BasicSettings 必须复用单源 helper')
  assert.doesNotMatch(vue, /d && d > 0 \? d : 90/, 'SFC 内联第二实现必须退役')
})
