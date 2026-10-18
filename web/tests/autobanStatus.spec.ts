// 自动封禁状态卡黄条判据（审计 81 历史问题-02）：ban_effective 为生效面单一判据；
// list_referenced（四面引用集）仅保留为后端内部字段，不得再驱动黄条。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const src = readFileSync(new URL('../src/views/security/SecurityEvents.vue', import.meta.url), 'utf8')

test('黄条判据：使用 ban_effective === false，不再用 list_referenced', () => {
  assert.match(src, /autobanStatus\.enabled && autobanStatus\.ban_effective === false/)
  assert.doesNotMatch(src, /autobanStatus\.list_referenced === false/, 'list_referenced 不得再驱动 UI')
})

test('状态契约：ban_effective 已声明且默认 true（成功响应前 fail-closed 不弹黄条）', () => {
  assert.match(src, /ban_effective: boolean/)
  assert.match(src, /ban_effective: true/)
  assert.match(src, /list_referenced: boolean/, 'list_referenced 作为后端内部字段保留')
})
