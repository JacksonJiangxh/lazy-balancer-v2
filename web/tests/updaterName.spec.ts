// 更新者展示名单源验收：Rules/SecurityRules/SecurityBlockPages/
// SecurityPolicies 四份同构实现收敛为 utils/updaterName。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { updaterName } from '../src/utils/updaterName.ts'

const users = [
  { id: 1, display_name: '管理员', username: 'admin' },
  { id: 2, display_name: '', username: 'operator' },
  { id: 3, username: 'bot' },
]

test('display_name 优先，空串回落 username', () => {
  assert.equal(updaterName(users, 1), '管理员')
  assert.equal(updaterName(users, 2), 'operator')
  assert.equal(updaterName(users, 3), 'bot')
})

test('缺省/零/未命中一律显示 -', () => {
  assert.equal(updaterName(users, undefined), '-')
  assert.equal(updaterName(users, 0), '-')
  assert.equal(updaterName(users, 999), '-')
  assert.equal(updaterName([], 1), '-')
})
