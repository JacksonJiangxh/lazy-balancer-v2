import { test } from 'node:test'
import assert from 'node:assert/strict'
import { shouldCloseRegistrationDialog } from '../src/utils/clusterRegistration.ts'

test('历史问题-3：仅首次注册发生 master→slave 跃迁时自动关闭', () => {
  assert.equal(shouldCloseRegistrationDialog(true, 'master', 'slave'), true)
})

test('历史问题-3：从节点重新注册不会被状态轮询关闭', () => {
  assert.equal(shouldCloseRegistrationDialog(true, 'slave', 'slave'), false)
})

test('历史问题-3：未打开、未知来源与其它状态不触发跃迁关闭', () => {
  assert.equal(shouldCloseRegistrationDialog(false, 'master', 'slave'), false)
  assert.equal(shouldCloseRegistrationDialog(true, null, 'slave'), false)
  assert.equal(shouldCloseRegistrationDialog(true, 'master', 'master'), false)
})
