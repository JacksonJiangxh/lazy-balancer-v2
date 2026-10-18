import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createOidcProbeGuard, oidcProbeKey } from '../src/utils/oidcProbe.ts'

const values = { issuer: ' https://idp.example ', clientId: ' client ', clientSecret: 'secret' }

test('历史问题-4：探测键绑定实际提交的规范化表单快照', () => {
  assert.equal(oidcProbeKey(values), oidcProbeKey({ issuer: 'https://idp.example', clientId: 'client', clientSecret: 'secret' }))
  assert.notEqual(oidcProbeKey(values), oidcProbeKey({ ...values, clientSecret: 'changed' }))
})

test('历史问题-4：输入变化使旧在途结果失效，恢复旧值也不能复活', () => {
  const guard = createOidcProbeGuard()
  const oldToken = guard.token(values)
  assert.equal(guard.isCurrent(oldToken, values), true)
  guard.invalidate()
  assert.equal(guard.isCurrent(oldToken, values), false)
  assert.equal(guard.isCurrent(oldToken, { ...values, clientSecret: 'new' }), false)
  const newToken = guard.token(values)
  assert.equal(guard.isCurrent(newToken, values), true)
})

test('历史问题-4：关闭弹框或重新 load 作废同快照在途探测', () => {
  const guard = createOidcProbeGuard()
  const token = guard.token(values)
  guard.invalidate()
  assert.equal(guard.isCurrent(token, values), false)
})
