import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createOidcProbeGuard, isOidcProbeFresh, oidcProbeKey } from '../src/utils/oidcProbe.ts'
import { section, source } from './_helpers.ts'

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

// 历史修复：issuer 失焦原无条件重发 discovery+JWKS（+可选凭证校验）外部请求，
// 字段间来回切换会重复打 IdP。结果仍对应当前表单值时必须直接复用。
test('WS-14：已通过且值未变的探测结果可复用', () => {
  const key = oidcProbeKey(values)
  assert.equal(isOidcProbeFresh({ ok: true, key }, values), true)
  assert.equal(isOidcProbeFresh({ ok: true, key }, { ...values, clientSecret: 'changed' }), false)
  assert.equal(isOidcProbeFresh({ ok: false, key }, values), false)
  assert.equal(isOidcProbeFresh({ ok: true }, values), false, '无键=不可复用')
  const page = source('src/views/settings/OIDCSettings.vue')
  assert.match(
    section(page, 'const probeOnBlur = () => {', '\n}'),
    /if \(isOidcProbeFresh\(probe, currentProbeValues\(\)\)\) return/,
  )
})
