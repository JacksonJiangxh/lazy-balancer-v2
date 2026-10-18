import { test } from 'node:test'
import assert from 'node:assert/strict'
import { dnsServerAfterToggle } from '../src/utils/ruleWizard.ts'

test('历史问题-03：水合 false 配置不得清空已存 dns_server', () => {
  assert.equal(dnsServerAfterToggle('10.0.0.53', false, true), '10.0.0.53')
})

test('历史问题-03：用户主动关闭仍清空，启用与水合 true 保留', () => {
  assert.equal(dnsServerAfterToggle('10.0.0.53', false, false), '')
  assert.equal(dnsServerAfterToggle('10.0.0.53', true, false), '10.0.0.53')
  assert.equal(dnsServerAfterToggle('10.0.0.53', true, true), '10.0.0.53')
})
