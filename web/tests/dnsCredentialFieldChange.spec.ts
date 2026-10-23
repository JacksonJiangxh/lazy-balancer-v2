// DNS 凭证 select 变更处理器按字段元数据求值。
//
// 原实现把整个 dns_credentials 重置为 `{ auth_mode: 新值 }`——假定唯一 select
// 名为 auth_mode。新增含两个 select 的 provider（如「区域 + 认证模式」）时，改
// 第二个 select 会把第一个 select 与全部文本字段一并清空。新判据：只清理被
// visible_when 隐藏的字段，仍可见的值保留。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  applyCredentialFieldChange,
  credentialFieldVisible,
  type CredentialFieldMeta,
} from '../src/utils/dnsProviderFields.ts'
import { source } from './_helpers.ts'

const doubleSelectFields: readonly CredentialFieldMeta[] = [
  { name: 'region', label: '区域', type: 'select', required: true, options: ['cn', 'global'] },
  { name: 'auth_mode', label: '认证方式', type: 'select', required: true, options: ['token', 'pair'] },
  { name: 'token', label: 'Token', type: 'password', required: false, visible_when: { auth_mode: ['token'] } },
  { name: 'secret_id', label: 'SecretId', type: 'text', required: false, visible_when: { auth_mode: ['pair'] } },
]

const dnspodFields: readonly CredentialFieldMeta[] = [
  { name: 'auth_mode', label: '认证方式', type: 'select', required: true, options: ['dnspod', 'tencent_cloud'] },
  { name: 'app_id', label: 'App ID', type: 'text', required: false, visible_when: { auth_mode: ['dnspod'] } },
  { name: 'app_token', label: 'App Token', type: 'password', required: false, visible_when: { auth_mode: ['dnspod'] } },
  { name: 'secret_id', label: 'SecretId', type: 'text', required: false, visible_when: { auth_mode: ['tencent_cloud'] } },
  { name: 'secret_key', label: 'SecretKey', type: 'password', required: false, visible_when: { auth_mode: ['tencent_cloud'] } },
]

test('切换第二个 select 不清空第一个 select 与文本字段', () => {
  const next = applyCredentialFieldChange(
    doubleSelectFields,
    { region: 'cn', auth_mode: 'token', token: 'abc' },
  )
  assert.deepEqual(next, { region: 'cn', auth_mode: 'token', token: 'abc' })
})

test('切换认证模式只清理被 visible_when 隐藏的字段', () => {
  const next = applyCredentialFieldChange(
    dnspodFields,
    { auth_mode: 'tencent_cloud', app_id: 'id', app_token: 'tok', secret_id: 'sid', secret_key: 'skey' },
  )
  assert.deepEqual(next, { auth_mode: 'tencent_cloud', secret_id: 'sid', secret_key: 'skey' })
})

test('切回原模式保留新模式下填写的值（仅隐藏面被清理）', () => {
  const next = applyCredentialFieldChange(
    dnspodFields,
    { auth_mode: 'dnspod', app_id: 'id', secret_id: 'sid' },
  )
  assert.deepEqual(next, { auth_mode: 'dnspod', app_id: 'id' })
})

test('未声明字段保留（不静默丢弃非表单键）', () => {
  const next = applyCredentialFieldChange(dnspodFields, { auth_mode: 'dnspod', mode: 'legacy' })
  assert.equal(next.mode, 'legacy')
})

test('求值不修改入参', () => {
  const credentials = { auth_mode: 'tencent_cloud', app_id: 'id' }
  applyCredentialFieldChange(dnspodFields, credentials)
  assert.deepEqual(credentials, { auth_mode: 'tencent_cloud', app_id: 'id' })
})

test('组件接线：select 变更按字段求值，无 auth_mode 字面量重置', () => {
  const page = source('src/views/settings/FreeCertificates.vue')
  assert.match(page, /@change="onCredentialFieldChange"/)
  assert.match(page, /applyCredentialFieldChange\(\n?\s*selectedProvider\.value\?\.credential_fields \?\? \[\],\n?\s*form\.value\.dns_credentials,/)
  assert.doesNotMatch(page, /onAuthModeChange/)
  assert.doesNotMatch(page, /dns_credentials = \{ auth_mode: authMode\.value \}/)
  assert.doesNotMatch(page, /const authMode = computed\(/)
  // 可见性与变更处理器同源：都走 credentialFieldVisible 的元数据口径
  assert.match(page, /credentialFieldVisible\(field, form\.value\.dns_credentials\)/)
  assert.ok(
    credentialFieldVisible(dnspodFields[1], { auth_mode: 'dnspod' }),
    '元数据可见性契约不变',
  )
})
