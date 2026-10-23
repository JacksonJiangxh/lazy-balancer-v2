// 管理面板 HTTPS 确认门：已保存的上传证书可沿用。
//
// 后端 PUT /admin-tls 在 mode=upload 且未携带 cert_file/key_file 时保留库内
// 证书材料（internal/handlers/admintls.go），故「关闭强制加密 → 再开启」不需要
// 重传文件。前端曾以「弹框里有 certInfo」为唯一放行条件，而 staged 证书在保存
// 成功后即清空 → 再次开启时「确定」恒灰、只能重传或改用自签（后者会清空上传
// 证书材料）。本用例钉住门判据 + 组件接线 + 部分成功披露。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { adminTlsConfirmDisabled, adminTlsReusesSavedCert } from '../src/utils/adminTlsGate.ts'
import { repoSource, section, source } from './_helpers.ts'

const stored = (overrides: Partial<{ savedMode: string; hasSavedCert: boolean; certError: string }> = {}) => ({
  savedMode: 'upload',
  hasSavedCert: true,
  certError: '',
  ...overrides,
})

const form = (overrides: Partial<{
  mode: string
  certFile: unknown
  keyFile: unknown
  certInfo: { days_left: number } | null
}> = {}) => ({
  mode: 'upload',
  certFile: null,
  keyFile: null,
  certInfo: null,
  ...overrides,
})

test('库内已保存上传证书：未选新文件即可确认启用', () => {
  assert.equal(adminTlsReusesSavedCert(stored(), form()), true)
  assert.equal(adminTlsConfirmDisabled(stored(), form()), false, '关闭后再开启不得要求重传文件')
})

test('库内证书损坏（cert_info_error 非空）必须重传', () => {
  const broken = stored({ certError: '证书已损坏' })
  assert.equal(adminTlsReusesSavedCert(broken, form()), false)
  assert.equal(adminTlsConfirmDisabled(broken, form()), true)
})

test('库内无可解析证书 / 已保存为自签时不沿用', () => {
  assert.equal(adminTlsConfirmDisabled(stored({ hasSavedCert: false }), form()), true)
  assert.equal(adminTlsConfirmDisabled(stored({ savedMode: 'selfsigned' }), form()), true)
})

test('用户选择了新文件但解析失败不得静默沿用旧证书', () => {
  const picked = form({ certFile: {}, keyFile: {} })
  assert.equal(adminTlsReusesSavedCert(stored(), picked), false)
  assert.equal(adminTlsConfirmDisabled(stored(), picked), true)
})

test('新证书已校验且未过期 → 放行；过期 → 拦截', () => {
  assert.equal(adminTlsConfirmDisabled(stored(), form({ certInfo: { days_left: 30 }, certFile: {}, keyFile: {} })), false)
  assert.equal(adminTlsConfirmDisabled(stored(), form({ certInfo: { days_left: 0 }, certFile: {}, keyFile: {} })), true)
})

test('自签模式不需要证书材料', () => {
  assert.equal(adminTlsConfirmDisabled(stored({ savedMode: 'selfsigned', hasSavedCert: true }), form({ mode: 'selfsigned' })), false)
})

test('组件接线：确定按钮与 confirmAdminTls 共用同一门', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  assert.match(page, /:disabled="adminTlsConfirmBlocked"/, '按钮必须消费统一判据')
  const confirm = section(page, 'const confirmAdminTls = () => {', 'loadAdminTls()')
  assert.match(confirm, /if \(adminTlsConfirmBlocked\.value\) return/)
  assert.match(confirm, /stagedAdminTlsCert\.value = mode === 'upload' && certFile && keyFile && certInfo/)
  // 沿用分支必须保持 staged 为空（载荷只发 enabled+mode，材料由后端保留）
  const save = section(page, 'const handleSave = async', 'emit(\'save\')')
  assert.match(save, /adminTlsHasCert\.value/, '保存门必须认「库内已有证书」')
})

test('沿用提示与全局样式类一致（无局部 hack）', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  const reuseBar = section(page, 'v-if="adminTlsReuseSaved', '</div>')
  assert.match(reuseBar, /class="info-note-bar"/)
  assert.match(reuseBar, /info-note-desc/)
})

test('/admin-tls 保存语义：不带材料即保留库内证书（跨栈对照）', () => {
  const go = repoSource('internal/handlers/admintls.go')
  assert.match(go, /cert, key := current\.Cert, current\.Key/, '默认沿用库内证书材料')
  assert.match(go, /if mode == "upload" && input\.hasUploadPayload\(\)/, '仅在带材料时才替换证书')
})

test('两段写：/config 已落库时 TLS 段失败须披露部分成功', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  const save = section(page, 'const handleSave = async', 'const message = (saveResp')
  assert.ok(
    save.indexOf("emit('save')") < save.indexOf("'/admin-tls'"),
    '父级刷新必须先于 TLS 段（否则 TLS 失败让基础设置看起来整单未生效）',
  )
  const tls = section(page, "if (tlsPending) {", '} else {')
  assert.match(tls, /silent: true/, 'TLS 段失败由本段自报部分成功，不得再弹全局「保存失败」')
  assert.match(tls, /基础设置已保存；HTTPS 配置保存失败/)
  const failure = section(tls, 'catch (tlsError)', '\n      }\n')
  assert.doesNotMatch(failure, /stagedAdminTlsCert\.value = null/, '失败时不得清除已暂存证书')
  assert.match(failure, /tlsError instanceof Error/, '失败原因必须取自后端错误文案')
})
