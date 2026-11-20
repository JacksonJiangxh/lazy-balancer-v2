// file 源证书路径编辑回显契约钉测（JJC-20261120-001 方案 A）：
//   A. openWizard/openCopyWizard 对 file 源规则发 GET /rules/:id——GET 条件按
//      tls_source 单条件（manual ∪ file）、与 enable_tls 解耦（列表投影有意置空
//      路径列，file 源编辑必须经详情投影回显摄取源路径）
//   B. markTlsDetailFailed 两调用点带 enable_tls 守卫（TLS-off 行 TLS 步不可达，
//      GET 失败禁保存后无自救路径——不置 tlsDetailError，由写侧语义兜底）
//   C. 保存按钮禁用门实址（tlsDetailError && tls_source === 'manual'）不被放宽
//
// 运行：cd web && node --test tests/ruleFileSourceEdit.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, member } from './_helpers.ts'

const page = code('src/views/Rules.vue')

const GET_CONDITION = "rule.tls_source === 'manual' || rule.tls_source === 'file'"
const LEGACY_CONDITION = "rule.enable_tls && rule.tls_source === 'manual'"

test('A1 openWizard 对 manual ∪ file 源发 GET /rules/:id（enable_tls 前缀禁回流）', () => {
  const body = member(page, 'const openWizard = async')
  assert.match(body, new RegExp(`if \\(${GET_CONDITION.replace(/[$()*+.?[\\^{|]/g, '\\$&')}\\)`), 'GET 条件须为 tls_source 单条件（manual ∪ file）')
  assert.match(body, /request\.get<APIResponse<Rule>>\(`\/rules\/\$\{rule\.caddy_id\}`\)/, 'file 源编辑必须经详情投影回显（列表投影有意置空路径列）')
  assert.doesNotMatch(body, new RegExp(LEGACY_CONDITION.replace(/[$()*+.?[\\^{|]/g, '\\$&')), 'enable_tls 前缀回流会让 TLS-off file 行编辑回显缺失')
})

test('A2 openCopyWizard 同条件（复制 file 源规则同样回显路径）', () => {
  const body = member(page, 'const openCopyWizard = async')
  assert.match(body, new RegExp(`if \\(${GET_CONDITION.replace(/[$()*+.?[\\^{|]/g, '\\$&')}\\)`), 'GET 条件须为 tls_source 单条件（manual ∪ file）')
  assert.match(body, /request\.get<APIResponse<Rule>>\(`\/rules\/\$\{rule\.caddy_id\}`\)/, '复制须拉详情回显摄取源路径')
  assert.doesNotMatch(body, new RegExp(LEGACY_CONDITION.replace(/[$()*+.?[\\^{|]/g, '\\$&')), 'enable_tls 前缀禁回流')
})

test('B markTlsDetailFailed 两调用点带 enable_tls 守卫（TLS-off 不禁保存）', () => {
  const guard = /if \(rule\.enable_tls\) markTlsDetailFailed\(rule\.caddy_id\)/
  assert.match(member(page, 'const openWizard = async'), guard, 'openWizard catch 分支须守卫')
  assert.match(member(page, 'const openCopyWizard = async'), guard, 'openCopyWizard catch 分支须守卫')
  // 无守卫的裸调用禁回流（缩进行直接 markTlsDetailFailed(...)）
  assert.doesNotMatch(page, /^\s+markTlsDetailFailed\(rule\.caddy_id\)$/m, '裸调用会让 TLS-off 行 GET 失败后无自救路径')
})

test('C 保存按钮禁用门实址：tlsDetailError && tls_source === manual（不放宽）', () => {
  assert.match(
    page,
    /:disabled="tlsDetailError && wizardForm\.tls_source === 'manual'"/,
    '保存禁用门实址（Rules.vue 确认步按钮）不得放宽',
  )
})
