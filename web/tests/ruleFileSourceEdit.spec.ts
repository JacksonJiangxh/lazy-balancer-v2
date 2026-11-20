// file 源证书路径编辑回显契约钉测（JJC-20261120-001 方案 A + JJC-20261120-002 B 线）：
//   A. openWizard/openCopyWizard 对 file 源规则发 GET /rules/:id——GET 条件按
//      tls_source 单条件（manual ∪ file）、与 enable_tls 解耦（列表投影有意置空
//      路径列，file 源编辑必须经详情投影回显摄取源路径）
//   B. markTlsDetailFailed 两调用点按 tls_source ∈ {manual,file} 守卫（20261120-002：
//      enable_tls 守卫退役——file 行 GET 失败同置错误态，消灭无提示的保存死路）
//   C. 失败阻断态单源 computed tlsDetailBlocked（manual ∪ file）：横幅+重试上提
//      向导头部（任意步可见可达）、保存禁用门、submitWizard 预拦三处同源消费；
//      file 行文案「证书文件路径无法回显，保存前请重新加载」
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

test('B1 markTlsDetailFailed 两调用点按 tls_source ∈ {manual,file} 守卫（enable_tls 守卫退役）', () => {
  const guard = /if \(rule\.tls_source === 'manual' \|\| rule\.tls_source === 'file'\) markTlsDetailFailed\(rule\.caddy_id\)/
  assert.match(member(page, 'const openWizard = async'), guard, 'openWizard catch 分支须按 tls_source 守卫（file 行失败不再静默）')
  assert.match(member(page, 'const openCopyWizard = async'), guard, 'openCopyWizard catch 分支同守卫')
  // 变异自证：回退 enable_tls 守卫即红
  assert.doesNotMatch(page, /if \(rule\.enable_tls\) markTlsDetailFailed\(rule\.caddy_id\)/, 'enable_tls 守卫回流会复活 file 行「无提示的保存死路」')
})

test('C1 单源 computed tlsDetailBlocked = tlsDetailError && source ∈ {manual,file}', () => {
  assert.match(
    page,
    /const tlsDetailBlocked = computed\(\(\) => tlsDetailError\.value && \['manual', 'file'\]\.includes\(wizardForm\.tls_source\)\)/,
    '阻断态须单源 computed（manual ∪ file），防三处条件各自漂移',
  )
  // 三处消费面（保存禁用门 / submitWizard 预拦 / 头部横幅 v-if）
  assert.match(page, /:disabled="tlsDetailBlocked"/, '保存按钮禁用门须消费单源 computed')
  assert.match(page, /if \(tlsDetailBlocked\.value\)/, 'submitWizard TLS 步预拦须消费单源 computed')
  assert.match(page, /v-if="tlsDetailBlocked"/, '向导头部横幅须消费单源 computed')
  // 旧的双键条件禁回流
  assert.doesNotMatch(page, /:disabled="tlsDetailError && wizardForm\.tls_source === 'manual'"/, '旧内联条件禁回流（单源防漂移）')
})

test('C2 横幅+重试上提向导头部：任意步可见（PREVIEW 步可达），TLS 步内容区不再承载', () => {
  // 横幅必须落在 el-steps（步骤区）之前——即向导头部、任何 step-content 之外
  const bannerAt = page.indexOf('v-if="tlsDetailBlocked"')
  assert.ok(bannerAt >= 0, '头部横幅缺失')
  const stepsAt = page.indexOf('<el-steps')
  assert.ok(stepsAt > bannerAt, '横幅须位于向导步骤区（el-steps）之前——任意步可见')
  const contentStart = page.indexOf('class="wizard-content"')
  assert.ok(contentStart > bannerAt, '横幅须在 wizard-content（各步内容区）之外')
  // TLS 步内容区不得再持有旧横幅（否则同屏双横幅/语义分裂）
  assert.equal(
    page.indexOf('v-if="tlsDetailBlocked"', contentStart),
    -1,
    'wizard-content 内不得重复承载失败横幅（已上提头部）',
  )
  // 重试按钮与横幅同块（任意步可达重试）
  const banner = page.slice(bannerAt - 200, page.indexOf('</div>', bannerAt) + 6)
  assert.match(banner, /@click="retryTlsDetail"/, '重试按钮须与横幅同块——PREVIEW 步也可点')
})

test('C3 file 行失败文案「证书文件路径无法回显，保存前请重新加载」', () => {
  assert.match(page, /证书文件路径无法回显，保存前请重新加载/, 'file 源失败文案缺失（用户可见）')
})

test('C4 四态钉：失败→提示可见（任意步）→重试可达→恢复后保存门解除', () => {
  // 状态机由模板/脚本结构钉死：
  // ① 失败：markTlsDetailFailed 置位（B1 两调用点）→ tlsDetailError=true
  // ② 提示可见：横幅 v-if="tlsDetailBlocked"（任意步，C2 落位头部）
  // ③ 重试可达：retryTlsDetail 挂横幅内按钮（C2），通用 GET 回填按 tlsDetailRuleId
  assert.match(page, /function retryTlsDetail/, '重试入口缺失')
  // ④ 恢复：retryTlsDetail 成功路径清 tlsDetailError → 保存门（tlsDetailBlocked）自动解除
  const retry = member(page, 'function retryTlsDetail')
  assert.match(retry, /tlsDetailError\.value = false/, '重试成功路径必须清 tlsDetailError——保存门随之解除')
})
