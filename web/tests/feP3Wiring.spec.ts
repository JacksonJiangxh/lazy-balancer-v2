// 前端基座/设置/安全域的接线验收（每条对应一个可回归的接线点）：
// 死契约删除、表单上限与写侧门对齐、慢车道解耦、会话序号无条件自增、
// 命中索引与手势输入集同源、隐藏谓词的信任侧、大屏层级。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, repoSource, section, source } from './_helpers.ts'

test('个人资料弹框不再保留无人消费的自动聚焦契约', () => {
  const dialog = source('src/components/ProfileDialog.vue')
  assert.doesNotMatch(dialog, /focusField/, 'focusField 全仓零消费方，属残留对外契约')
  assert.doesNotMatch(dialog, /passwordInput\.value\?\.focus\(\)|displayNameInput\.value\?\.focus\(\)/, '自动聚焦分支必须删除')
  // 唯一消费方只传 v-model
  const layout = source('src/components/layout/AppLayout.vue')
  assert.match(layout, /<ProfileDialog v-model="showProfile" \/>/)
})

test('表格标签居中的 flex 规则必须记录混合单元格省略号取舍', () => {
  const css = source('src/styles/main.css')
  const rule = section(css, '.el-table .cell:has(.el-tag) {', '}')
  assert.match(rule, /display: inline-flex/, '标签居中形态保持不变')
  const comment = section(css, '/* 表格单元格标签垂直居中', '.el-table .cell:has(.el-tag) {')
  assert.match(comment, /text-overflow 对匿名项不生效|匿名 flex 项|混合单元格/, '必须写明混合单元格失去省略号的取舍')
  assert.match(comment, /tooltip/, '必须写明可发现性（tooltip）不受影响')
})

test('策略绑定写路径显式声明「最后写入生效」的并发口径', () => {
  const editor = source('src/components/SecurityBindingEditor.vue')
  const doc = section(editor, '// 绑定写路径的并发口径', 'const submit = async')
  assert.match(doc, /最后写入生效|后写覆盖前写/, '必须声明无乐观并发护栏')
  assert.match(doc, /版本前置条件|409/, '必须写明根治需要后端前置条件')
  // 绑定端点不接受 expected_updated_at：不得悄悄发送一个后端会忽略的字段
  const submit = section(editor, 'const submit = async', '\n}\n')
  assert.doesNotMatch(submit, /expected_updated_at/, '绑定端点未实现版本前置条件，不得发无用字段')
})

test('表单上限与后端写侧门对齐（证书重签天数 / HTTP 超时）', () => {
  const cert = source('src/views/settings/FreeCertificates.vue')
  assert.match(cert, /cert_renewal_days" :min="1" :max="CERT_RENEWAL_DAYS_MAX"/, '控件上限必须引用单源常量')
  assert.doesNotMatch(cert, /cert_renewal_days[^>]*:max="60"/, '60 只是建议值，不得作为硬上限（会把 API/导入写入的 61-88 静默夹回）')
  const configValues = source('src/utils/configValues.ts')
  assert.match(configValues, /export const CERT_RENEWAL_DAYS_MAX = 88/, '上限常量必须是写侧门同值')
  // 跨栈钉：后端上界 = 规划寿命 90 − 2
  const certinfo = repoSource('internal/services/certinfo.go')
  assert.match(certinfo, /const CertRenewalLifetimeDays = 90/)
  assert.match(certinfo, /const CertRenewalDaysMax = CertRenewalLifetimeDays - 2/)

  const caddy = source('src/views/settings/CaddyGlobalSettings.vue')
  for (const field of ['http_read_timeout', 'http_write_timeout', 'http_idle_timeout']) {
    const line = caddy.split('\n').find((l) => l.includes(`v-model="settings.${field}"`))
    assert.ok(line, `${field} 控件必须存在`)
    assert.doesNotMatch(line, /:max=/, `${field} 不得硬限 86400——后端写侧门只要求 ≥1，控件夹紧会静默改写合法库值`)
    assert.match(line, /:min="1"/)
  }
  // 提示文案同步：不再是「必须为 1-86400」
  assert.doesNotMatch(caddy, /必须为 1-86400/, '提示文案不得再声称后端不存在的时间上限')
  assert.match(caddy, /必须 ≥1/)
})

test('Dashboard 慢车道健康查询不得阻塞整轮刷新', () => {
  const page = code('src/views/Dashboard.vue')
  assert.match(page, /void fetchRuleHealth\(currentRules, version, roundSignal\)/, '健康查询必须 fire-and-forget（版本守卫已足够）')
  assert.doesNotMatch(page, /await fetchRuleHealth\(currentRules, version, roundSignal\)/, 'await 会把系统指标/流量/连接一起拖慢')
  // 收尾补跑仍在函数内部 await（顺序语义必要）
  assert.match(page, /await fetchRuleHealth\(pending\.rules, pending\.version\)/, '更新版本补跑必须保持串行')
})

test('时间戳两族的边界写在 formatDate 文档里', () => {
  const date = source('src/utils/date.ts')
  const doc = section(date, '/**\n * 站内时间戳有两族', 'export const formatDate')
  assert.match(doc, /UTC 存储族/)
  assert.match(doc, /task_runs/, '必须点名禁止面（配置时区墙钟族）')
  assert.match(doc, /格式化为|不得混用|formatDate/, '必须写明入口归属')
})

test('策略向导拦截页步骤纳入引用条目懒加载门', () => {
  const page = source('src/views/security/SecurityPolicies.vue')
  const gate = member(page, 'watch([currentStep, ipACLList, ipWhitelist, ipACLListRefs, ipWhitelistRefs], ')
  assert.match(gate, /step !== WIZARD_STEP\.BLOCK_PAGE/, '拦截页能力门消费合并条目数，必须预取引用条目')
})

test('信任侧冲突警告的门控位置与注释一致（computed 内）', () => {
  const page = source('src/views/security/SecurityPolicies.vue')
  const doc = section(page, '// 名单生效口径与保存语义对齐', 'const entrySourceSuffix')
  assert.doesNotMatch(doc, /仅模板\s*$/m, '注释不得声称门控只在模板层')
  assert.match(doc, /门控在 computed 内/)
  const alert = section(page, 'const whitelistSectionAlert = computed<string>(', '  if (trust.length === 0)')
  assert.match(alert, /ipWhitelistEnabled\.value \? mergeIpEntries/, '实现口径：信任关闭时条目零生效')
})

test('IP 快捷弹框的隐藏谓词必须看信任侧命中', () => {
  const page = source('src/views/security/IPLocationAction.vue')
  const predicate = member(page, 'const aclRefsAllSystem = ')
  assert.match(predicate, /mergedTrustEntries\(p\)/, '被隐藏卡的信任侧命中会让「取消信任」无入口')
  assert.match(predicate, /ip_whitelist_enabled/, '信任关闭时条目零生效，不构成保留理由')
})

test('威胁大屏：攻击弹框层级高于错误条堆叠，且错误条默认点击穿透', () => {
  const page = source('src/views/security/ThreatScreen.vue')
  const toastZ = Number(page.match(/\.toasts \{[^}]*z-index: (\d+)/)?.[1] ?? 0)
  const stackZ = Number(page.match(/\.error-stack \{[^}]*z-index: (\d+)/)?.[1] ?? 0)
  assert.ok(toastZ > stackZ, `攻击弹框必须在错误条之上（toasts=${toastZ}, error-stack=${stackZ}）`)
  const stack = section(page, '.error-stack {', '}')
  assert.match(stack, /pointer-events: none/, '错误条不得拦截其下弹框点击')
  assert.match(page, /\.error-stack \.error-retry \{ pointer-events: auto; \}/, '重试按钮必须可点')
})

test('规则流程弹框会话打开即作废在途证书响应', () => {
  const dialog = source('src/components/RuleFlowDialog.vue')
  const open = member(dialog, 'const onDialogOpen = ')
  assert.match(open, /detailsSeq\+\+[\s\S]*?certSeq\+\+/, '打开时必须无条件自增证书序号（非 TLS 规则也要作废上一会话）')
  assert.match(open, /certSeq\+\+\s*\n\s*detailLoading\.value = false/, '自增必须与其它会话状态重置同处')
})
