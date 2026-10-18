import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const source = (relative: string): string => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')

test('历史问题-历史问题：当前密码错误在页面本地 toast，拦截器复用精确分类', () => {
  const layout = source('src/components/layout/AppLayout.vue')
  assert.match(layout, /isCurrentPasswordRejection\('patch', '\/users\/me', error\.status, error\.message\)/)
  assert.match(layout, /authStore\.showToast\('error', error\.message\)/)
  assert.match(source('src/utils/api.ts'), /isCurrentPasswordRejection\(/)
})

test('历史问题-1：只有已启用信任命中才抑制新增信任', () => {
  const text = source('src/views/security/IPLocationAction.vue')
  const hit = text.indexOf('if (!mergedTrustEntries(policy).some')
  const enabled = text.indexOf('if (!policy.ip_whitelist_enabled) continue', hit)
  const trusted = text.indexOf('trusted = true', hit)
  assert.ok(hit > 0 && enabled > hit && trusted > enabled, 'trusted 赋值必须位于 enabled 门之后')
})

test('历史问题-2：引用列表仅精确条目可移除，removed=false 不得报成功', () => {
  const text = source('src/views/security/IPLocationAction.vue')
  assert.match(text, /const ipExactListIds = computed/)
  assert.match(text, /removableTrustRefLists[\s\S]*ipExactListIds\.value\.has/)
  assert.match(text, /removableRefLists[\s\S]*ipExactListIds\.value\.has/)
  assert.match(source('src/composables/useTrustAssociation.ts'), /res\.data\?\.removed !== true/)
})

test('历史问题-3：注册弹框记录打开时节点模式', () => {
  const text = source('src/views/settings/cluster/ClusterModeCard.vue')
  assert.match(text, /registrationOriginMode/)
  assert.match(text, /shouldCloseRegistrationDialog\(/)
})

test('历史问题-4：OIDC 保存门与响应落地都校验当前探测快照', () => {
  const text = source('src/views/settings/OIDCSettings.vue')
  assert.match(text, /probeGuard\.isCurrent\(/)
  assert.match(text, /probe\.key !== oidcProbeKey\(currentProbeValues\(\)\)/)
})

test('历史问题-5：流量游标使用回退检测并在 visibility 恢复时归零', () => {
  const text = source('src/views/security/ThreatScreen.vue')
  assert.match(text, /flowSince = nextFlowCursor\(flowSince, data\)/)
  const start = text.indexOf('function onVisibilityChange')
  const end = text.indexOf('// 大屏流量采集租约', start)
  assert.match(text.slice(start, end), /flowSince = 0/)
  assert.match(text, /flowCursorEpoch/)
  assert.match(text, /cursorEpoch !== flowCursorEpoch/)
})

test('历史问题-6：Dashboard 所有落地路径统一重建逐规则失败映射', () => {
  const text = source('src/views/Dashboard.vue')
  const calls = text.match(/ruleMetricsUnavailable\.value = buildRuleMetricsUnavailable\(/g) ?? []
  assert.ok(calls.length >= 4, `至少四个成功/失败/规则落地路径应复用 helper，实际 ${calls.length}`)
  assert.doesNotMatch(text, /if \(!caddyMetricsUnavailable\.value\) \{\s*ruleMetricsUnavailable/)
})

test('历史问题-7：混合策略只读视图复用独立黑名单生效谓词', () => {
  assert.match(source('src/views/security/SecurityPolicies.vue'), /hasIPACLControl\(d\) \? formatAclModeDetail\(ipLists\.value, d\) : '未启用'/)
})

test('历史问题-8：只读态隐藏迁移入口并保留函数级守卫', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /<el-button v-if="!isReadOnly" type="warning" @click="openMigrateFromView">/)
  const open = text.indexOf('const openMigrateDialog')
  const submit = text.indexOf('const submitMigrate')
  assert.match(text.slice(open, submit), /if \(isReadOnly\.value\) return/)
  assert.match(text.slice(submit, text.indexOf('// ── 混合策略只读查看', submit)), /if \(isReadOnly\.value\) return/)
})

test('历史问题-9：关联规则与预览步骤同样补齐引用名单条目', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  const start = text.indexOf('watch([currentStep, ipACLList')
  const end = text.indexOf('const hasContent', start)
  const watcher = text.slice(start, end)
  for (const step of ['IP_ACL', 'TRUST', 'BINDINGS', 'PREVIEW']) {
    assert.match(watcher, new RegExp(`WIZARD_STEP\\.${step}`))
  }
})

test('历史问题-10：事件名称搜索命中后自动切换到策略所在 tab', () => {
  assert.match(source('src/views/security/SecurityPolicies.vue'), /activeTypeTab\.value = policyTypeOf\(matched\)/)
})

test('历史问题-11：自动封禁卡片主体恢复配置点击入口', () => {
  assert.match(source('src/views/security/SecurityEvents.vue'), /<div\s+class="autoban-main"[^>]*@click="openAutobanConfig"/)
})

test('历史问题-02：默认上游分支不得显示无启用上游', () => {
  const text = source('src/components/RuleFlowDialog.vue')
  assert.match(text, /v-else-if="pr\.upstreams === null"/)
  assert.match(text, /跟随主路由上游/)
})

test('历史问题-03：关闭向导时复位 DNS 开关与服务器', () => {
  const text = source('src/views/Rules.vue')
  const start = text.indexOf('const resetWizard = () =>')
  const end = text.indexOf('const beforeWizardClose', start)
  const reset = text.slice(start, end)
  assert.match(reset, /wizardForm\.enable_dns_server = false/)
  assert.match(reset, /wizardForm\.dns_server = ''/)
})

test('历史问题-04：大屏显性披露回填未完成与汇总陈旧', () => {
  const text = source('src/views/security/ThreatScreen.vue')
  assert.match(text, /backfill_incomplete\?: boolean/)
  assert.match(text, /rollup_stale\?: boolean/)
  assert.match(text, /stats\?\.backfill_incomplete/)
  assert.match(text, /stats\?\.rollup_stale/)
})

test('H-历史问题：Vite 开发代理默认 HTTP，仅显式环境开关使用 HTTPS', () => {
  const text = source('vite.config.ts')
  assert.match(text, /VITE_DEV_BACKEND_HTTPS/)
  assert.match(text, /'http:\/\/localhost:8000'/)
  assert.doesNotMatch(text, /target:\s*'https:\/\/localhost:8000'/)
})
