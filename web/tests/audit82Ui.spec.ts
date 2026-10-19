import { test } from 'node:test'
import assert from 'node:assert/strict'

import { source } from './_helpers.ts'

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
  // 审计 87 WEBT-11：原正则 /removableTrustRefLists[\s\S]*?\.map\(...\)/ 的惰性
  // 终点仍可跨语句——信任侧 .map 被重构掉时会延伸到 ACL 赋值（同形 .map），
  // 由 ACL 的精确条目过滤让断言通过。改为「语句级限段（到下一个行首注释）+
  // 各自 refs 过滤谓词」：两个赋值必须各自按本侧 refs + 精确条目双重过滤。
  const statementBlock = (head: string): string => {
    const start = text.indexOf(head)
    assert.ok(start >= 0, `${head} 未找到`)
    const end = text.indexOf('\n  //', start)
    assert.ok(end > start, `${head} 语句块缺终止边界`)
    return text.slice(start, end)
  }
  const trustBlock = statementBlock('view.removableTrustRefLists = ipLists.value')
  assert.match(trustBlock, /trustRefIds\.includes\(l\.id\)/, '信任引用移除列表必须按信任 refs 过滤')
  assert.match(trustBlock, /ipExactListIds\.value\.has\(l\.id\)/, '信任引用移除列表必须过滤为精确条目命中')
  assert.match(trustBlock, /\.map\(\(l\) => \(\{ id: l\.id, name: l\.name \}\)\)/)
  const aclBlock = statementBlock('view.removableRefLists = ipLists.value')
  assert.match(aclBlock, /ip_acl_list_refs\)\.includes\(l\.id\)/, 'ACL 引用移除列表必须按 ACL refs 过滤')
  assert.match(aclBlock, /ipExactListIds\.value\.has\(l\.id\)/, 'ACL 引用移除列表必须过滤为精确条目命中')
  assert.match(aclBlock, /\.map\(\(l\) => \(\{ id: l\.id, name: l\.name \}\)\)/)
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
  // A86 历史问题 起 visible 恢复语义纳管在 screenLoop.onVisible（原 onVisibilityChange）。
  const start = text.indexOf('onVisible: () => {')
  const end = text.indexOf('\n})', start)
  assert.match(text.slice(start, end), /flowSince = 0/)
  assert.match(text, /flowCursorEpoch/)
  assert.match(text, /cursorEpoch !== flowCursorEpoch/)
})

test('历史问题-6：Dashboard 所有落地路径统一重建逐规则失败映射', () => {
  const text = source('src/views/Dashboard.vue')
  // 审计 87 WEBT-05⑥：原断言只数 helper 调用次数 >=4——不证明「所有落地路径」，
  // 原 bug 恰是某一路径绕过 helper 直接赋值且计数仍够。改为反向断言：任何
  // ruleMetricsUnavailable 赋值都必须经 helper（绕过即红），且至少四条落地路径。
  const assignments = [...text.matchAll(/ruleMetricsUnavailable\.value = ([^\n]*)/g)]
  assert.ok(assignments.length >= 4, `指标落地路径不足: ${assignments.length}`)
  for (const assignment of assignments) {
    assert.match(assignment[1], /^buildRuleMetricsUnavailable\(/, `绕过 helper 的落地路径: ${assignment[0]}`)
  }
  assert.doesNotMatch(text, /if \(!caddyMetricsUnavailable\.value\) \{\s*ruleMetricsUnavailable/)
})

test('历史问题-7：混合策略只读视图复用独立黑名单生效谓词', () => {
  // 审计 87 WU-09 残余：展示口径改为「ip_acl_enabled 开启 或 内容门命中」——
  // 后端 SecurityPolicyHasIPControl 对开启 flag 即算有 AC 管控面，含信任的
  // has_ip_control 摘要标志不得用于本列（会把纯信任策略说成 ACL 生效）。
  assert.match(source('src/views/security/SecurityPolicies.vue'), /ip_acl_enabled === true \|\| hasIPACLControl\(d\) \? formatAclModeDetail\(ipLists\.value, d\) : '未启用'/)
})

test('历史问题-8：只读态隐藏迁移入口并保留函数级守卫', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /<el-button v-if="!isReadOnly" type="warning" @click="openMigrateFromView">/)
  const open = text.indexOf('const openMigrateDialog')
  const submit = text.indexOf('const submitMigrate')
  assert.match(text.slice(open, submit), /if \(isReadOnly\.value\) return/)
  assert.match(text.slice(submit, text.indexOf('// ── 混合策略只读查看', submit)), /if \(isReadOnly\.value \|\| migrateSaving\.value\) return/)
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
  // 审计 87 WEBT-05⑤：原断言只钉 `?: boolean` 类型声明（类型契约由 vue-tsc 承担）。
  // 改为钉渲染接线：两个标志各自绑定独立横幅且文案区分（回填未完成 vs 汇总延迟）。
  const text = source('src/views/security/ThreatScreen.vue')
  assert.match(
    text,
    /v-if="stats\?\.backfill_incomplete"[\s\S]{0,400}?历史统计回填尚未完成/,
    '回填未完成必须渲染显性横幅',
  )
  assert.match(
    text,
    /v-if="stats\?\.rollup_stale"[\s\S]{0,200}?统计汇总更新延迟/,
    '汇总陈旧必须渲染独立横幅（不得与回填提示合并或静默）',
  )
  // 原始事件覆盖不足时披露覆盖起点（不得泛化成同一条「回填未完成」）
  assert.match(text, /rawCoverageGap[\s\S]{0,200}?raw_coverage_from/)
})

test('H-历史问题：Vite 开发代理默认 HTTP，仅显式环境开关使用 HTTPS', () => {
  const text = source('vite.config.ts')
  assert.match(text, /VITE_DEV_BACKEND_HTTPS/)
  assert.match(text, /'http:\/\/localhost:8000'/)
  assert.doesNotMatch(text, /target:\s*'https:\/\/localhost:8000'/)
})

// ---- 审计 87 安全视图接线钉（已从 audit87SecurityViews.spec.ts 撤并；可纯函数化的
//      语义在 securityLibraries / blockPageAttribution / policyPayload / triggeredFilter
//      各 spec 做行为求值，此处只钉「视图是否真的接了实现」）----

test('W87-02/W87-10：库计数列文案与「数量 / 大小」列义', () => {
  const text = source('src/views/security/SecurityRules.vue')
  assert.match(text, /crsRuleCountLabel\(crsInfo\.value\.rule_count\)/)
  assert.doesNotMatch(text, /个文件/)
  assert.match(text, /label="数量 \/ 大小"/)
  // IP 地理库字节数带单位（formatSize）
  assert.match(text, /formatSize\(ip2regionInfo\.value\.db_size\)/)
})

test('W87-03：爬虫豁免空引擎保存守卫（单源谓词）', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /if \(crawlerExemptionNeedsEngines\(\{ geoipEnabled: form\.value\.geoip_enabled, crawlerExempt: form\.value\.geoip_crawler_exempt, engines: form\.value\.geoip_crawler_engines \}\)\)/)
  assert.match(text, /空选等于豁免「全部引擎」/)
  // 空选时的行内提示（用户不必点保存才知道语义）
  assert.match(text, /v-if="form\.geoip_crawler_engines\.length === 0"/)
})

test('W87-04：主列表失败可辨识（错误态 + 横幅重试 + 空态文案切换）', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /const policiesLoadError = ref\(false\)/)
  assert.match(text, /v-if="policiesLoadError" type="error"/)
  assert.match(text, /:loading="loading" @click="fetchData">立即重试/)
  // 空态：失败与「确实没有策略」不同形
  assert.match(text, /v-if="!policiesLoadError" description="暂无安全策略"/)
  // 两条失败路径（rejected / catch）都置错误态，成功路径复位
  const rejected = text.indexOf("if (polRes.status === 'rejected')")
  const setErr = text.indexOf('policiesLoadError.value = true', rejected)
  assert.ok(rejected > 0 && setErr > rejected, 'rejected 分支必须置错误态')
  assert.match(text, /policies\.value = polRes\.value\.data \|\| \[\]\s*\n\s*policiesLoadError\.value = false/)
})

test('W87-06：自动封禁口径文案不再自缩为「WAF 事件」', () => {
  const events = source('src/views/security/SecurityEvents.vue')
  assert.doesNotMatch(events, /WAF 事件固定窗口计数/)
  assert.match(events, /安全事件（IP 访问控制\/地域\/WAF\/威胁情报，已验证爬虫豁免除外）固定窗口计数/)
})

test('W87-07：IP 快捷弹框全流程使用 trim 后的地址（无裸 props.ip 消费）', () => {
  const text = source('src/views/security/IPLocationAction.vue')
  assert.match(text, /const trimmedIp = computed\(\(\) => props\.ip\.trim\(\)\)/)
  // 只剩 computed 自身的 props.ip 读取 + 注释
  const bare = text.match(/props\.ip(?!\.trim)/g) ?? []
  assert.equal(bare.length, 1, `只允许 computed 定义处读取 props.ip，实际 ${bare.length}`)
  // 移除/legacy 判定路径都用归一值
  assert.match(text, /inLegacy: parseIPList\(policy\.ip_blacklist\)\.includes\(trimmedIp\.value\)/)
  assert.match(text, /if \(!list\.includes\(trimmedIp\.value\)\)/)
  assert.match(text, /entry !== trimmedIp\.value/)
})

test('W87-08：拦截页删除重入守卫（确认前占位、finally 释放）', () => {
  const text = source('src/views/security/SecurityBlockPages.vue')
  const guard = text.indexOf('if (deletingId.value !== null) return')
  const confirm = text.indexOf('ElMessageBox.confirm(`确定删除拦截页面')
  const release = text.indexOf('deletingId.value = null')
  assert.ok(guard > 0, '必须有重入守卫')
  assert.ok(confirm > guard, '守卫必须先于确认框（先占位再弹）')
  assert.ok(release > confirm, 'finally 必须释放占位')
  assert.match(text, /:loading="deletingId === row\.id"/)
})

test('W87-09：阶段页覆盖写入按 skipped 归集后再回写（不谎报已覆盖）', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  const skippedSet = text.indexOf('const skippedIds = new Set(skippedItems.map((item) => item.rule_id))')
  const apply = text.indexOf('applyStageOverrideSuccess(caddyId, edit)', skippedSet)
  assert.ok(skippedSet > 0 && apply > skippedSet, '必须先归集 skipped 再回写成功态')
  assert.match(text, /if \(!skippedIds\.has\(caddyId\)\) applyStageOverrideSuccess/)
  // 行内状态：未写入 + 原因；成功计数不把 skipped 计入
  assert.match(text, /\? '未写入' :/)
  assert.match(text, /const syncedCount = pendingOverrides\.length - skippedNotes\.length/)
})

test('W87-13：名单详情 GET 静默，避免与全局拦截器双 toast', () => {
  const text = source('src/views/security/SecurityRules.vue')
  const silentGets = text.match(/security\/ip-lists\/\$\{[^}]+\}`, \{ silent: true \}\)/g) ?? []
  assert.equal(silentGets.length, 2, `详情与重试两处请求都应 silent，实际 ${silentGets.length}`)
  // 本地提示保留（带「已禁用保存」动作信息）
  assert.match(text, /加载列表条目失败，已禁用保存；请重新加载/)
})

test('W87-16：库状态未知时自动更新开关显示「—」而非默认开', () => {
  const text = source('src/views/security/SecurityRules.vue')
  assert.match(text, /autoUpdateKnown: !crsInfoError\.value && crsInfoLoaded\.value/)
  assert.match(text, /autoUpdateKnown: threatLibLoaded\.value && !threatLibError\.value/)
  assert.match(text, /v-if="!row\.autoUpdateKnown"/)
  assert.match(text, /<el-switch v-else :model-value="row\.autoUpdate"/)
})
