import { test } from 'node:test'
import assert from 'node:assert/strict'

import { member, section, source, stripComments } from './_helpers.ts'

test('当前密码错误在页面本地 toast，拦截器复用精确分类', () => {
  const layout = source('src/components/layout/AppLayout.vue')
  assert.match(layout, /isCurrentPasswordRejection\('patch', '\/users\/me', error\.status, error\.message\)/)
  assert.match(layout, /authStore\.showToast\('error', error\.message\)/)
  assert.match(source('src/utils/api.ts'), /classifyAuthFailure\(/)
  // 401 分类判据单源在 utils/apiFailure（拦截器只做处置分派）
  assert.match(source('src/utils/apiFailure.ts'), /isCurrentPasswordRejection\(/)
})

test('只有已启用信任命中才抑制新增信任', () => {
  const text = source('src/views/security/IPLocationAction.vue')
  const hit = text.indexOf('if (!mergedTrustEntries(policy).some')
  const enabled = text.indexOf('if (!policy.ip_whitelist_enabled) continue', hit)
  const trusted = text.indexOf('trusted = true', hit)
  assert.ok(hit > 0 && enabled > hit && trusted > enabled, 'trusted 赋值必须位于 enabled 门之后')
})

test('引用列表仅精确条目可移除，removed=false 不得报成功', () => {
  const text = source('src/views/security/IPLocationAction.vue')
  assert.match(text, /const ipExactListIds = computed/)
  // 原正则 /removableTrustRefLists[\s\S]*?\.map\(...\)/ 的惰性
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

test('注册弹框记录打开时节点模式', () => {
  const text = source('src/views/settings/cluster/ClusterModeCard.vue')
  assert.match(text, /registrationOriginMode/)
  assert.match(text, /shouldCloseRegistrationDialog\(/)
})

test('OIDC 保存门与响应落地都校验当前探测快照', () => {
  const text = source('src/views/settings/OIDCSettings.vue')
  assert.match(text, /probeGuard\.isCurrent\(/)
  assert.match(text, /probe\.key !== oidcProbeKey\(currentProbeValues\(\)\)/)
})

test('流量游标使用回退检测并在 visibility 恢复时归零', () => {
  const text = source('src/views/security/ThreatScreen.vue')
  assert.match(text, /flowSince = nextFlowCursor\(flowSince, data\)/)
  // visible 恢复语义纳管在 screenLoop.onVisible（原 onVisibilityChange）。
  assert.match(section(text, 'onVisible: () => {', '\n})'), /flowSince = 0/)
  assert.match(text, /flowCursorEpoch/)
  assert.match(text, /cursorEpoch !== flowCursorEpoch/)
})

test('Dashboard 所有落地路径统一重建逐规则失败映射', () => {
  const text = source('src/views/Dashboard.vue')
  // 原断言只数 helper 调用次数 >=4——不证明「所有落地路径」，
  // 原 bug 恰是某一路径绕过 helper 直接赋值且计数仍够。改为反向断言：任何
  // ruleMetricsUnavailable 赋值都必须经 helper（绕过即红），且至少四条落地路径。
  const assignments = [...text.matchAll(/ruleMetricsUnavailable\.value = ([^\n]*)/g)]
  assert.ok(assignments.length >= 4, `指标落地路径不足: ${assignments.length}`)
  for (const assignment of assignments) {
    assert.match(assignment[1], /^buildRuleMetricsUnavailable\(/, `绕过 helper 的落地路径: ${assignment[0]}`)
  }
  assert.doesNotMatch(text, /if \(!caddyMetricsUnavailable\.value\) \{\s*ruleMetricsUnavailable/)
  // 「已落地」与「可用」分离：dashboard 未到达前不得判定采集失败；
  // 成功与失败两条落地路径都要置 landed，/rules 重建必须同时看 landed+可用。
  assert.equal([...text.matchAll(/dashboardMetricsLanded\.value = true/g)].length, 2, 'dashboard 成功/失败两条路径都必须置「已落地」')
  assert.match(text, /dashboardMetricsLanded\.value && !caddyMetricsUnavailable\.value/,
    '/rules 重建必须用「已落地 && 可用」，避免首轮误标采集失败')
})

test('混合策略只读视图复用独立黑名单生效谓词', () => {
  // 展示口径改为「ip_acl_enabled 开启 或 内容门命中」——
  // 后端 SecurityPolicyHasIPControl 对开启 flag 即算有 AC 管控面，含信任的
  // has_ip_control 摘要标志不得用于本列（会把纯信任策略说成 ACL 生效）。
  assert.match(source('src/views/security/SecurityPolicies.vue'), /ip_acl_enabled === true \|\| hasIPACLControl\(d\) \? formatAclModeDetail\(ipLists\.value, d\) : '未启用'/)
})

test('只读态隐藏迁移入口并保留函数级守卫', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /<el-button v-if="!isReadOnly" type="warning" @click="openMigrateFromView">/)
  assert.match(section(text, 'const openMigrateDialog', 'const submitMigrate'), /if \(isReadOnly\.value\) return/)
  assert.match(section(text, 'const submitMigrate', '// ── 混合策略只读查看'), /if \(isReadOnly\.value \|\| migrateSaving\.value\) return/)
})

test('关联规则与预览步骤同样补齐引用名单条目', () => {
  const watcher = section(source('src/views/security/SecurityPolicies.vue'), 'watch([currentStep, ipACLList', 'const hasContent')
  for (const step of ['IP_ACL', 'TRUST', 'BINDINGS', 'PREVIEW']) {
    assert.match(watcher, new RegExp(`WIZARD_STEP\\.${step}`))
  }
})

test('事件名称搜索命中后自动切换到策略所在 tab', () => {
  assert.match(source('src/views/security/SecurityPolicies.vue'), /activeTypeTab\.value = policyTypeOf\(matched\)/)
})

test('自动封禁卡片主体恢复配置点击入口', () => {
  assert.match(source('src/views/security/SecurityEvents.vue'), /<div\s+class="autoban-main"[^>]*@click="openAutobanConfig"/)
})

test('自动封禁卡片主体与函数入口统一受只读和节点门控', () => {
  const text = source('src/views/security/SecurityEvents.vue')
  assert.match(text, /<el-tooltip[^>]*:content="autobanConfigTooltip"[^>]*:disabled="autobanWritable"/)
  assert.match(text, /:tabindex="autobanWritable \? 0 : -1"/)
  assert.match(text, /:aria-disabled="!autobanWritable"/)
  const open = section(text, 'const openAutobanConfig', 'const saveAutobanConfig')
  assert.match(open, /if \(!autobanWritable\.value\) return/)
  assert.match(text, /自动封禁状态加载中，暂不可配置/)
  // 函数级纵深守卫：按钮 :disabled 只是呈现层，保存/禁用直切必须各自带
  // writable 门（与 openAutobanConfig 同构）——键盘/控制台直接调用不得绕过。
  const save = section(text, 'const saveAutobanConfig', 'const AUTOBAN_ENABLE_CONFIRM_HTML')
  assert.match(save, /if \(!autobanWritable\.value\) return/, '保存必须带函数级 autobanWritable 守卫')
  const toggle = section(text, 'const toggleAutobanEnabled', '// 触发阶段分类')
  assert.match(toggle, /!autobanWritable\.value/, '禁用直切必须带函数级 autobanWritable 守卫')
})

test('默认上游分支不得显示无启用上游', () => {
  const text = source('src/components/RuleFlowDialog.vue')
  assert.match(text, /v-else-if="pr\.upstreams === null"/)
  assert.match(text, /跟随主路由上游/)
})

test('关闭向导时复位 DNS 开关与服务器', () => {
  const reset = section(source('src/views/Rules.vue'), 'const resetWizard = () =>', 'const beforeWizardClose')
  assert.match(reset, /wizardForm\.enable_dns_server = false/)
  assert.match(reset, /wizardForm\.dns_server = ''/)
})

test('大屏显性披露回填未完成与汇总陈旧', () => {
  // 原断言只钉 `?: boolean` 类型声明（类型契约由 vue-tsc 承担）。
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

test('Vite 开发代理默认 HTTP，仅显式环境开关使用 HTTPS', () => {
  const text = source('vite.config.ts')
  // 钉三元表达式本身的分支顺序（条件=显式开关、默认臂=HTTP、开关臂=HTTPS）：
  // 只查「HTTPS 字符串出现过/没出现在 target: 后」无法证伪——target 消费的是
  // devBackendTarget，交换两臂后三条文本断言全绿。
  const targetExpr = section(text, 'const devBackendTarget =', '\nexport default')
  assert.match(
    targetExpr,
    /^const devBackendTarget = process\.env\.VITE_DEV_BACKEND_HTTPS === '1'\n\s*\? 'https:\/\/localhost:8000'\n\s*: 'http:\/\/localhost:8000'\s*$/,
    `默认必须走 HTTP、开关臂才走 HTTPS，实际: ${targetExpr}`,
  )
  // 代理必须消费该表达式，且不得另写内联 target 字符串（绕过开关）
  assert.match(section(text, 'proxy: {', 'secure: false'), /target: devBackendTarget/)
  assert.doesNotMatch(text, /target:\s*'/)
})

// ---- 安全视图接线钉（可纯函数化的
//      语义在 securityLibraries / blockPageAttribution / policyPayload / triggeredFilter
//      各 spec 做行为求值，此处只钉「视图是否真的接了实现」）----

test('库计数列文案与「数量 / 大小」列义', () => {
  const text = source('src/views/security/SecurityRules.vue')
  assert.match(text, /crsRuleCountLabel\(crsInfo\.value\.rule_count\)/)
  assert.doesNotMatch(text, /个文件/)
  assert.match(text, /label="数量 \/ 大小"/)
  // IP 地理库字节数带单位（formatSize）
  assert.match(text, /formatSize\(ip2regionInfo\.value\.db_size\)/)
})

test('爬虫豁免空引擎保存守卫（单源谓词）', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /if \(crawlerExemptionNeedsEngines\(\{ geoipEnabled: form\.value\.geoip_enabled, crawlerExempt: form\.value\.geoip_crawler_exempt, engines: form\.value\.geoip_crawler_engines \}\)\)/)
  assert.match(text, /空选等于豁免「全部引擎」/)
  // 空选时的行内提示（用户不必点保存才知道语义）
  assert.match(text, /v-if="form\.geoip_crawler_engines\.length === 0"/)
})

test('主列表失败可辨识（错误态 + 横幅重试 + 空态文案切换）', () => {
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

test('自动封禁口径文案不再自缩为「WAF 事件」', () => {
  const events = source('src/views/security/SecurityEvents.vue')
  assert.doesNotMatch(events, /WAF 事件固定窗口计数/)
  assert.match(events, /安全事件（IP 访问控制\/地域\/WAF\/威胁情报，已验证爬虫豁免除外）固定窗口计数/)
})

test('IP 快捷弹框全流程使用 trim 后的地址（无裸 props.ip 消费）', () => {
  const text = source('src/views/security/IPLocationAction.vue')
  assert.match(text, /const trimmedIp = computed\(\(\) => props\.ip\.trim\(\)\)/)
  // 裸 props.ip 的鉴别力要求「消费点」而非「出现次数」：剥注释后除归一化
  // 读取（props.ip.trim()）外不得再有任何读取——新增合法读取/注释不再误红。
  assert.doesNotMatch(
    stripComments(text),
    /props\.ip(?!\.trim\()/,
    '地址只允许经 trimmedIp 归一后消费，禁止直接读 props.ip',
  )
  // 移除/legacy 判定路径都用归一值
  assert.match(text, /inLegacy: parseIPList\(policy\.ip_blacklist\)\.includes\(trimmedIp\.value\)/)
  assert.match(text, /if \(!list\.includes\(trimmedIp\.value\)\)/)
  assert.match(text, /entry !== trimmedIp\.value/)
})

test('拦截页删除重入守卫（确认前占位、finally 释放）', () => {
  const text = source('src/views/security/SecurityBlockPages.vue')
  const guard = text.indexOf('if (deletingId.value !== null) return')
  const confirm = text.indexOf('ElMessageBox.confirm(`确定删除拦截页面')
  const release = text.indexOf('deletingId.value = null')
  assert.ok(guard > 0, '必须有重入守卫')
  assert.ok(confirm > guard, '守卫必须先于确认框（先占位再弹）')
  assert.ok(release > confirm, 'finally 必须释放占位')
  assert.match(text, /:loading="deletingId === row\.id"/)
})

test('阶段页覆盖写入按 skipped 归集后再回写（不谎报已覆盖）', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  const skippedSet = text.indexOf('const skippedIds = new Set(skippedItems.map((item) => item.rule_id))')
  const apply = text.indexOf('applyStageOverrideSuccess(caddyId, edit)', skippedSet)
  assert.ok(skippedSet > 0 && apply > skippedSet, '必须先归集 skipped 再回写成功态')
  assert.match(text, /if \(!skippedIds\.has\(caddyId\)\) applyStageOverrideSuccess/)
  // 行内状态：未写入 + 原因；成功计数不把 skipped 计入
  assert.match(text, /\? '未写入' :/)
  // 成功计数必须扣掉 skipped（声明关键字不作钉：let/const 皆可）
  assert.match(text, /syncedCount = pendingOverrides\.length - skippedNotes\.length/)
})

test('名单详情 GET 静默，避免与全局拦截器双 toast', () => {
  const text = source('src/views/security/SecurityRules.vue')
  const silentGets = text.match(/security\/ip-lists\/\$\{[^}]+\}`, \{ silent: true \}\)/g) ?? []
  assert.equal(silentGets.length, 2, `详情与重试两处请求都应 silent，实际 ${silentGets.length}`)
  // 本地提示保留（带「已禁用保存」动作信息）
  assert.match(text, /加载列表条目失败，已禁用保存；请重新加载/)
})

test('库状态未知时自动更新开关显示「—」而非默认开', () => {
  const text = source('src/views/security/SecurityRules.vue')
  assert.match(text, /autoUpdateKnown: !crsInfoError\.value && crsInfoLoaded\.value/)
  assert.match(text, /autoUpdateKnown: threatLibLoaded\.value && !threatLibError\.value/)
  assert.match(text, /v-if="!row\.autoUpdateKnown"/)
  assert.match(text, /<el-switch v-else :model-value="row\.autoUpdate"/)
})

// ---- 前端展示/契约批次：单源化与首轮误标 ----
test('分页器形态收敛 main.css，四个视图不得再本地重定义', () => {
  const main = source('src/styles/main.css')
  assert.match(main, /\.rules-pagination \{ display: flex; justify-content: flex-end; margin-top: 16px; \}/)
  for (const file of ['src/views/Rules.vue', 'src/views/security/SecurityRules.vue', 'src/views/security/SecurityPolicies.vue', 'src/views/security/SecurityBlockPages.vue']) {
    assert.doesNotMatch(source(file), /^\.rules-pagination \{/m, `${file} 仍保留本地 .rules-pagination 定义`)
  }
})

test('SecurityRules 条件列用专用 class-name，不再页级 :deep 覆盖全局表格单元格', () => {
  const text = source('src/views/security/SecurityRules.vue')
  assert.match(text, /<el-table-column label="条件" min-width="250" class-name="rule-cond-cell">/)
  assert.doesNotMatch(text, /:deep\(\.el-table \.cell:has\(\.el-tag\)\)/, '页级全局覆盖必须退役')
  assert.match(text, /\.el-table \.rule-cond-cell \.cell:has\(\.el-tag\) \{ flex-wrap: wrap; row-gap: 4px; \}/)
})

test('BasicSettings 两处 radio 行回归 el-form-item（自管标签行族已退役）', () => {
  const text = source('src/views/settings/BasicSettings.vue')
  assert.doesNotMatch(text, /class="form-radio-row"/, '自管标签行标记必须退役')
  assert.doesNotMatch(text, /^\.form-radio-row/m, '自管标签行样式必须退役')
  assert.match(text, /<el-form-item label="证书来源">/)
  assert.match(text, /<el-form-item label="频率">/)
})

test('BasicSettings 不再局部重复定义全局 .settings-form（main.css 单源）', () => {
  const text = source('src/views/settings/BasicSettings.vue')
  assert.doesNotMatch(text, /\.settings-form \{/, 'main.css 已有同名规则，局部重定义必须退役')
})

test('SecurityBindingEditor 先声明 props/emits 再派生 computed', () => {
  const text = source('src/components/SecurityBindingEditor.vue')
  const propsIdx = text.indexOf('const props = defineProps')
  const emitIdx = text.indexOf('const emit = defineEmits')
  const subtitleIdx = text.indexOf('const bindSubtitle = computed')
  assert.ok(propsIdx > 0 && emitIdx > propsIdx, 'props/emits 声明缺失或顺序错误')
  assert.ok(subtitleIdx > emitIdx, 'bindSubtitle 必须在 props 之后声明（不得依赖 TDZ 惰性求值）')
})

test('总览总量卡片按 includes_reserved 切换口径 tooltip（含/不含私网双文案）', () => {
  const text = source('src/views/security/SecurityOverview.vue')
  assert.ok([...text.matchAll(/overview\.includes_reserved \? '总量含私网\/保留地址事件/g)].length >= 2, '今日拦截与今日检测两处都须按 includes_reserved 切换口径 tooltip')
  assert.ok([...text.matchAll(/与大屏同口径（分钟汇总）：不含私网\/保留地址事件/g)].length >= 2, 'rollup 口径（不含私网）文案两处都须存在')
})

test('自动封禁预置名单条目数标注含已到期条目', () => {
  const text = source('src/views/security/SecurityRules.vue')
  assert.match(text, /v-if="row\.preset_autoban"[^>]*content="含已到期条目/, '预置名单条数须 tooltip 消歧')
})

test('useLibUpdateDialog 409 路径不得重复立即轮询', () => {
  const text = source('src/composables/useLibUpdateDialog.ts')
  assert.match(text, /const startPolling = \(\) => \{ polling\.start\(\) \}/, '起轮询只挂定时器（refreshStatus 已拉过本轮）')
  assert.doesNotMatch(text, /startPolling = \(\) => \{ polling\.resume\(\) \}/, 'resume 会立即 run，409/onOpened 路径产生重复请求')
})

test('大屏光流可用性位/恢复基线/重装复位（L8 前端三项）', () => {
  const text = source('src/views/security/ThreatScreen.vue')
  assert.match(text, /<div v-if="flowError || attackFlowError" class="error-banner site-unset">光流数据加载失败，正在重试…<\/div>/, '光流端点失败必须显性横幅')
  assert.match(text, /interval: ATTACK_FLOW_POLL_MS, onError: \(\) => \{ attackFlowError\.value = true \}/)
  assert.match(text, /interval: 1000, onError: \(\) => \{ flowError\.value = true \}/)
  // 恢复首轮重建基线：手动暂停恢复 + 可见性恢复两处（原仅「不可用」一处）
  assert.ok([...text.matchAll(/trafficBaseline = null/g)].length >= 3, '暂停/可见性恢复/不可用三处都必须重建基线')
  assert.match(member(text, 'async function mountEngine('), /zoomedName\.value = null/, '引擎重装必须复位下钻态')
})
