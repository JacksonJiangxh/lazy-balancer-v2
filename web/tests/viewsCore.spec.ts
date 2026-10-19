// 历史 WEB-VIEWS-CORE 验收（W87-01…W87-16）：
//   A. 可抽出的纯逻辑做 node 行为测试（向导阶段覆盖/复制 Host、审计筛选参数、
//      API 密钥白名单归一、分页夹紧）；
//   B. 视图内行为（错误态/CSS 映射/权限态）沿用本仓既有「源码钉」形态——SFC 无法
//      在 node --test 下挂载，钉住的是可判定的结构化形态，并对同族全量收敛。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { nextTick, ref } from 'vue'

import { copyRuleHostHeader, newRuleWizardStageOverrides, stageBlockPageOverrides } from '../src/utils/ruleWizard.ts'
import { buildAuditLogParams } from '../src/utils/auditLogFilters.ts'
import { normalizeCidr, serializeWhitelist } from '../src/utils/apiKeyWhitelist.ts'
import { useClampedPagination } from '../src/composables/useClampedPagination.ts'

const source = (relativePath: string): string => readFileSync(new URL(`../src/${relativePath}`, import.meta.url), 'utf8')

const rules = source('views/Rules.vue')
const dashboard = source('views/Dashboard.vue')
const auditLog = source('views/AuditLog.vue')
const caddyConfig = source('views/CaddyConfig.vue')
const users = source('views/Users.vue')
const keys = source('views/Keys.vue')

const slice = (text: string, startMarker: string, endMarker: string): string => {
  const start = text.indexOf(startMarker)
  assert.ok(start >= 0, `missing start marker: ${startMarker}`)
  const end = text.indexOf(endMarker, start + startMarker.length)
  assert.ok(end > start, `missing end marker: ${endMarker}`)
  return text.slice(start, end)
}

// ============ W87-01：阶段拦截页覆盖的共享键集 ============

test('W87-01：新建规则的阶段拦截页覆盖恒为 0（4 键全零）', () => {
  assert.deepEqual(newRuleWizardStageOverrides(), {
    block_page_stage1_id: 0,
    block_page_stage1_status: 0,
    block_page_stage3_id: 0,
    block_page_stage3_status: 0,
  })
})

test('W87-01：编辑/复制水合保留源规则的阶段覆盖，缺键按 0', () => {
  assert.deepEqual(stageBlockPageOverrides({
    block_page_stage1_id: 7,
    block_page_stage1_status: 403,
    block_page_stage3_id: 9,
    block_page_stage3_status: 451,
  }), {
    block_page_stage1_id: 7,
    block_page_stage1_status: 403,
    block_page_stage3_id: 9,
    block_page_stage3_status: 451,
  })
  assert.deepEqual(stageBlockPageOverrides({}), newRuleWizardStageOverrides())
  assert.deepEqual(stageBlockPageOverrides({ block_page_stage1_id: null }), newRuleWizardStageOverrides())
})

test('W87-01：水合/新建/重置三处共用同一键集（双向清单，防再次分叉）', () => {
  const hydrate = slice(rules, 'const wizardFormFromRule', 'const buildRuleConfigView')
  assert.match(hydrate, /\.\.\.stageBlockPageOverrides\(fullRule\)/)
  // 水合里不得再逐键手写（逐键手写正是与重置清单分叉的根因）
  assert.doesNotMatch(hydrate, /block_page_stage1_id: fullRule\./)

  const openWizard = slice(rules, 'const openWizard = async', 'const resetWizard')
  const newBranch = openWizard.slice(openWizard.indexOf('} else {', openWizard.indexOf('if (rule) {')))
  assert.ok(newBranch.length > 0, 'missing new-rule branch')
  assert.match(newBranch, /\.\.\.newRuleWizardStageOverrides\(\)/)

  const reset = slice(rules, 'const resetWizard = () => {', 'const beforeWizardClose')
  assert.match(reset, /Object\.assign\(wizardForm, newRuleWizardStageOverrides\(\)\)/)

  // 提交载荷仍显式发送四键（0=不覆盖）
  const payload = slice(rules, 'const data: UpdateRuleRequest = {', 'request.')
  for (const key of ['block_page_stage1_id', 'block_page_stage1_status', 'block_page_stage3_id', 'block_page_stage3_status']) {
    assert.match(payload, new RegExp(`${key}: wizardForm\\.${key} \\|\\| 0`), `payload must send ${key}`)
  }
})

// ============ W87-02：复制路径携带规则级回源 Host ============

test('W87-02：复制载荷的 host_header 取源规则值（空/缺省→空串）', () => {
  assert.equal(copyRuleHostHeader({ host_header: 'backend.internal' }), 'backend.internal')
  assert.equal(copyRuleHostHeader({ host_header: '' }), '')
  assert.equal(copyRuleHostHeader({ host_header: null }), '')
  assert.equal(copyRuleHostHeader({}), '')
})

test('W87-02：复制向导从源规则取值，仅复制分支把 host_header 编入载荷', () => {
  const copyWizard = slice(rules, 'const openCopyWizard', 'const viewConfig')
  assert.match(copyWizard, /copySourceHostHeader\.value = copyRuleHostHeader\(fullRule\)/)
  assert.match(rules, /\.\.\.\(isCopyMode\.value \? \{ host_header: copySourceHostHeader\.value \} : \{\}\)/)
  // 新建/编辑不得发送该键（Update 的 nil=保留语义，新建本就无覆盖）
  const payload = slice(rules, 'const data: UpdateRuleRequest = {', 'request.')
  assert.equal((payload.match(/host_header:/g) ?? []).length, 1, 'payload must carry host_header only via the copy spread')
})

// ============ W87-09：关闭规则日志弹框即停定时器 ============

test('W87-09：onRuleLogDialogClosed 停本地轮询定时器（不再 5s 空转）', () => {
  const closed = slice(rules, 'const onRuleLogDialogClosed = () => {', '// A85WA-历史问题')
  assert.match(closed, /stopRuleLogPolling\(\)/)
  assert.match(closed, /ruleLogTail\.stop\(\)/)
})

// ============ W87-14：配置预览负载策略走标签单源 ============

test('W87-14：配置预览使用 getStrategyLabel，不再直出枚举键', () => {
  assert.match(rules, /\{\{ getStrategyLabel\(ruleConfig\.strategy\) \}\}/)
  assert.doesNotMatch(rules, /\{\{ ruleConfig\.strategy \}\}/)
})

// ============ W87-05：采集失败的规则行必须可见 ============

test('W87-05：排行榜纳入采集失败行并排在正常行之后（逐列「采集失败」可达）', () => {
  const rank = slice(dashboard, 'const rankableRules = computed', 'const sortedRules')
  assert.match(rank, /ruleMetricsUnavailable\.value\[rule\.caddy_id\] === true/, '失败行必须进入可排行集合')
  assert.match(rank, /if \(aUnavailable !== bUnavailable\) return aUnavailable \? 1 : -1/, '失败行排末尾')
  assert.match(rank, /return ruleRankValue\(b\.caddy_id\) - ruleRankValue\(a\.caddy_id\)/, '正常行仍按指标降序')
  const sorted = slice(dashboard, 'const sortedRules = computed', 'const rulesEmptyText')
  assert.match(sorted, /ranked\.slice\(0, 10\), \.\.\.failed/, '失败行不占 10 个名额，恒追加在末尾')
  // 逐列「采集失败」分支保持存在（现为可达态）
  assert.ok((dashboard.match(/ruleMetricsUnavailable\[row\.caddy_id\]/g) ?? []).length >= 5)
})

// ============ W87-06：历史弹框错误态与空态分文案 ============

test('W87-06：历史统计失败置错误态并给重试，空态文案不再代表失败', () => {
  assert.match(dashboard, /ruleHistoryError\.value = error instanceof Error \? error\.message/)
  const dialog = slice(dashboard, '<el-dialog v-model="ruleHistoryVisible"', '</el-dialog>')
  assert.match(dialog, /v-if="ruleHistoryError"/)
  assert.match(dialog, /@click="fetchRuleHistory"/)
  // 错误态分支内不得再出现「该时间范围内暂无数据」
  const errorBranch = dialog.slice(dialog.indexOf('v-if="ruleHistoryError"'), dialog.indexOf('<template v-else>', dialog.indexOf('v-if="ruleHistoryError"')))
  assert.doesNotMatch(errorBranch, /该时间范围内暂无数据/)
  assert.match(dialog, /图表为空不代表该时间范围没有流量/)
})

// ============ W87-07：节点角色三态 ============

test('W87-07：节点模式未知不再展示「主节点」', () => {
  assert.match(dashboard, /const nodeModeRole = computed<'master' \| 'slave' \| 'unknown'>/)
  assert.match(dashboard, /return 'unknown'/)
  assert.match(dashboard, /'节点角色未知'/)
  assert.match(dashboard, /const nodeModeTagType = computed/)
  assert.match(dashboard, /:type="nodeModeTagType"/)
  assert.doesNotMatch(dashboard, /isSlave \? 'warning' : 'success'/)
})

// ============ W87-08：未知状态兑现灰底样式 ============

test('W87-08：caddyStatus 映射样式类，unknown→info（.status-tag.info 生效）', () => {
  assert.match(dashboard, /const caddyStatusClass = computed\(\(\) => caddyStatus\.value === 'running' \? 'running' : caddyStatus\.value === 'stopped' \? 'stopped' : 'info'\)/)
  assert.match(dashboard, /:class="\['status-tag', caddyStatusClass\]"/)
  assert.match(dashboard, /\.status-tag\.info \{/)
})

// ============ W87-04：审计日志列表错误态 ============

test('W87-04：审计日志加载失败显性化（横幅 + 重试 + 空态分文案）', () => {
  const fetchLogs = slice(auditLog, 'const fetchLogs = async', 'onMounted(')
  assert.match(fetchLogs, /loadError\.value = false/)
  assert.match(fetchLogs, /if \(currentRequestSeq === requestSeq\) loadError\.value = true/, '仅最新请求可置错误态')
  assert.match(auditLog, /v-if="loadError"/)
  assert.match(auditLog, /@click="fetchLogs"/)
  assert.match(auditLog, /操作日志加载失败：列表为空不代表没有日志/)
  assert.match(auditLog, /loadError \? '日志加载失败' : '暂无操作日志'/)
})

// ============ W87-13：消费 /audit-logs/options 的 partial ============

test('W87-13：部分下拉（partial）与整体失败都有可见提示与重试', () => {
  assert.match(auditLog, /optionsPartial\.value = d\?\.partial === true/)
  assert.match(auditLog, /optionsError\.value = true/)
  assert.match(auditLog, /const optionsIncomplete = computed\(\(\) => optionsPartial\.value \|\| optionsError\.value\)/)
  const selects = auditLog.slice(auditLog.indexOf('<div class="filter-bar">'), auditLog.indexOf('<el-table'))
  assert.equal((selects.match(/optionsIncomplete \?/g) ?? []).length, 3, '三个下拉的 placeholder 都要显性化')
  assert.match(auditLog, /@click="fetchOptions"/)
})

// ============ W87-03：配置预览按角色收口 ============

test('W87-03：非管理员渲染权限空态且不发请求（深链同样覆盖）', () => {
  assert.match(caddyConfig, /const canViewConfig = computed\(\(\) => authStore\.user\?\.role === 'admin'\)/)
  assert.match(caddyConfig, /v-if="!canViewConfig"/)
  assert.match(caddyConfig, /仅管理员可查看 Caddy 配置预览/)
  assert.match(caddyConfig, /if \(canViewConfig\.value\) void fetchCaddyConfig\(\)/)
  assert.doesNotMatch(caddyConfig, /onMounted\(\(\) => void fetchCaddyConfig\(\)\)/)
  // 角色补齐后自动补拉
  assert.match(caddyConfig, /watch\(canViewConfig, \(allowed\) =>/)
})

// ============ W87-10/11/12：用户页 MFA 与死分支 ============

test('W87-11：MFA 激活按钮按 6 位禁用（不再静默 no-op）', () => {
  assert.match(users, /:disabled="mfaBinding\.code\.length !== 6"/)
  const activate = slice(users, 'const activateMfa = async', 'const copyMfaRecovery')
  assert.match(activate, /isReadOnly\.value \|\| mfaBinding\.value\.code\.length !== 6/)
})

test('W87-10：MFA 两个入口补函数级只读守卫（纵深防御）', () => {
  const open = slice(users, 'const openMfaBinding = async', 'const activateMfa')
  assert.match(open, /if \(isReadOnly\.value \|\| mfaBinding\.value\.loading\) return/)
  const activate = slice(users, 'const activateMfa = async', 'const copyMfaRecovery')
  assert.match(activate, /isReadOnly\.value/)
})

test('W87-12：resetPassword 删除 lbOpen 时代残留的 cancel/close 分支', () => {
  const reset = slice(users, 'const resetPassword = async', 'const resetMfa = async')
  assert.doesNotMatch(reset, /e === 'cancel' \|\| e === 'close'/, 'lbOpen 以 {ok:false} resolve，不会 reject 字符串')
  assert.match(reset, /if \(!r\.ok\) return/)
})

// ============ W87-16：纯逻辑抽出后的行为测试 ============

test('W87-16：审计筛选参数——空值不上送、空白剥离、时间半开区间', () => {
  assert.deepEqual(buildAuditLogParams({
    timeRange: null, username: '', action: '', resource: '', ip: '', keyword: '',
  }, 1, 20), { page: 1, page_size: 20 })

  assert.deepEqual(buildAuditLogParams({
    timeRange: ['2026-01-01 00:00:00', ''],
    username: '  admin ',
    action: '',
    resource: '规则 ',
    ip: '',
    keyword: '  ',
  }, 3, 50), {
    page: 3,
    page_size: 50,
    start_time: '2026-01-01 00:00:00',
    username: 'admin',
    resource: '规则',
  })
})

test('W87-16：白名单 CIDR 归一（IPv4→/32、IPv6→/128、已带前缀保留）', () => {
  assert.equal(normalizeCidr(' 192.168.1.10 '), '192.168.1.10/32')
  assert.equal(normalizeCidr('2001:db8::1'), '2001:db8::1/128')
  assert.equal(normalizeCidr('10.0.0.0/8'), '10.0.0.0/8')
  assert.equal(normalizeCidr('   '), '')
})

test('W87-16：白名单序列化——忽略空行、报错带原始行号、非法行不落任何值', () => {
  assert.deepEqual(serializeWhitelist('192.168.1.10\n\n10.0.0.0/8\n'), {
    value: ['192.168.1.10/32', '10.0.0.0/8'],
    error: '',
  })
  assert.deepEqual(serializeWhitelist('192.168.1.10\n\nnot-an-ip'), {
    value: [],
    error: '第 3 行 IP 或 CIDR 格式不正确',
  })
  assert.deepEqual(serializeWhitelist(''), { value: [], error: '' })
})

test('W87-16：分页越界自动回夹（用户列表改用共享 composable）', async () => {
  const items = ref(Array.from({ length: 12 }, (_, index) => ({ id: index + 1 })))
  const page = ref(3)
  const pageSize = ref(10)
  // useClampedPagination 只用 watch/computed（无生命周期钩子），脱离组件实例直接
  // 调用即可测真实回夹行为（SSR 渲染结束会销毁 effect scope，watch 不再触发）。
  const { pagedItems } = useClampedPagination(items, page, pageSize)
  assert.equal(page.value, 2, '初始越界页立即回夹到最大页')
  assert.deepEqual(pagedItems.value.map((row) => row.id), [11, 12])

  items.value = items.value.slice(0, 5)
  await nextTick()
  assert.equal(page.value, 1, '列表收缩后回夹')
  assert.equal(pagedItems.value.length, 5)

  assert.match(users, /useClampedPagination\(users, currentPage, pageSize\)/)
  assert.doesNotMatch(users, /users\.value\.slice\(start, start \+ pageSize\.value\)/, '不得保留手写切片')
})

test('W87-16：白名单逻辑单源（视图不再内联实现）', () => {
  assert.match(keys, /import \{ serializeWhitelist \} from '@\/utils\/apiKeyWhitelist'/)
  assert.doesNotMatch(keys, /const serializeWhitelist = /)
  assert.doesNotMatch(keys, /const normalizeCidr = /)
  // 审计筛选参数同样单源
  assert.match(auditLog, /import \{ buildAuditLogParams \} from '@\/utils\/auditLogFilters'/)
  assert.doesNotMatch(auditLog, /const buildParams = \(\) => \{\n/)
})
