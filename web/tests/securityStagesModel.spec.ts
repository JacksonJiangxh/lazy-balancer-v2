// 阶段投影与 CIDR 匹配行为验收
//   阶段 2 拦截页失效必须显性（回落默认 429），不得静默省略
//   ACL 内容门口径（与后端摘要 has_ip_control 分层，禁止统一）
//   IPv6 CIDR 命中（命中定位 / 残余信任判定）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  aclAssociateSides,
  attachStageDetails,
  blockPageStageCanIntercept,
  buildStageModel,
  entryMatchesIp,
  eventDetailRefIds,
  extractCrsRuleSnippet,
  formatAclModeDetail,
  hasIPACLControl,
  inferPolicyType,
  isTrustExemptionCandidate,
  isWafDurationFamily,
  triggerStageFamily,
  trustHitMode,
  type SecurityStageBinding,
  type SecurityStageBlockPage,
  type SecurityStagePolicy,
} from '../src/utils/securityStages.ts'

const policyOf = (overrides: Partial<SecurityStagePolicy> = {}): SecurityStagePolicy => ({
  id: 1,
  name: '策略 A',
  mode: 'off',
  enabled: true,
  has_ip_control: false,
  has_rate_limit: false,
  has_geoip: false,
  has_custom_rules: false,
  geoip_countries: '[]',
  custom_rules_count: 0,
  ip_acl_mode: 'deny',
  ip_acl_list: '[]',
  ip_whitelist: '[]',
  rate_limit_rps: 10,
  rate_limit_burst: 20,
  ...overrides,
})

const bindingOf = (overrides: Partial<SecurityStageBinding> = {}): SecurityStageBinding => ({
  policy_id: 1,
  name: '策略 A',
  mode: 'off',
  enabled: true,
  rate_limit_enabled: true,
  ...overrides,
})

const stageRows = (
  binding: SecurityStageBinding,
  policy: SecurityStagePolicy,
  blockPages: readonly SecurityStageBlockPage[],
  stageIndex: 0 | 1 | 2 | 3,
): Array<{ label: string; detail: string }> => buildStageModel([binding], [policy], [], blockPages).stages[stageIndex].groups[0]?.rows ?? []

test('阶段 2：拦截页已删/内容空时显性给出失效回落（不再静默省略该行）', () => {
  const policy = policyOf({ has_rate_limit: true, block_page_id: 0 })
  // 页已删：binding/策略仍指向 #9，但页面列表里没有它
  const deleted = stageRows(bindingOf({ block_page_id: 9 }), policy, [], 2)
  assert.deepEqual(deleted.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '已失效（回落绑定链首个有效页，无则默认 429）',
  })
  // 内容为空：同样视为失效
  const empty = stageRows(bindingOf({ block_page_id: 9 }), policy, [{ id: 9, name: '限流页', content: '' }], 2)
  assert.deepEqual(empty.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '已失效（回落绑定链首个有效页，无则默认 429）',
  })
  // 有效页：保留页名 + 429 语义
  const valid = stageRows(bindingOf({ block_page_id: 9 }), policy, [{ id: 9, name: '限流页', content: '<p>x</p>' }], 2)
  assert.deepEqual(valid.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '限流页（429 时渲染）',
  })
  // 未配置（0）：不虚增行（与阶段 1/3 的「未配置」口径一致——阶段 2 只呈现已配置）
  const unset = stageRows(bindingOf({ block_page_id: 0 }), policy, [], 2)
  assert.equal(unset.some((row) => row.label === '拦截页（策略页）'), false)
})

test('ACL 内容门：启用但名单空不记账为阶段 1 能力（摘要展示另走 has_ip_control）', () => {
  // 启用 ∧ 空名单：内容门 false（无 ACL 渲染产物）；摘要标志虽为 true 也不得用于阶段出组
  const enabledEmpty = policyOf({ has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '[]', ip_acl_list_refs: '[]', ip_blacklist: '[]' })
  assert.equal(hasIPACLControl(enabledEmpty), false)
  assert.equal(inferPolicyType(enabledEmpty), 'stage3')
  assert.equal(buildStageModel([bindingOf()], [enabledEmpty], [], []).stages[1].groups.length, 0, '阶段 1 不虚增空组')

  // 启用 ∧ 内联非空 → true
  assert.equal(hasIPACLControl(policyOf({ has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '["10.0.0.0/8"]' })), true)
  // 启用 ∧ 仅引用非空 → true
  assert.equal(hasIPACLControl(policyOf({ has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '[]', ip_acl_list_refs: '[3]' })), true)
  // 遗留黑名单非空（未启用 ACL 开关）→ true
  assert.equal(hasIPACLControl(policyOf({ has_ip_control: true, ip_acl_enabled: false, ip_blacklist: '["1.2.3.4"]' })), true)
  // 原始字段缺失（精简绑定载荷）→ 回退摘要标志
  assert.equal(hasIPACLControl({ has_ip_control: true }), true)
  assert.equal(hasIPACLControl({ has_ip_control: false }), false)
})

test('IPv6 CIDR：前缀位匹配生效且只作用于同族', () => {
  // v6 /32
  assert.equal(entryMatchesIp('2001:db8::/32', '2001:db8:1234::1'), true)
  assert.equal(entryMatchesIp('2001:db8::/32', '2001:db9::1'), false)
  // /128 精确前缀
  assert.equal(entryMatchesIp('2001:db8::1/128', '2001:db8::1'), true)
  assert.equal(entryMatchesIp('2001:db8::1/128', '2001:db8::2'), false)
  // /0 全匹配（v6 条目对 v6 地址）
  assert.equal(entryMatchesIp('::/0', '2001:db8::1'), true)
  // '::' 压缩尾与嵌入 IPv4 尾
  assert.equal(entryMatchesIp('fe80::/10', 'fe80::abc'), true)
  assert.equal(entryMatchesIp('::ffff:192.168.0.0/112', '::ffff:192.168.3.4'), true)
  assert.equal(entryMatchesIp('::ffff:192.168.0.0/112', '::ffff:192.169.3.4'), false)
  // 族隔离：v4 地址不得命中 v6 CIDR，反之亦然
  assert.equal(entryMatchesIp('::/0', '192.168.1.1'), false)
  assert.equal(entryMatchesIp('0.0.0.0/0', '2001:db8::1'), false)
  // 非法形态不误判
  assert.equal(entryMatchesIp('2001:db8::/129', '2001:db8::1'), false)
  assert.equal(entryMatchesIp('1::2::3/64', '1::2'), false)
  assert.equal(entryMatchesIp('gggg::/16', 'gggg::1'), false)
  // 既有 IPv4 语义不回归
  assert.equal(entryMatchesIp('203.0.113.0/24', '203.0.113.7'), true)
  assert.equal(entryMatchesIp('203.0.113.0/24', '203.0.114.7'), false)
  // 精确条目（无 /）仍按串相等
  assert.equal(entryMatchesIp('2001:db8::1', '2001:db8::1'), true)
})

// IP 快捷处置动作的模式门控——
// ip_acl_list_refs 是黑/白共用字段：名单本身无黑白属性，语义由 ip_acl_mode
// 决定（渲染只对 allow/deny 发射拒绝规则；绕过=免检测、空模式不发射）。
// 同一字段上同时给「拦截」「放行」两个动作会在模式生效后反转用户意图。
test('ACL 加入动作：deny 只给拦截、allow 只给放行，绕过/空/未知不给动作', () => {
  assert.deepEqual(aclAssociateSides('deny'), { deny: true, allow: false })
  assert.deepEqual(aclAssociateSides('allow'), { deny: false, allow: true })
  assert.deepEqual(aclAssociateSides('绕过'), { deny: false, allow: false })
  assert.deepEqual(aclAssociateSides(''), { deny: false, allow: false })
  assert.deepEqual(aclAssociateSides(undefined), { deny: false, allow: false })
})

test('ACL 加入动作：任何模式都不得同时提供拦截与放行', () => {
  for (const mode of ['deny', 'allow', '绕过', '', 'weird', undefined]) {
    const sides = aclAssociateSides(mode)
    assert.ok(!(sides.deny && sides.allow), `模式 ${String(mode)} 同时提供了拦截与放行`)
  }
})

// 事件详情预取名单集合——
// 详情弹框只消费「属主策略 ACL refs（命中列表/内联判定）+ 全部信任 refs
// （跨策略信任豁免）」；他策略 ACL 名单零消费，并入会在他策略引用大名单
// （内置威胁名单可达上万条）时全量下载。
test('事件详情预取：属主 ACL ∪ 全部信任，不含他策略 ACL', () => {
  const own = { ip_acl_list_refs: '[1,2]', ip_whitelist_refs: '[3]' }
  const others = [
    { ip_acl_list_refs: '[9,10]', ip_whitelist_refs: '[3,4]' },
    { ip_acl_list_refs: '[11]', ip_whitelist_refs: '[5]' },
  ]
  assert.deepEqual(eventDetailRefIds(own, others), [1, 2, 3, 4, 5])
  assert.ok(!eventDetailRefIds(own, others).includes(9))
})

test('事件详情预取：无属主策略时仅取信任 refs；去重保序并丢弃非法 id', () => {
  assert.deepEqual(eventDetailRefIds(null, [{ ip_whitelist_refs: '[7]' }, { ip_whitelist_refs: '[7,8]' }]), [7, 8])
  assert.deepEqual(eventDetailRefIds({ ip_acl_list_refs: '[0,6,6,2]', ip_whitelist_refs: '[]' }, []), [6, 2])
  assert.deepEqual(eventDetailRefIds(null, []), [])
})

test('拦截页回落文案：失效策略页不得断言「回落默认 403」（真实回落取绑定链首个有效页）', () => {
  const stage1 = stageRows(bindingOf(), policyOf({ block_page_id: 9 }), [], 1)
  assert.deepEqual(stage1.find((row) => row.label === '拦截页（策略页）'), {
    label: '拦截页（策略页）',
    detail: '已失效（回落绑定链首个有效页）',
  })
  // 阶段 3 同口径：逐策略合成码，页失效时回落同为绑定链首个有效页
  // （无规则级覆盖时行标签为「拦截页」）
  const stage3 = stageRows(bindingOf({ block_page_id: 9 }), policyOf({ mode: 'blocking' }), [], 3)
  assert.equal(stage3.find((row) => row.label === '拦截页')?.detail, '已失效（回落绑定链首个有效页）')
  // 未配置：跟随绑定链首个有效页，无则默认 403
  const unset = stageRows(bindingOf({ block_page_id: 0 }), policyOf({ mode: 'blocking' }), [], 3)
  assert.equal(unset.find((row) => row.label === '拦截页')?.detail, '未配置（跟随绑定链首个有效页，无则默认 403）')
})

test('ACL 摘要：有名单但模式为空/未知时显示「未配置模式」而非「黑名单模式」', () => {
  const two = { ip_acl_list: '["1.1.1.1","2.2.2.2"]', ip_blacklist: '[]' }
  // 目标形状：空模式/未知模式——名单存在但 ACL 不发射拒绝规则
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: '' }), '未配置模式 · 2 条')
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: 'unknown-x' }), '未配置模式 · 2 条')
  // 畸形形状：空模式 + 独立黑名单——独立黑名单无模式门，仍须追告生效
  assert.equal(
    formatAclModeDetail([], { ip_acl_mode: '', ip_acl_list: '["1.1.1.1"]', ip_blacklist: '["3.3.3.3"]' }),
    '未配置模式 · 1 条；独立黑名单 1 条仍生效',
  )
  // 回归形状：allow/绕过/deny 既有分支不动
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: 'allow' }), '白名单模式 · 2 条')
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: '绕过' }), '免检测模式 · 2 条')
  assert.equal(formatAclModeDetail([], { ...two, ip_acl_mode: 'deny' }), '黑名单模式 · 2 条')
  // 回归形状：deny 含独立黑名单的合并文案
  assert.equal(
    formatAclModeDetail([], { ip_acl_mode: 'deny', ip_acl_list: '["1.1.1.1"]', ip_blacklist: '["3.3.3.3"]' }),
    '黑名单模式 · 2 条（名单 1 + 独立 1）',
  )
})

test('白名单空生效集必须显性警示「将拒绝所有请求」', () => {
  // 引擎 allow 空集发射否定算子＝恒拒（带外直写/旧快照可达）
  assert.equal(formatAclModeDetail([], { ip_acl_mode: 'allow', ip_acl_list: '[]', ip_blacklist: '[]' }), '白名单模式 · 0 条（将拒绝所有请求）')
  // 有条目/其他模式不追加警示（回归形状）
  assert.equal(formatAclModeDetail([], { ip_acl_mode: 'allow', ip_acl_list: '["1.1.1.1"]' }), '白名单模式 · 1 条')
  assert.equal(formatAclModeDetail([], { ip_acl_mode: 'deny', ip_acl_list: '[]' }), '黑名单模式 · 0 条')
})

test('阶段可拦截能力门：stage3 关模式/检测无 block 规则、stage1 无能力均不得宣称生效', () => {
  // 阶段 2 恒可（429 归因另由绑定链限流门控）
  assert.equal(blockPageStageCanIntercept({ stage: 2 }), true)
  // 阶段 3：off 恒 false；blocking 恒 true；detection/custom_only 仅 block 自定义规则
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'off', hasBlockingCustomRule: true }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'blocking' }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'detection' }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'detection', hasBlockingCustomRule: true }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'custom_only' }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 3, mode: 'custom_only', hasBlockingCustomRule: true }), true)
  // 阶段 1：ACL/独立黑名单/地域任一成立
  assert.equal(blockPageStageCanIntercept({ stage: 1 }), false)
  assert.equal(blockPageStageCanIntercept({ stage: 1, hasAclEntries: true }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 1, hasBlacklistEntries: true }), true)
  assert.equal(blockPageStageCanIntercept({ stage: 1, hasGeoip: true }), true)
})

test('信任命中语义：非阶段 0 策略恒保留检测（与 trust_detection 无关）', () => {
  assert.equal(trustHitMode('stage0', false), 'passthrough')
  assert.equal(trustHitMode('stage0', true), 'detection')
  assert.equal(trustHitMode('mixed', false), 'detection')
  assert.equal(trustHitMode('stage1', false), 'detection')
  // 类型缺省（精简载荷/旧摘要）回落旧口径
  assert.equal(trustHitMode(undefined, false), 'passthrough')
  assert.equal(trustHitMode(undefined, true), 'detection')
})

test('阶段 0 投影：非阶段 0 策略的存量信任显示保留检测', () => {
  const mixed = policyOf({ policy_type: 'mixed', ip_whitelist: '["1.1.1.1"]', trust_detection: false })
  const rows = stageRows(bindingOf(), mixed, [], 0)
  assert.equal(rows.find((row) => row.label === '模式')?.detail, '保留检测记录（事件动作=检测）')
  const stage0 = policyOf({ policy_type: 'stage0', ip_whitelist: '["1.1.1.1"]', trust_detection: false })
  const stage0Rows = stageRows(bindingOf(), stage0, [], 0)
  assert.equal(stage0Rows.find((row) => row.label === '模式')?.detail, '直通上游（不产生安全事件）')
})

test('豁免候选：非阶段 0 存量信任（trust_detection=false）参与归因，阶段 0 直通不参与', () => {
  const base = { enabled: true, ip_whitelist_enabled: true }
  assert.equal(isTrustExemptionCandidate({ ...base, policy_type: 'mixed', trust_detection: false }), true)
  assert.equal(isTrustExemptionCandidate({ ...base, policy_type: 'stage0', trust_detection: false }), false)
  assert.equal(isTrustExemptionCandidate({ ...base, policy_type: 'stage0', trust_detection: true }), true)
  assert.equal(isTrustExemptionCandidate({ ...base, enabled: false, policy_type: 'mixed' }), false)
})

test('事件详情预取按类别/动作收窄：WAF 已拦截事件不取 ACL/信任引用', () => {
  const own = { ip_acl_list_refs: '[1,2]', ip_whitelist_refs: '[3]' }
  const others = [{ ip_whitelist_refs: '[4]' }]
  // 省略 scope = 全集（既有调用口径不变）
  assert.deepEqual(eventDetailRefIds(own, others), [1, 2, 3, 4])
  // WAF 拦截事件：三类全关（只保留名单名称查询，不下载条目）
  assert.deepEqual(eventDetailRefIds(own, others, { ownerAcl: false, ownerTrust: false, otherTrust: false }), [])
  // IP 类拦截事件：仍需属主 ACL 条目，无需信任/跨策略豁免
  assert.deepEqual(eventDetailRefIds(own, others, { ownerAcl: true, ownerTrust: false, otherTrust: false }), [1, 2])
  // 未拦截事件的豁免归因：属主 + 他策略信任，不含属主 ACL
  assert.deepEqual(eventDetailRefIds(own, others, { ownerAcl: false, ownerTrust: true, otherTrust: true }), [3, 4])
})

// 阶段 1 明细 vs 摘要对账：摘要对非 deny 模式提示「独立黑名单 N 条仍生效」，
// 明细模型必须同时给出这些条目，否则排障时摘要报数、明细无据可查。
test('阶段 1 明细：独立黑名单逐条可对账，且不受 ACL 开关门控', () => {
  // non-deny 模式：摘要强调「独立黑名单 N 条仍生效」，明细必须给出同一批条目
  const policy = policyOf({
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: true,
    ip_acl_mode: 'allow',
    ip_acl_list: '["10.0.0.0/8"]',
    ip_blacklist: '["1.2.3.4"," 5.6.7.8 "]',
  })
  assert.match(formatAclModeDetail([], policy), /；独立黑名单 2 条仍生效/)
  const details = attachStageDetails(
    buildStageModel([bindingOf()], [policy], [], []),
    { policies: [policy], ipLists: [] },
  ).stages[1].groups[0]?.details
  assert.deepEqual(details?.blacklistEntries, ['1.2.3.4', '5.6.7.8'], '独立黑名单必须去重去空后逐条进入明细')
  assert.equal(details?.aclInlineCount, 1)

  // ACL 关闭（保留名单）：内联 ACL 明细按开关门省略，独立黑名单不受该门控
  const disabled = policyOf({
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: false,
    ip_acl_mode: '绕过',
    ip_acl_list: '["10.0.0.0/8"]',
    ip_blacklist: '["1.2.3.4","5.6.7.8"]',
  })
  assert.match(formatAclModeDetail([], disabled), /；独立黑名单 2 条仍生效/)
  const disabledDetails = attachStageDetails(
    buildStageModel([bindingOf()], [disabled], [], []),
    { policies: [disabled], ipLists: [] },
  ).stages[1].groups[0]?.details
  assert.deepEqual(disabledDetails?.blacklistEntries, ['1.2.3.4', '5.6.7.8'])
  assert.equal(disabledDetails?.aclInlineCount, undefined)

  // deny 模式：黑名单计入生效集，明细同样逐条（不因模式变化而丢失）
  const deny = policyOf({
    policy_type: 'stage1',
    has_ip_control: true,
    ip_acl_enabled: true,
    ip_acl_mode: 'deny',
    ip_acl_list: '["10.0.0.0/8"]',
    ip_blacklist: '["1.2.3.4"]',
  })
  const denyDetails = attachStageDetails(
    buildStageModel([bindingOf()], [deny], [], []),
    { policies: [deny], ipLists: [] },
  ).stages[1].groups[0]?.details
  assert.deepEqual(denyDetails?.blacklistEntries, ['1.2.3.4'])
  assert.equal(denyDetails?.aclInlineCount, 1)
})

// WAF 耗时族：加和式（duration_us + precheck_us）只对 WAF 段独立计时的族成立；
// 预检族 duration_us 恒等于 precheck_us，加和会翻倍。全仓单源谓词。
test('WAF 耗时族谓词：wafCrs/wafCustom/body 加和，预检族与未知不入族', () => {
  for (const id of ['942100', '959999', '100123', '1500000', '11']) {
    assert.equal(isWafDurationFamily(triggerStageFamily(id)), true, `id ${id} 应属 WAF 耗时族`)
  }
  for (const id of ['2', '3', '4', '7', '12', '14', '800123', '850123', '810123', '', 'not-a-rule']) {
    assert.equal(isWafDurationFamily(triggerStageFamily(id)), false, `id ${id} 不应属 WAF 耗时族`)
  }
  // 与检测模式归因族的集合差异：body 加和但不由检测模式解释
  assert.equal(isWafDurationFamily('body'), true)
})

// CRS 源码片段定位：`id:942100` 是 `id:9421000` 的子串，纯 includes 会把片段
// 中心落到更长的 ID 行。边界匹配后片段必须落在精确 ID 行。
test('CRS 源码片段按 ID 边界定位（短 ID 不命中更长的 ID 行）', () => {
  const content = [
    'SecRule ARGS "@rx a" "id:9421000,phase:2,deny"',
    'SecRule ARGS "@rx b" "id:942100,phase:2,deny"', // 目标行（idx 1）
    'SecRule ARGS "@rx c" "id:942101,phase:2,deny"',
  ].join('\n')
  assert.equal(
    extractCrsRuleSnippet(content, '942100', 0),
    'SecRule ARGS "@rx b" "id:942100,phase:2,deny"',
  )
  // 上下文窗口 ±1 行
  assert.equal(extractCrsRuleSnippet(content, '942100', 1).split('\n').length, 3)
  // 引号/空格形态同样命中
  assert.equal(extractCrsRuleSnippet(`id:'942102'`, '942102', 0), `id:'942102'`)
  assert.equal(extractCrsRuleSnippet('id:"942103"', '942103', 0), 'id:"942103"')
  assert.equal(extractCrsRuleSnippet('id: 942104', '942104', 0), 'id: 942104')
  // 孤儿前缀（仅更长的 ID 存在）不得误命中
  assert.equal(extractCrsRuleSnippet('id:9421000', '942100', 0), '')
  // 非法/空输入
  assert.equal(extractCrsRuleSnippet(content, '', 0), '')
  assert.equal(extractCrsRuleSnippet('', '942100', 0), '')
})


// 禁用规则的锁摘要/流程必须显式降级：enabled=0 时控制面不渲染任何路由，
// 安全链不进入运行配置——阶段模型必须携带 ruleDisabled，消费方据此灰锁 +
// 顶部禁用横幅（否则巡检得到「四阶段在位」的高估结论）。
test('禁用规则：阶段模型携带 ruleDisabled 且不影响阶段内容', () => {
  const policy = policyOf({ policy_type: 'stage1', has_ip_control: true, ip_acl_enabled: true, ip_acl_list: '["10.0.0.0/8"]' })
  const binding = bindingOf()
  const enabledModel = buildStageModel([binding], [policy], [], [], null, true)
  assert.equal(enabledModel.ruleDisabled, false)
  const disabledModel = buildStageModel([binding], [policy], [], [], null, false)
  assert.equal(disabledModel.ruleDisabled, true)
  // 绑定与阶段页保留：阶段内容不因禁用而消失（启用后生效的「保留配置」口径）
  assert.equal(disabledModel.hasAnyPolicy, true)
  assert.deepEqual(
    disabledModel.stages.map((stage) => stage.groups.length),
    enabledModel.stages.map((stage) => stage.groups.length),
  )
  // 缺省（未知态）不得宣称已禁用
  assert.equal(buildStageModel([binding], [policy], [], []).ruleDisabled, false)
})
