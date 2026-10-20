// 阶段投影与 CIDR 匹配行为验收（审计 87 WEB-UTILS）：
//   历史问题-08 阶段 2 拦截页失效必须显性（回落默认 429），不得静默省略
//   历史问题-09 ACL 内容门口径（与后端摘要 has_ip_control 分层，禁止统一）
//   历史问题-03 IPv6 CIDR 命中（命中定位 / 残余信任判定）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  aclAssociateSides,
  buildStageModel,
  entryMatchesIp,
  eventDetailRefIds,
  hasIPACLControl,
  inferPolicyType,
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

test('历史问题-08 阶段 2：拦截页已删/内容空时显性给出失效回落（不再静默省略该行）', () => {
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

test('历史问题-09 ACL 内容门：启用但名单空不记账为阶段 1 能力（摘要展示另走 has_ip_control）', () => {
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

test('历史问题-03 IPv6 CIDR：前缀位匹配生效且只作用于同族', () => {
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

// —— IP 快捷处置动作的模式门控（历史问题）——
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

// —— 事件详情预取名单集合（历史问题）——
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
