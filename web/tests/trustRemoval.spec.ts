// 「取消信任」处置计划验收：可移除条目与残余 CIDR 信任必须一次算清。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { planTrustRemoval } from '../src/utils/trustRemoval.ts'
import { isTrustExemptionCandidate } from '../src/utils/securityStages.ts'

const ip = '203.0.113.7'

test('内联精确 + 引用 CIDR：可移除但必须报告残余信任（原实现谎报已取消）', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify([ip]),
    whitelistRefs: '[1]',
    lists: [{ id: 1, name: '办公网段' }],
    removableListIds: [1],
    listEntries: () => ['203.0.113.0/24'],
  })
  assert.equal(plan.inlineExact, true)
  assert.equal(plan.hasRemovable, true)
  assert.deepEqual(plan.exactRefListIds, [])
  assert.deepEqual(plan.residualSources, ['引用列表「办公网段」的 CIDR 条目'])
})

test('仅内联精确条目：移除后信任真正解除（无残余）', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify([ip, '198.51.100.0/24']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(plan.hasRemovable, true)
  assert.deepEqual(plan.residualSources, [])
})

test('引用列表精确条目可移除 + 内联 CIDR 仍残余', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify(['203.0.113.0/24']),
    whitelistRefs: '[2]',
    lists: [{ id: 2, name: '可信 IP' }],
    removableListIds: [2],
    listEntries: () => [ip],
  })
  assert.deepEqual(plan.exactRefListIds, [2])
  assert.deepEqual(plan.residualSources, ['策略内联 CIDR 条目'])
})

test('仅 CIDR 提供信任：本弹窗无可执行动作', () => {
  const inlineCidr = planTrustRemoval({
    ip,
    inlineWhitelist: JSON.stringify(['203.0.113.0/24']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(inlineCidr.hasRemovable, false)
  assert.deepEqual(inlineCidr.residualSources, ['策略内联 CIDR 条目'])

  const refCidr = planTrustRemoval({
    ip,
    inlineWhitelist: '[]',
    whitelistRefs: '[3]',
    lists: [{ id: 3, name: '数据中心' }],
    removableListIds: [3],
    listEntries: () => ['203.0.113.0/24'],
  })
  assert.equal(refCidr.hasRemovable, false)
  assert.deepEqual(refCidr.residualSources, ['引用列表「数据中心」的 CIDR 条目'])
})

test('引用列表精确条目但不在可移除集合：不得纳入删除计划', () => {
  const plan = planTrustRemoval({
    ip,
    inlineWhitelist: '[]',
    whitelistRefs: '[4]',
    lists: [{ id: 4, name: '系统名单' }],
    removableListIds: [],
    listEntries: () => [ip],
  })
  assert.equal(plan.hasRemovable, false)
  assert.deepEqual(plan.exactRefListIds, [])
})

test('空白归一：带空格的精确条目仍视为可移除', () => {
  const plan = planTrustRemoval({
    ip: ` ${ip} `,
    inlineWhitelist: JSON.stringify([` ${ip} `]),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(plan.inlineExact, true)
  assert.deepEqual(plan.residualSources, [])
})

test('IPv6 残余信任：精确条目移除后覆盖它的 IPv6 CIDR 必须报告（不得谎报已取消）', () => {
  const v6 = '2001:db8:abcd::7'
  const plan = planTrustRemoval({
    ip: v6,
    inlineWhitelist: JSON.stringify([v6, '2001:db8::/32']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.equal(plan.inlineExact, true)
  assert.deepEqual(plan.residualSources, ['策略内联 CIDR 条目'])
  // 不在 CIDR 覆盖范围内 → 无残余（不得把「同族但不同前缀」也算残余）
  const clear = planTrustRemoval({
    ip: v6,
    inlineWhitelist: JSON.stringify([v6, '2001:db9::/32']),
    whitelistRefs: '',
    lists: [],
    removableListIds: [],
    listEntries: () => [],
  })
  assert.deepEqual(clear.residualSources, [])
})

// 跨策略信任豁免的候选策略判定：事件详情端点不过滤 enabled——属主
// 策略可能事后被禁用，禁用策略不渲染、不可能放行，不得参与「由某策略信任名单
// 放行」的归因。语义按 trustHitMode：非阶段 0 存量信任引擎恒 DetectionOnly，
// 即使 trust_detection=false 也可解释 logged 事件。
test('豁免候选：禁用/信任关闭不参与；非阶段 0 存量信任参与归因', () => {
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: true, policy_type: 'stage0', trust_detection: true }), true)
  assert.equal(isTrustExemptionCandidate({ enabled: false, ip_whitelist_enabled: true, policy_type: 'stage0', trust_detection: true }), false)
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: false, policy_type: 'stage0', trust_detection: true }), false)
  // 阶段 0 直通不产生后续阶段事件 → 不参与
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: true, policy_type: 'stage0', trust_detection: false }), false)
  // 非阶段 0（mixed/stage1 存量）：引擎恒 DetectionOnly，与 trust_detection 无关
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: true, policy_type: 'mixed', trust_detection: false }), true)
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: true, policy_type: 'stage1', trust_detection: false }), true)
  // 类型缺省回落旧口径
  assert.equal(isTrustExemptionCandidate({ enabled: true, ip_whitelist_enabled: true }), false)
})
