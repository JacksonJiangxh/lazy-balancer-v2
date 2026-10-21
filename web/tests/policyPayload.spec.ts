// 安全策略保存载荷行为验收（历史修复）：
// 载荷原先内联在 SecurityPolicies.handleSave，字段语义（阶段外裁剪、引用释放、
// stage0 信任恒启用、geoip 三态归一、mixed 不显式提交）无求值测试。
//
// 后端契约：internal/handlers/security.go UpdateSecurityPolicyRequest。
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildPolicyPayload, crawlerExemptionNeedsEngines, type PolicyPayloadInput } from '../src/utils/policyPayload.ts'

const base = (over: Partial<PolicyPayloadInput> = {}): PolicyPayloadInput => ({
  name: '策略 A',
  description: '',
  enabled: true,
  mode: 'blocking',
  anomalyThreshold: 5,
  ipAclEnabled: false,
  ipAclMode: 'deny',
  ipAclList: [],
  ipAclListRefs: [],
  ipWhitelist: [],
  ipWhitelistRefs: [],
  ipWhitelistEnabled: false,
  rateLimitEnabled: false,
  rateLimitRps: 100,
  rateLimitBurst: 50,
  crsRuleGroups: [],
  crsExcludedRules: [],
  customRuleIds: [],
  blockPageId: 0,
  blockStatusCode: 403,
  geoipCountries: [],
  geoipEnabled: false,
  geoipMode: 'deny',
  geoipCrawlerExempt: false,
  geoipCrawlerEngines: ['googlebot'],
  wafCheckResponse: false,
  logRequestBody: false,
  trustDetection: false,
  policyType: 'stage3',
  ...over,
})

test('数组字段按 JSON 文本下发（名单/引用/组/排除/自定义/区域/引擎）', () => {
  const payload = buildPolicyPayload(base({
    ipAclEnabled: true,
    ipAclList: ['1.2.3.4'],
    ipAclListRefs: [3, 7],
    crsRuleGroups: ['942'],
    crsExcludedRules: [{ target: '942100', scope: 'all', ips: [], listRefs: [] }],
    customRuleIds: [12],
    geoipEnabled: true,
    geoipCountries: ['CN'],
  }))
  assert.equal(payload.ip_acl_list, '["1.2.3.4"]')
  assert.equal(payload.ip_acl_list_refs, '[3,7]')
  assert.equal(payload.crs_rule_groups, '["942"]')
  assert.equal(payload.crs_excluded_rules, '[{"target":"942100","scope":"all","ips":[],"listRefs":[]}]')
  assert.equal(payload.custom_rules, '[12]')
  assert.equal(payload.geoip_countries, '["CN"]')
  assert.equal(payload.geoip_crawler_engines, '["googlebot"]')
})

test('ACL 关闭 = 释放引用但保留内联名单（关闭再打开不丢数据）', () => {
  const payload = buildPolicyPayload(base({ ipAclEnabled: false, ipAclList: ['1.2.3.4'], ipAclListRefs: [3] }))
  assert.equal(payload.ip_acl_list, '["1.2.3.4"]')
  assert.equal(payload.ip_acl_list_refs, '[]')
})

test('信任开关三态：关闭释放引用且不生效；开启保留引用', () => {
  const off = buildPolicyPayload(base({ ipWhitelistEnabled: false, ipWhitelist: ['9.9.9.9'], ipWhitelistRefs: [2] }))
  assert.equal(off.ip_whitelist_enabled, false)
  assert.equal(off.ip_whitelist, '["9.9.9.9"]')
  assert.equal(off.ip_whitelist_refs, '[]')
  const on = buildPolicyPayload(base({ ipWhitelistEnabled: true, ipWhitelistRefs: [2] }))
  assert.equal(on.ip_whitelist_enabled, true)
  assert.equal(on.ip_whitelist_refs, '[2]')
})

test('阶段 0 信任名单策略恒启用（开关位不参与）', () => {
  const payload = buildPolicyPayload(base({ policyType: 'stage0', ipWhitelistEnabled: false, ipWhitelistRefs: [5] }))
  assert.equal(payload.ip_whitelist_enabled, true)
  assert.equal(payload.ip_whitelist_refs, '[5]')
  assert.equal(payload.policy_type, 'stage0')
})

test('geoip 三态归一：关闭 → off；开启但模式 off → deny；爬虫豁免随地域开关', () => {
  assert.equal(buildPolicyPayload(base({ geoipEnabled: false, geoipMode: 'allow', geoipCrawlerExempt: true })).geoip_mode, 'off')
  assert.equal(buildPolicyPayload(base({ geoipEnabled: false, geoipCrawlerExempt: true })).geoip_crawler_exempt, false)
  assert.equal(buildPolicyPayload(base({ geoipEnabled: true, geoipMode: 'off' })).geoip_mode, 'deny')
  assert.equal(buildPolicyPayload(base({ geoipEnabled: true, geoipMode: 'allow' })).geoip_mode, 'allow')
  assert.equal(buildPolicyPayload(base({ geoipEnabled: true, geoipCrawlerExempt: true })).geoip_crawler_exempt, true)
})

test('mixed 不显式提交类型（省略=后端按内容推断）', () => {
  const payload = buildPolicyPayload(base({ policyType: 'mixed' }))
  assert.equal('policy_type' in payload, true)
  assert.equal(payload.policy_type, undefined)
  assert.equal(buildPolicyPayload(base({ policyType: 'stage1' })).policy_type, 'stage1')
})

test('几何开关与限流参数原样透传（不做裁剪）', () => {
  const payload = buildPolicyPayload(base({ rateLimitEnabled: true, rateLimitRps: 33, rateLimitBurst: 7, anomalyThreshold: 9, blockStatusCode: 503, blockPageId: 4 }))
  assert.deepEqual(
    [payload.rate_limit_enabled, payload.rate_limit_rps, payload.rate_limit_burst, payload.anomaly_threshold, payload.block_status_code, payload.block_page_id],
    [true, 33, 7, 9, 503, 4],
  )
})

test('豁免开启 + 空引擎 = 不可保存（后端空集=全部引擎）', () => {
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: true, crawlerExempt: true, engines: [] }), true)
  // 勾选任一引擎即合法
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: true, crawlerExempt: true, engines: ['googlebot'] }), false)
  // 地域关闭或豁免关闭 = 引擎选择不参与（不阻断保存）
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: false, crawlerExempt: true, engines: [] }), false)
  assert.equal(crawlerExemptionNeedsEngines({ geoipEnabled: true, crawlerExempt: false, engines: [] }), false)
})
