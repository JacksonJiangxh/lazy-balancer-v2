// securityStages（阶段化流水线投影）中**未被既有 spec 求值**的纯函数行为验收：
// 阶段出组判据（hasGeoIPControl / hasTrustEntries）、条目合并与计数、阶段页覆盖
// 解析、明细附着、版本比较、耗时格式化、宽松 id 解析与缓存订阅退订。
//
// 这些判据直接决定用户可见的阶段抽屉、阈值统计与「已配置」徽标；此前只有
// 源码文本钉或零覆盖。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  attachStageDetails,
  compareVersion,
  ensureSharedEntries,
  formatDurationUs,
  hasGeoIPControl,
  hasTrustEntries,
  invalidateSharedEntriesCache,
  mergeIpEntries,
  mergeIpEntryCount,
  mergeIpEntryValues,
  parseRefIds,
  parseUnknownIds,
  resolveStageOverride,
  subscribeSharedEntriesCache,
  type RuleStageModel,
  type SecurityStageIPList,
  type SecurityStagePolicy,
  type StageGroup,
  type StagePolicyGroup,
} from '../src/utils/securityStages.ts'

const policy = (over: Partial<SecurityStagePolicy> = {}): SecurityStagePolicy => ({
  id: 1,
  name: '策略',
  mode: 'blocking',
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
  rate_limit_rps: 100,
  rate_limit_burst: 50,
  ...over,
})

const entryList = (id: number, values: string[], count?: number): SecurityStageIPList => ({
  id,
  name: `名单 ${id}`,
  entry_count: count ?? values.length,
  entries: values.map((value) => ({ value })),
})

test('parseRefIds：JSON 数字数组，坏数据/非正/小数一律丢弃', () => {
  assert.deepEqual(parseRefIds('[1,5]'), [1, 5])
  assert.deepEqual(parseRefIds('["3","7"]'), [3, 7])
  assert.deepEqual(parseRefIds('[0,-2,2.5,4]'), [4])
  assert.deepEqual(parseRefIds('{"a":1}'), [])
  assert.deepEqual(parseRefIds('not-json'), [])
  assert.deepEqual(parseRefIds(''), [])
  assert.deepEqual(parseRefIds(undefined), [])
})

test('parseUnknownIds：数字或 { id } 对象两形态，其余丢弃', () => {
  assert.deepEqual(parseUnknownIds([1, { id: 2 }, { name: 'x' }, '3', 0, { id: '4' }]), [1, 2])
  assert.deepEqual(parseUnknownIds('not-array'), [])
  assert.deepEqual(parseUnknownIds([]), [])
})

test('mergeIpEntryValues：trim + 精确去重 + 空串剔除（跨引用组同口径）', () => {
  assert.deepEqual(
    mergeIpEntryValues([' 1.1.1.1 ', '1.1.1.1', ''], [['2.2.2.2'], [' 2.2.2.2 ', '3.3.3.3']]),
    ['1.1.1.1', '2.2.2.2', '3.3.3.3'],
  )
  assert.deepEqual(mergeIpEntryValues([], []), [])
})

test('mergeIpEntries：缺失的引用列表跳过（防御性回退为仅内联）', () => {
  const lists = [entryList(3, ['2.2.2.2', '3.3.3.3'])]
  assert.deepEqual(mergeIpEntries(lists, ['1.1.1.1'], [3, 99]), ['1.1.1.1', '2.2.2.2', '3.3.3.3'])
})

test('mergeIpEntryCount：内联去重数 + Σ引用 entry_count', () => {
  // 列表载荷不内联 entries 时计数仍可用（只依赖 entry_count）
  const lists: SecurityStageIPList[] = [
    { id: 3, name: 'A', entry_count: 10, entries: [] },
    { id: 4, name: 'B', entry_count: 5, entries: [] },
  ]
  assert.equal(mergeIpEntryCount(lists, ['1.1.1.1', ' 1.1.1.1 ', ''], [3, 4]), 16)
  // 缺失名单不计入；无内联时只计引用
  assert.equal(mergeIpEntryCount(lists, [], [4, 99]), 5)
})

test('hasTrustEntries：内联或引用任一非空即为真（阶段 0 出组判据）', () => {
  assert.equal(hasTrustEntries({ ip_whitelist: '["1.1.1.1"]', ip_whitelist_refs: '[]' }), true)
  assert.equal(hasTrustEntries({ ip_whitelist: '[]', ip_whitelist_refs: '[2]' }), true)
  assert.equal(hasTrustEntries({ ip_whitelist: '[]', ip_whitelist_refs: '[]' }), false)
  assert.equal(hasTrustEntries({}), false)
  assert.equal(hasTrustEntries({ ip_whitelist: 'bad-json' }), false)
})

test('hasGeoIPControl：显式字段按「模式非 off 且区域非空」，缺省回退摘要标志', () => {
  assert.equal(hasGeoIPControl({ geoip_mode: 'deny', geoip_countries: '["CN"]' }), true)
  assert.equal(hasGeoIPControl({ geoip_mode: 'allow', geoip_countries: '["US"]' }), true)
  assert.equal(hasGeoIPControl({ geoip_mode: 'off', geoip_countries: '["CN"]' }), false)
  assert.equal(hasGeoIPControl({ geoip_mode: 'deny', geoip_countries: '[]' }), false)
  assert.equal(hasGeoIPControl({ geoip_mode: '', geoip_countries: '["CN"]' }), false)
  assert.equal(hasGeoIPControl({ geoip_mode: 'deny', geoip_countries: 'bad-json' }), false)
  // 摘要接口形态（无显式字段）只看 has_geoip
  assert.equal(hasGeoIPControl({ has_geoip: true }), true)
  assert.equal(hasGeoIPControl({ has_geoip: false }), false)
})

test('resolveStageOverride：0=跟随策略；页缺失/内容空=broken；状态码兜底 403', () => {
  const pages = [
    { id: 5, name: '自定义拦截页', content: '<html>' },
    { id: 6, name: '空页面', content: '' },
  ]
  assert.equal(resolveStageOverride(0, 403, pages), null)
  assert.equal(resolveStageOverride(undefined, undefined, pages), null)
  assert.deepEqual(resolveStageOverride(5, 0, pages), { pageId: 5, pageName: '自定义拦截页', status: 403, broken: false })
  assert.deepEqual(resolveStageOverride(5, 429, pages), { pageId: 5, pageName: '自定义拦截页', status: 429, broken: false })
  assert.deepEqual(resolveStageOverride(6, 403, pages), { pageId: 6, pageName: '空页面', status: 403, broken: true })
  // 页已删除：名称回退为「页面 #id」且 broken（渲染侧等同未配）
  assert.deepEqual(resolveStageOverride(42, 403, pages), { pageId: 42, pageName: '页面 #42', status: 403, broken: true })
})

const stageGroup = (stage: 0 | 1 | 2 | 3, groups: StagePolicyGroup[]): StageGroup => ({
  stage,
  title: `阶段 ${stage}`,
  enabled: groups.length > 0,
  override: null,
  groups,
})

test('attachStageDetails：按策略 id 附着明细，缺策略的组不附着（不改其余字段）', () => {
  const model: RuleStageModel = {
    ruleDisabled: false,
    hasAnyPolicy: true,
    stages: [
      stageGroup(0, [
        { key: 7, order: 0, name: '信任', enabled: true, rows: [] },
        { key: 8, order: 1, name: '缺失策略', enabled: true, rows: [] },
      ]),
      stageGroup(1, []),
      stageGroup(2, []),
      stageGroup(3, []),
    ],
  }
  const attached = attachStageDetails(model, {
    policies: [policy({ id: 7, ip_whitelist: '["1.1.1.1"]' })],
    ipLists: [],
  })
  const stageZero = attached.stages[0]
  assert.equal(stageZero.groups[0]?.details?.trustEntries?.length, 1)
  assert.equal(stageZero.groups[0]?.details?.trustEntries?.[0]?.value, '1.1.1.1')
  assert.equal(stageZero.groups[1]?.details, undefined)
  // 不可变：原模型不被就地修改
  assert.equal(model.stages[0]?.groups[0]?.details, undefined)
})

test('compareVersion：段数值比较，v 前缀与长短段等价', () => {
  assert.ok(compareVersion('1.10', '1.9') > 0)
  assert.ok(compareVersion('v1.9', '1.10') < 0)
  assert.equal(compareVersion('v1.2.3', '1.2.3'), 0)
  assert.equal(compareVersion('1.2', '1.2.0'), 0)
  assert.ok(compareVersion('2.0.0', '1.99.99') > 0)
  // 非数字段按字符串序（预发布后缀）
  assert.ok(compareVersion('1.0.0-beta', '1.0.0') > 0)
})

test('formatDurationUs：0/缺省 → 占位，三档精度', () => {
  assert.equal(formatDurationUs(0), '—')
  assert.equal(formatDurationUs(undefined), '—')
  assert.equal(formatDurationUs(-1), '—')
  assert.equal(formatDurationUs(999), '0.999ms')
  assert.equal(formatDurationUs(1500), '1.5ms')
  assert.equal(formatDurationUs(12345), '12ms')
})

test('subscribeSharedEntriesCache：写回通知订阅者，退订后不再回调（无泄漏）', async () => {
  invalidateSharedEntriesCache()
  let hits = 0
  const unsubscribe = subscribeSharedEntriesCache(() => { hits++ })
  await ensureSharedEntries([11], async () => ['1.1.1.1'])
  assert.equal(hits, 1, '写回必须通知订阅者')
  unsubscribe()
  await ensureSharedEntries([12], async () => ['2.2.2.2'])
  assert.equal(hits, 1, '退订后不得再回调')
  invalidateSharedEntriesCache()
})
