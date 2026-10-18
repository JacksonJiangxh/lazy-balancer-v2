// IP 名单弹框守卫与 CSV 往返验收（历史 历史问题 / 历史问题）：
//   A. 详情在途/失败时保存必须禁用（否则空 entries 全量 PUT 清空名单）
//   B. 已有名单 + 空条目需二次确认；新建空名单不弹
//   C. 导出→导入逐字相等，二次往返不累积漂移（备注含逗号/引号/换行）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { canSaveIpList, needsEmptyListConfirm } from '../src/utils/ipListSaveGuard.ts'
import { formatIpListEntryLine, parseIpListEntryLine } from '../src/utils/ipListCsv.ts'
import {
  ensureSharedEntries,
  invalidateSharedEntriesCache,
  parseIPList,
  sharedEntriesCache,
  writeSharedEntries,
} from '../src/utils/securityStages.ts'

test('IP 快捷处置：信任命中只全扫一次，GeoIP 区域只解析一次（历史问题/历史问题）', () => {
  const src = readFileSync(new URL('../src/views/security/IPLocationAction.vue', import.meta.url), 'utf8')
  assert.match(src, /const trustHitSummary = computed/, '信任命中与豁免策略应共享一次计算')
  assert.doesNotMatch(src, /const td[01]Owner = policies\.value\.find/, '逐行不得再全策略扫描')
  assert.doesNotMatch(src, /JSON\.parse\(policy\.geoip_countries/, 'GeoIP 区域不得重复 JSON.parse')
  assert.match(src, /const regions = parseIPList\(policy\.geoip_countries\)/)
})

test('规则流程只拉本规则阶段 0 策略的信任引用（历史问题）', () => {
  const src = readFileSync(new URL('../src/components/RuleFlowDialog.vue', import.meta.url), 'utf8')
  assert.match(src, /boundTrustPolicyIds/)
  assert.match(src, /if \(!boundTrustPolicyIds\.has\(pol\.id\)\) continue/)
})

const isIp = (value: string): boolean => /^\d{1,3}(\.\d{1,3}){3}(\/\d{1,2})?$/.test(value)

test('A 保存守卫：加载中/失败两种形态均禁止保存', () => {
  assert.equal(canSaveIpList(false, false), true)
  assert.equal(canSaveIpList(true, false), false, '详情在途：entries 为空，禁止保存')
  assert.equal(canSaveIpList(false, true), false, '详情失败：必须禁止保存')
  assert.equal(canSaveIpList(true, true), false)
})

test('B 空条目确认：仅已有名单触发（新建空名单是合法操作）', () => {
  assert.equal(needsEmptyListConfirm(12, 0), true)
  assert.equal(needsEmptyListConfirm(12, 3), false)
  assert.equal(needsEmptyListConfirm(null, 0), false)
})

test('C1 CSV 往返：备注含逗号/引号逐字相等', () => {
  const value = '10.0.0.1'
  const remark = '备注,含逗号"和引号"'
  const line = formatIpListEntryLine(value, remark)
  assert.equal(line, '10.0.0.1,"备注,含逗号""和引号"""')
  assert.deepEqual(parseIpListEntryLine(line, isIp), { value, remark })
})

test('C2 二次往返不累积漂移', () => {
  let remark = 'a,"b",c'
  let line = formatIpListEntryLine('192.168.1.0/24', remark)
  for (let i = 0; i < 3; i++) {
    const parsed = parseIpListEntryLine(line, isIp)
    assert.ok(parsed)
    assert.equal(parsed.remark, remark)
    line = formatIpListEntryLine(parsed.value, parsed.remark)
  }
})

test('C3 旧格式（无引号、逗号/空白分隔）保持兼容', () => {
  assert.deepEqual(parseIpListEntryLine('10.0.0.1,普通备注', isIp), { value: '10.0.0.1', remark: '普通备注' })
  assert.deepEqual(parseIpListEntryLine('10.0.0.1 普通备注', isIp), { value: '10.0.0.1', remark: '普通备注' })
  assert.deepEqual(parseIpListEntryLine('10.0.0.1', isIp), { value: '10.0.0.1', remark: '' })
  assert.deepEqual(parseIpListEntryLine('2001:db8::/32', isIp), null, '非法值由注入校验拒绝')
})

test('C4 畸形行：未闭合引号/空值返回 null（导入计数为非法，不静默吞）', () => {
  assert.equal(parseIpListEntryLine('"10.0.0.1', isIp), null)
  assert.equal(parseIpListEntryLine(',remark', isIp), null)
  assert.equal(parseIpListEntryLine('   ', isIp), null)
  assert.equal(parseIpListEntryLine('10.0.0.1,"未闭合', isIp), null)
})

test('C5 引号包裹的 IP 字段（外部 CSV 工具产物）可解析', () => {
  assert.deepEqual(parseIpListEntryLine('"10.0.0.2","备注"', isIp), { value: '10.0.0.2', remark: '备注' })
})

test('C6 多行备注导出归一为空格——导入端按行切分，往返不丢备注（历史问题-11）', () => {
  const line = formatIpListEntryLine('10.0.0.1', '第一行\r\n第二行')
  assert.equal(line, '10.0.0.1,第一行 第二行')
  const parsed = parseIpListEntryLine(line, isIp)
  assert.deepEqual(parsed, { value: '10.0.0.1', remark: '第一行 第二行' })
})

test('C7 备注按 Unicode code point 截断 100，不产生半个代理对（历史问题-15）', () => {
  const parsed = parseIpListEntryLine(`10.0.0.1,${'😀'.repeat(100)}尾`, isIp)
  assert.ok(parsed)
  assert.equal(Array.from(parsed.remark).length, 100)
  assert.equal(parsed.remark, '😀'.repeat(100))
  assert.equal(parsed.remark.isWellFormed(), true)
})

test('C8 JSON 字符串数组统一 trim 并丢弃空项（历史问题-17）', () => {
  assert.deepEqual(parseIPList('[" 1.1.1.1 ","","  ",2,"10.0.0.0/8"]'), ['1.1.1.1', '10.0.0.0/8'])
  const crsSource = readFileSync(new URL('../src/composables/useCrsRuleIndex.ts', import.meta.url), 'utf8')
  assert.match(crsSource, /normalizeStringEntries\(rec\.ips\)/, 'CRS 排除规则数组必须复用同一 trim 归一')
})

test('D 共享条目缓存：缺失才拉、并发去重、失败可重试、invalidate 后重拉', async () => {
  invalidateSharedEntriesCache()
  const calls: number[] = []
  const loader = async (id: number): Promise<string[]> => {
    calls.push(id)
    if (id === 9) throw new Error('boom')
    return [`10.0.0.${id}`]
  }
  // 并发两次：同一 id 只发一次请求（in-flight 复用）
  await Promise.all([ensureSharedEntries([1, 2, 9], loader), ensureSharedEntries([1, 2, 9], loader)])
  assert.deepEqual(calls.sort((a, b) => a - b), [1, 2, 9])
  assert.deepEqual(sharedEntriesCache[1], ['10.0.0.1'])
  assert.equal(9 in sharedEntriesCache, false, '失败不得写缓存')
  // 已缓存 id 不再请求；失败 id 重试
  calls.length = 0
  await ensureSharedEntries([1, 2, 9], loader)
  assert.deepEqual(calls, [9])
  // 写回与失效通知
  writeSharedEntries(3, ['10.0.0.3'])
  assert.deepEqual(sharedEntriesCache[3], ['10.0.0.3'])
  invalidateSharedEntriesCache()
  calls.length = 0
  await ensureSharedEntries([1], loader)
  assert.deepEqual(calls, [1])
  invalidateSharedEntriesCache()
})

test('D2 代际守卫：失效前发起的在途 loader 落地不得回填缓存（历史问题-03）', async () => {
  invalidateSharedEntriesCache()
  let release: () => void = () => {}
  const gate = new Promise<void>((resolve) => { release = resolve })
  const pending = ensureSharedEntries([7], async () => {
    await gate
    return ['10.0.0.7-old']
  })
  // 在途期间发生写动作：失效缓存并递增代际
  invalidateSharedEntriesCache()
  release()
  await pending
  assert.equal(7 in sharedEntriesCache, false, '迟到结果必须丢弃，保持未缓存待重取')
  // 重取得到新值
  await ensureSharedEntries([7], async () => ['10.0.0.7-new'])
  assert.deepEqual(sharedEntriesCache[7], ['10.0.0.7-new'])
  invalidateSharedEntriesCache()
})
