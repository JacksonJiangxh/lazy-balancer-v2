// 「取消信任」的安全结论新鲜度：条目缓存 TTL 只约束「谁去重拉」，不约束
// 「谁能拿旧值下结论」——长开弹层（>60s）期间另一标签页/另一管理员在受引用
// 名单里增删覆盖该 IP 的 CIDR 时，直接读组件本地副本会漏报残余信任（把「引擎
// 仍信任」谎报成「已取消信任」）。
//
// 因此 planTrustRemoval 前必须按 TTL 强制补齐本策略信任侧引用的名单条目，并在
// 补齐失败（条目缺失）时拒绝出结论。本文件验证两件事：
//   1. securityStages 的「补齐后仍缺失」判据（失败面单源）行为正确；
//   2. IPLocationAction 的决策路径确实先补齐、且失败分支禁用动作并释放 busy。
//
// 运行：cd web && node --test tests/trustRemovalFreshness.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, section, source } from './_helpers.ts'
import {
  ensureSharedEntriesMissing,
  ensureSharedEntries,
  invalidateSharedEntriesCache,
  sharedEntriesCache,
} from '../src/utils/securityStages.ts'

const realNow = Date.now

test('补齐成功：回报空清单，缓存按 id 回填（loader 每 id 一次）', async () => {
  invalidateSharedEntriesCache()
  const calls: number[] = []
  const loader = async (id: number): Promise<string[]> => {
    calls.push(id)
    return [`10.0.0.${id}`]
  }
  assert.deepEqual(await ensureSharedEntriesMissing([1, 2], loader), [])
  assert.deepEqual(calls.sort(), [1, 2])
  assert.deepEqual(sharedEntriesCache[1], ['10.0.0.1'])
  assert.deepEqual(sharedEntriesCache[2], ['10.0.0.2'])
  // TTL 内不重复回源
  assert.deepEqual(await ensureSharedEntriesMissing([1, 2], loader), [])
  assert.deepEqual(calls.sort(), [1, 2])
  invalidateSharedEntriesCache()
})

test('单名单失败：回报该 id 且不留失败缓存（下次可重试，成功即清空回报）', async () => {
  invalidateSharedEntriesCache()
  let fail = true
  const loader = async (id: number): Promise<string[]> => {
    if (fail) throw new Error('boom')
    return [`10.0.1.${id}`]
  }
  assert.deepEqual(await ensureSharedEntriesMissing([7], loader), [7], '失败必须回报该 id（调用方据此拒绝出结论）')
  assert.equal(7 in sharedEntriesCache, false, '失败不得留下空/脏缓存（否则会被当作「名单为空」）')
  fail = false
  assert.deepEqual(await ensureSharedEntriesMissing([7], loader), [], '重试成功后失败面清空')
  assert.deepEqual(sharedEntriesCache[7], ['10.0.1.7'])
  invalidateSharedEntriesCache()
})

test('TTL 过期：过期缓存不算就绪（必须重拉后才回报空清单）', async () => {
  invalidateSharedEntriesCache()
  let offset = 0
  Date.now = () => realNow() + offset
  try {
    let version = 1
    const loader = async (): Promise<string[]> => [`203.0.113.0/24#${version}`]
    await ensureSharedEntries([5], loader)
    assert.deepEqual(await ensureSharedEntriesMissing([5], loader), [], 'TTL 内视为就绪')
    // 跨过 60s TTL：旧值不得再被当作就绪（长开弹层的形态）
    offset = 61_000
    version = 2
    assert.deepEqual(await ensureSharedEntriesMissing([5], loader), [], '过期后先重拉，重拉成功即就绪')
    assert.deepEqual(sharedEntriesCache[5], ['203.0.113.0/24#2'], '回报就绪必须建立在重新拉取的值上')
  } finally {
    Date.now = realNow
    invalidateSharedEntriesCache()
  }
})

// —— 组件侧：决策路径的顺序与失败门（node --test 无 .vue 装载器，用限段文本钉）——

const page = code('src/views/security/IPLocationAction.vue')

test('取消信任：先取最新策略、补齐信任侧引用名单条目，再算处置计划', () => {
  const cancel = section(page, 'const cancelTrustAll = async', '\n}\n')
  const refreshAt = cancel.indexOf('await ensureSharedEntriesMissing(refIds, loadListEntries)')
  const planAt = cancel.indexOf('const plan = buildPlan(policy)')
  assert.ok(refreshAt > 0, '决策前必须补齐条目（安全结论不得读可能过期的显示缓存）')
  assert.ok(planAt > refreshAt, '补齐必须早于出计划 —— 否则计划仍按旧条目计算')
  // 只刷新本策略信任侧引用（不做与本决策无关的整批下载）；refs 取自**最新策略**
  // 而非弹层挂载快照——并发新增的信任引用列表同样要被补齐与移除。
  assert.match(cancel, /const trustRefIds = parseRefIds\(policy\.ip_whitelist_refs\)/)
  const callAt = cancel.indexOf('const missingTrustIds = await refreshTrustEntries(trustRefIds)')
  assert.ok(callAt > 0, '补齐调用必须传入本策略信任侧 refs')
  assert.ok(cancel.indexOf('const trustRefIds') < callAt, '补齐的 id 集合必须来自最新策略信任侧 refs')
  assert.match(cancel, /policy = await fetchDetail\(row\.policy\.id\)/, '决策前必须重取策略（不得读挂载快照）')
})

test('补齐失败不得出结论：置错误态、释放 busy、不进入确认/写入', () => {
  const cancel = section(page, 'const cancelTrustAll = async', '\n}\n')
  const checkAt = cancel.indexOf('if (missingTrustIds.length > 0) {')
  assert.ok(checkAt > 0, '必须校验补齐结果')
  const failure = cancel.slice(checkAt, cancel.indexOf('const plan = buildPlan(policy)', checkAt))
  assert.match(failure, /listsError\.value = true/, '失败必须与加载失败态同口径（禁用全部处置动作 + 横幅重试）')
  assert.match(failure, /unlockBusy\(row\.policy\.id, 'untrust'\)/, '失败路径必须释放 busy 锁（否则按钮永久转圈）')
  assert.match(failure, /return\b/, '失败路径必须直接返回，不得落到确认框/写入')
  assert.doesNotMatch(failure, /ElMessageBox|request\.(put|post)/, '失败路径不得触发确认或写入')
})

test('刷新期间的缓存中间态不得回写显示（不出现名单瞬时空缺）', () => {
  // ensure 对过期 id 先静默删除、再逐个回填，每次回填都会通知；若中间态照抄进
  // 本地副本，尚未回填的名单会瞬时显示成「未在该名单」。
  assert.match(page, /let entriesRefreshInFlight = false/)
  const subscribeAt = page.indexOf('subscribeSharedEntriesCache(() => {')
  assert.ok(subscribeAt > 0, '必须订阅共享缓存变更')
  const handler = page.slice(subscribeAt, page.indexOf('})', subscribeAt))
  assert.match(handler, /if \(entriesRefreshInFlight\) return/, '刷新期间必须跳过中间态回写')
  const cancel = section(page, 'const cancelTrustAll = async', '\n}\n')
  const flagAt = cancel.indexOf('entriesRefreshInFlight = true')
  const refreshAt = cancel.indexOf('await ensureSharedEntriesMissing(refIds, loadListEntries)')
  assert.ok(flagAt > 0 && flagAt < refreshAt, '必须在发请求前置位抑制标记')
  assert.match(cancel, /\.finally\(\(\) => \{ entriesRefreshInFlight = false \}\)/, '刷新结束（含失败）必须复位标记')
  assert.ok(
    cancel.indexOf('ipListEntries.value = { ...sharedEntriesCache }', refreshAt) > refreshAt,
    '刷新返回后必须整体替换本地副本（界面只看到补齐后的结果）',
  )
})

test('条目请求单一实现：加载态与决策前刷新共用同一 loader', () => {
  assert.match(page, /const loadListEntries = async \(id: number\): Promise<string\[\]> =>/)
  assert.equal(
    (page.match(/\/security\/ip-lists\/\$\{id\}/g) ?? []).length,
    1,
    '单名单条目请求只允许一处实现（第二份会在归一/字段变化时漂移）',
  )
  const loadIpLists = section(page, 'const loadIpLists = async', '\n}\n')
  assert.match(loadIpLists, /ensureSharedEntriesMissing\(refIds, loadListEntries\)/, '加载态必须复用同一 loader')
})

// 文档钉：planTrustRemoval 的输入契约必须声明 listEntries 的新鲜度要求——它是
// 本函数「不谎报已取消信任」承诺的前提条件，删掉这句话会让后续调用方以为可以直接
// 传组件本地副本。
test('文档钉：planTrustRemoval 的 listEntries 契约声明新鲜度要求', () => {
  const removal = source('src/utils/trustRemoval.ts')
  const fieldAt = removal.indexOf('readonly listEntries')
  assert.ok(fieldAt > 0, 'planTrustRemoval 入参必须含 listEntries')
  const field = removal.slice(removal.lastIndexOf('/**', fieldAt), fieldAt)
  assert.match(field, /必须新鲜/, 'listEntries 契约必须显式要求新鲜条目')
  assert.match(field, /不得出结论/, '契约必须声明拉取失败时不得出结论')
})
