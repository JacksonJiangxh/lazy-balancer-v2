// 信任/黑/白三侧快捷处置组合子的行为验收：同侧列表解析（逐引用、排除系统
// 名单）、加入既有列表、无列表时「创建 + 关联 + 加入」一步完成、移除后的
// removed=false 兜底文案、以及确认取消/重入锁不被跳过。
//
// element-plus / api / saveResult 用 data: 模块替身记录调用；useIpListAdd 使用
// 真实实现（同一条写入链路）。被测模块动态 import：钩子须先注册。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'

interface RecordedCall {
  fn: string
  arg?: unknown
  args?: unknown[]
}

type Harness = {
  __calls: RecordedCall[]
  __confirm: (...args: unknown[]) => Promise<unknown>
  __post: (url: string, body?: unknown) => Promise<unknown>
  __get: (url: string, config?: unknown) => Promise<unknown>
  __put: (url: string, body?: unknown) => Promise<unknown>
}
const g = globalThis as unknown as Harness
g.__calls = []

const dataModule = (code: string): string => `data:text/javascript,${encodeURIComponent(code)}`
const stubElement = dataModule(`
export const ElMessage = Object.assign(
  (arg) => globalThis.__calls.push({ fn: 'ElMessage', arg }),
  {
    info: (arg) => globalThis.__calls.push({ fn: 'ElMessage.info', arg }),
    error: (arg) => globalThis.__calls.push({ fn: 'ElMessage.error', arg }),
    success: (arg) => globalThis.__calls.push({ fn: 'ElMessage.success', arg }),
  },
)
export const ElMessageBox = { confirm: (...args) => globalThis.__confirm(...args) }
`)
const stubApi = dataModule(`
export const request = {
  get: (...args) => globalThis.__get(...args),
  post: (...args) => globalThis.__post(...args),
  put: (...args) => globalThis.__put(...args),
}
export const mfaAwareSuccess = (message) => globalThis.__calls.push({ fn: 'mfaAwareSuccess', arg: message })
`)
const stubSaveResult = dataModule(`
export const showSaveResult = (...args) => globalThis.__calls.push({ fn: 'showSaveResult', args })
`)
registerModuleHooks({
  'element-plus': stubElement,
  '@/utils/api': stubApi,
  '@/utils/saveResult': stubSaveResult,
})
const { useTrustAssociation } = await import('../src/composables/useTrustAssociation.ts')

interface PostRecord {
  url: string
  body: unknown
}
interface PutRecord {
  url: string
  body: unknown
}

const lists = [
  { id: 1, name: '内联黑名单' },
  { id: 2, name: '威胁情报库', system: 1 },
  { id: 3, name: '办公网段', entry_count: 5 },
  { id: 9, name: '未引用列表' },
]

const reset = (): { posts: PostRecord[]; puts: PutRecord[]; confirmArgs: unknown[][] } => {
  const posts: PostRecord[] = []
  const puts: PutRecord[] = []
  const confirmArgs: unknown[][] = []
  g.__calls = []
  g.__confirm = async (...args: unknown[]) => {
    confirmArgs.push(args)
  }
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    if (url === '/security/ip-lists') return { data: { id: 42 } }
    if (url.endsWith('/ips')) return { data: { added: true } }
    if (url.endsWith('/remove-ip')) return { data: { removed: true } }
    throw new Error(`unexpected POST ${url}`)
  }
  g.__put = async (url: string, body?: unknown) => {
    puts.push({ url, body })
    return { data: undefined }
  }
  g.__get = async () => ({ data: undefined })
  return { posts, puts, confirmArgs }
}

const callsOf = (fn: string): RecordedCall[] => g.__calls.filter((call) => call.fn === fn)

test('同侧列表解析：按引用逐列表返回、排除系统内置名单、缺失计数归零', () => {
  reset()
  const { resolveSideLists } = useTrustAssociation({ getList: () => lists })
  const policy = {
    id: 5,
    name: '策略 A',
    ip_acl_list_refs: '[1,2,3,9]',
    ip_whitelist_refs: '[2]',
  }
  assert.deepEqual(resolveSideLists(policy, 'deny'), [
    { id: 1, name: '内联黑名单', entry_count: 0 },
    { id: 3, name: '办公网段', entry_count: 5 },
    { id: 9, name: '未引用列表', entry_count: 0 },
  ])
  assert.deepEqual(resolveSideLists(policy, 'trust'), [], '信任侧只关联系统名单时解析为空')
  assert.deepEqual(
    resolveSideLists({ id: 6, name: '策略 B', ip_acl_list_refs: '{bad json' }, 'allow'),
    [],
    '坏 refs 文本回退空集（不炸渲染）',
  )
})

test('加入指定列表：确认 + 幂等 POST + onChanged 回调，返回完成', async () => {
  const { posts, confirmArgs } = reset()
  let changed = 0
  const { joinSpecificList } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  assert.equal(await joinSpecificList({ id: 3, name: '办公网段', entry_count: 5 }, '203.0.113.9', '信任'), true)
  assert.equal(confirmArgs.length, 1)
  assert.match(String(confirmArgs[0][0]), /办公网段/)
  assert.deepEqual(posts, [{ url: '/security/ip-lists/3/ips', body: { value: '203.0.113.9' } }])
  assert.equal(changed, 1, '写入成功后必须通知组件刷新')
  const saves = callsOf('showSaveResult')
  assert.equal(saves.length, 1)
  assert.match(String(saves[0].args?.[1]), /已信任——已加入列表「办公网段」/)
})

test('单击加入：策略已关联同侧非系统列表时直接加入首个列表，不创建', async () => {
  const { posts } = reset()
  let changed = 0
  const { ensureListAndJoin } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  await ensureListAndJoin(
    { id: 5, name: '策略 A', ip_acl_list_refs: '[1,2,3]' },
    '203.0.113.9',
    'deny',
  )
  assert.deepEqual(posts, [{ url: '/security/ip-lists/1/ips', body: { value: '203.0.113.9' } }], '按引用顺序取首个非系统列表')
  assert.equal(changed, 1)
})

test('无同侧列表：确认后创建 → 关联 refs → 加入 IP（一步完成）', async () => {
  const { posts, puts, confirmArgs } = reset()
  let changed = 0
  const { ensureListAndJoin } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  const policy = { id: 5, name: '策略 A', ip_whitelist_refs: '', ip_whitelist_enabled: false }
  await ensureListAndJoin(policy, '203.0.113.9', 'trust')

  assert.equal(confirmArgs.length, 1)
  const [message, title] = confirmArgs[0]
  assert.match(String(message), /尚未关联信任用地址列表/)
  assert.match(String(message), /暂不生效/, '信任未启用必须提示加入后暂不生效')
  assert.match(String(title), /创建列表并信任/)

  assert.deepEqual(posts, [
    { url: '/security/ip-lists', body: { name: '策略 A-信任', category: 'custom', entries: '[]' } },
    { url: '/security/ip-lists/42/ips', body: { value: '203.0.113.9' } },
  ])
  assert.deepEqual(puts, [
    { url: '/security/policies/5', body: { ip_whitelist_refs: '[42]' } },
  ])
  const saves = callsOf('showSaveResult')
  assert.equal(saves.length, 1)
  assert.match(String(saves[0].args?.[1]), /已创建「策略 A-信任」并加入 203\.0\.113\.9/)
  assert.equal(changed, 1)
})

test('同名未引用列表复用而非重复创建（仍关联并加入）', async () => {
  const { posts, puts } = reset()
  const sameName = [...lists, { id: 77, name: '策略 A-信任' }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => sameName })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }], '不得重复创建同名列表')
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_whitelist_refs: '[77]' } }])
  assert.match(String(callsOf('showSaveResult')[0].args?.[1]), /已关联既有/)
})

test('创建路径取消确认：不创建/不关联/不加入，重入锁释放', async () => {
  const { posts, puts } = reset()
  g.__confirm = async () => {
    throw new Error('cancel')
  }
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_whitelist_refs: '' }, '203.0.113.9', 'trust')
  assert.deepEqual(posts, [])
  assert.deepEqual(puts, [])
  assert.equal(creating.value, false)
})

test('既有列表加入不触碰策略 refs（无需补关联）', async () => {
  const { puts } = reset()
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  // 首个非系统列表 id=1 已在 refs 中 → 修正路径不触发 PUT
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '[1]' }, '1.2.3.4', 'deny')
  assert.deepEqual(puts, [], '既有列表加入不触碰策略 refs')
})

test('移除：removed=true 成功提示；removed=false 如实提示 CIDR 覆盖，两者都刷新', async () => {
  const removed = reset()
  let changed = 0
  const { removeFromSideRef } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  assert.deepEqual(removed.posts, [{ url: '/security/ip-lists/3/remove-ip', body: { value: '203.0.113.9' } }])
  assert.match(String(callsOf('ElMessage.success')[0].arg), /已从「办公网段」移除/)
  assert.equal(changed, 1)

  const kept = reset()
  g.__post = async (url: string) => {
    kept.posts.push({ url, body: null })
    return { data: { removed: false } }
  }
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  const infos = callsOf('ElMessage.info')
  assert.equal(infos.length, 1)
  assert.match(String(infos[0].arg), /没有 203\.0\.113\.9 的精确条目/, 'removed=false 不得报成功')
  assert.match(String(infos[0].arg), /CIDR/, '必须给出 CIDR 覆盖的解释')
  assert.equal(callsOf('ElMessage.success').length, 0)
  assert.equal(changed, 2, '无精确条目同样改变了列表可见状态，须刷新')
})
