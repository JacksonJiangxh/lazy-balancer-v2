// 信任/黑/白三侧快捷处置组合子的行为验收：同侧列表解析（逐引用、排除系统
// 名单）、加入既有列表、无列表时「创建（建单即带 IP）+ 关联」两步完成、同名
// 判据与后端唯一性同口径（ASCII 大小写折叠）、移除后的 removed=false 兜底
// 文案、以及确认取消/重入锁不被跳过。
//
// element-plus / api / saveResult 用 data: 模块替身记录调用；useIpListAdd 使用
// 真实实现（同一条写入链路）。被测模块动态 import：钩子须先注册。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'
import { STUB_API, STUB_ELEMENT, STUB_SAVE_RESULT } from './_stubs.ts'

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

registerModuleHooks({
  'element-plus': STUB_ELEMENT,
  '@/utils/api': STUB_API,
  '@/utils/saveResult': STUB_SAVE_RESULT,
})
const { useTrustAssociation, fitAutoListName } = await import('../src/composables/useTrustAssociation.ts')

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

test('无同侧列表：确认后创建（建单即带 IP）→ 关联 refs，两步完成', async () => {
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

  // 建单即播种条目：创建载荷自带 IP，写序收敛为「创建 → 关联」两次请求。
  // 原写序（创建空名单 → 关联 → 加入 IP）在加入失败时会留下已被策略引用的空名单。
  assert.deepEqual(posts, [
    {
      url: '/security/ip-lists',
      body: { name: '策略 A-信任', category: 'custom', entries: JSON.stringify([{ value: '203.0.113.9', remark: '' }]) },
    },
  ])
  assert.deepEqual(puts, [
    { url: '/security/policies/5', body: { ip_whitelist_refs: '[42]' } },
  ])
  const saves = callsOf('mfaAwareSuccess')
  assert.equal(saves.length, 1)
  assert.match(String(saves[0].arg), /已创建「策略 A-信任」并加入 203\.0\.113\.9/)
  assert.equal(changed, 1)
})

test('新建路径关联失败：名单已带 IP、未被引用，不留「被引用的空名单」', async () => {
  const { posts, puts } = reset()
  g.__put = async (url: string, body?: unknown) => {
    puts.push({ url, body })
    throw new Error('policy update failed')
  }
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '' }, '203.0.113.9', 'deny')

  assert.equal(posts.length, 1, '只应有创建请求（加入条目不单独发起）')
  const body: unknown = posts[0].body
  assert.ok(body && typeof body === 'object' && 'entries' in body, '创建载荷必须是对象')
  assert.deepEqual(JSON.parse(String(body.entries)), [{ value: '203.0.113.9', remark: '' }], '创建载荷必须已带本次 IP')
  assert.equal(puts.length, 1, '关联确实尝试过')
  assert.equal(callsOf('mfaAwareSuccess').length, 0, '关联失败不得报成功')
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

// 后端创建判重是 `LOWER(name)=LOWER(?)`（ASCII 大小写折叠）——前端复用既有名单
// 的查找必须同口径，否则策略名仅差大小写时（允许存在）会错过既有名单、转而创建，
// 换来一条 409 且本次加入不发生（弹框一次性，无改用既有名单的出口）。
test('同名判据与后端同口径：仅 ASCII 大小写不同也复用既有名单', async () => {
  const { posts, puts } = reset()
  const existing = [...lists, { id: 77, name: 'demo-白名单' }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: 'DEMO', ip_acl_list_refs: '' }, '203.0.113.9', 'allow')
  assert.equal(posts.filter((post) => post.url === '/security/ip-lists').length, 0, '不得再创建（后端会 409）')
  assert.deepEqual(posts, [{ url: '/security/ip-lists/77/ips', body: { value: '203.0.113.9' } }])
  assert.deepEqual(puts, [{ url: '/security/policies/5', body: { ip_acl_list_refs: '[77]' } }])
})

test('非 ASCII 大小写仍视为不同名单（SQLite LOWER 只折叠 ASCII）', async () => {
  const { posts } = reset()
  const existing = [...lists, { id: 77, name: 'ä-白名单' }]
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => existing })
  await ensureListAndJoin({ id: 5, name: 'Ä', ip_acl_list_refs: '' }, '203.0.113.9', 'allow')
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.ok(created, '非 ASCII 大小写变体后端视为新名，前端不得提前合并')
  const body: unknown = created.body
  assert.ok(body && typeof body === 'object' && 'name' in body, '创建载荷必须是对象')
  assert.equal(body.name, 'Ä-白名单')
})

// 写入口失败（reject）路径：creating/adding 的复位全靠 finally——一旦被挪进成功
// 分支，网络抖动后按钮永久灰死，而成功/取消用例仍全绿。
test('创建写入 reject：释放 creating 占位且不谎报成功', async () => {
  const { posts, puts } = reset()
  g.__post = async (url: string) => {
    if (url === '/security/ip-lists') throw new Error('boom')
    throw new Error(`unexpected POST ${url}`)
  }
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '' }, '203.0.113.9', 'deny')
  assert.equal(posts.length, 0, '失败的创建请求不记录成功响应')
  assert.equal(puts.length, 0, '创建失败不得继续关联')
  assert.equal(creating.value, false, '失败分支必须释放占位（否则按钮永久灰死）')
  assert.equal(callsOf('mfaAwareSuccess').length, 0, '创建失败不得报成功')
})

test('关联（PUT）reject：释放 creating 占位', async () => {
  reset()
  g.__put = async () => {
    throw new Error('boom')
  }
  const { creating, ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: '策略 A', ip_acl_list_refs: '' }, '203.0.113.9', 'deny')
  assert.equal(creating.value, false)
})

test('移除写入 reject：释放 creating 占位且不提示成功', async () => {
  reset()
  g.__post = async () => {
    throw new Error('boom')
  }
  const { creating, removeFromSideRef } = useTrustAssociation({ getList: () => lists })
  await removeFromSideRef({ id: 3, name: '办公网段' }, '203.0.113.9')
  assert.equal(creating.value, false, '失败分支必须释放占位')
  assert.equal(callsOf('ElMessage.success').length, 0, '移除失败不得报成功')
})

test('加入指定列表：写入在途时重入被拒（adding 锁经 joinSpecificList 传递）', async () => {
  const { posts } = reset()
  const { promise, resolve } = Promise.withResolvers<unknown>()
  let changed = 0
  g.__post = async (url: string, body?: unknown) => {
    posts.push({ url, body })
    return promise
  }
  const { joinSpecificList } = useTrustAssociation({
    getList: () => lists,
    onChanged: () => {
      changed += 1
    },
  })
  const target = { id: 3, name: '办公网段', entry_count: 5 }
  const first = joinSpecificList(target, '203.0.113.9', '信任')
  await new Promise<void>((done) => setTimeout(done, 0))
  assert.equal(await joinSpecificList(target, '203.0.113.9', '信任'), false, '在途重入必须立即拒绝')
  resolve({ data: { added: true } })
  assert.equal(await first, true)
  assert.deepEqual(posts, [{ url: '/security/ip-lists/3/ips', body: { value: '203.0.113.9' } }], '只产生一次 POST')
  assert.equal(changed, 1, '成功后才通知刷新')
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

test('自动名单名按 50 rune 预算：超长策略名截断且保留后缀', () => {
  // 46 rune 策略名 + 4 rune 后缀 = 50（恰满，不截断）
  const exact = 'a'.repeat(46)
  assert.deepEqual(fitAutoListName(exact, '-黑名单'), { name: `${exact}-黑名单`, truncated: false })
  // 55 rune 策略名 + 后缀 = 58 → 截断策略名部分，后缀完整保留，总长 50
  const long = 'a'.repeat(55)
  const fitted = fitAutoListName(long, '-信任')
  assert.equal(fitted.truncated, true)
  assert.equal(Array.from(fitted.name).length, 50)
  assert.ok(fitted.name.endsWith('-信任'))
  // 多字节字符按 rune 计数，不按 UTF16 编码单元
  const cjk = '策'.repeat(60)
  assert.equal(Array.from(fitAutoListName(cjk, '-黑名单').name).length, 50)
})

test('超长策略名创建并加入：名单名不超 50 且确认文案披露截断', async () => {
  const { posts, confirmArgs } = reset()
  const long = '长'.repeat(55)
  const { ensureListAndJoin } = useTrustAssociation({ getList: () => lists })
  await ensureListAndJoin({ id: 5, name: long, ip_acl_list_refs: '' }, '203.0.113.9', 'deny')
  const created = posts.find((post) => post.url === '/security/ip-lists')
  assert.ok(created, '必须发起创建')
  const body: unknown = created.body
  assert.ok(body && typeof body === 'object' && 'name' in body && 'entries' in body, '创建载荷必须是对象')
  assert.equal(Array.from(String(body.name)).length, 50)
  assert.ok(String(body.name).endsWith('-黑名单'))
  assert.deepEqual(JSON.parse(String(body.entries)), [{ value: '203.0.113.9', remark: '' }], '建单载荷必须带本次 IP')
  assert.match(String(confirmArgs[0][0]), /已截断至 50 字符上限/, '确认文案必须披露截断')
  const saves = callsOf('mfaAwareSuccess')
  assert.match(String(saves[0].arg), new RegExp(`已创建「${String(body.name)}」`), '成功文案必须用实际名单名')
})
