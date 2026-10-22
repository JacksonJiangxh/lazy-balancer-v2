// 「把 IP 加入地址列表」组合子的行为验收：确认框 → 幂等 POST → added 短成功 /
// 已存在 info；取消/失败不得谎报完成；重入锁（双击/双动作）只允许一次写入。
//
// element-plus / api / saveResult 均为字节级或跨域依赖，用 data: 模块替身记录
// 调用；被测逻辑本身是真实实现。
//
// 被测模块必须动态 import：钩子注册先于模块求值，静态 import 会先加载真实
// element-plus（CSS/DOM 字节级依赖，node 下不可加载）。

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
  __post: (...args: unknown[]) => Promise<unknown>
  __get: (...args: unknown[]) => Promise<unknown>
  __put: (...args: unknown[]) => Promise<unknown>
}
const g = globalThis as unknown as Harness
g.__calls = []

registerModuleHooks({
  'element-plus': STUB_ELEMENT,
  '@/utils/api': STUB_API,
  '@/utils/saveResult': STUB_SAVE_RESULT,
})
const { useIpListAdd } = await import('../src/composables/useIpListAdd.ts')

const list = { id: 7, name: '办公网', entry_count: 3 }
const tick = (): Promise<void> => {
  const { promise, resolve } = Promise.withResolvers<void>()
  setTimeout(resolve, 0)
  return promise
}

const reset = (): void => {
  g.__calls = []
  g.__confirm = async (...args: unknown[]) => {
    g.__calls.push({ fn: 'confirm', args })
  }
  g.__post = async () => ({ data: { added: true } })
  g.__get = async () => ({ data: undefined })
  g.__put = async () => ({ data: undefined })
}

const callsOf = (fn: string): RecordedCall[] => g.__calls.filter((call) => call.fn === fn)

test('确认后幂等 POST：added=true 走 showSaveResult，返回完成并复位重入锁', async () => {
  reset()
  const posted: unknown[] = []
  g.__post = async (url: unknown, body: unknown) => {
    posted.push({ url, body })
    return { data: { added: true } }
  }
  const { adding, addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('203.0.113.9', list), true)

  const [confirm] = callsOf('confirm')
  const [message, title] = confirm.args ?? []
  assert.match(String(message), /203\.0\.113\.9/, '确认文案必须点名 IP')
  assert.match(String(message), /办公网/, '确认文案必须点名列表')
  assert.match(String(message), /幂等/, '确认文案必须声明幂等语义')
  assert.equal(title, '加入地址列表')
  assert.deepEqual(posted, [{ url: '/security/ip-lists/7/ips', body: { value: '203.0.113.9' } }])

  const saves = callsOf('showSaveResult')
  assert.equal(saves.length, 1)
  assert.deepEqual(saves[0].args, [{ data: { added: true } }, '已加入地址列表「办公网」'])
  assert.equal(adding.value, false, '完成后必须释放重入锁')
})

test('added=false（已存在）以 info 呈现，不弹成功提示', async () => {
  reset()
  g.__post = async (url: unknown) => {
    assert.equal(url, '/security/ip-lists/7/ips')
    return { data: { added: false } }
  }
  const { addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('1.2.3.4', list), true, '已存在同样视为动作完成（列表已含该 IP）')
  const infos = callsOf('ElMessage.info')
  assert.equal(infos.length, 1)
  assert.match(String(infos[0].arg), /已在列表「办公网」中/)
  assert.equal(callsOf('showSaveResult').length, 0)
})

test('取消确认不写库，也不提示成功', async () => {
  reset()
  g.__confirm = async () => {
    throw new Error('cancel')
  }
  const posted: unknown[] = []
  g.__post = async (url: unknown) => {
    posted.push(url)
    return { data: { added: true } }
  }
  const { adding, addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('1.2.3.4', list), false)
  assert.deepEqual(posted, [])
  assert.equal(adding.value, false)
  assert.equal(callsOf('showSaveResult').length, 0)
})

test('写入在途时重入直接拒绝（双击只产生一次 POST）', async () => {
  reset()
  const { promise, resolve } = Promise.withResolvers<unknown>()
  const posted: unknown[] = []
  g.__post = async (url: unknown) => {
    posted.push(url)
    return promise
  }
  const { adding, addIpToList } = useIpListAdd()
  const first = addIpToList('1.2.3.4', list)
  await tick()
  assert.equal(adding.value, true, '在途期间重入锁必须置位')
  assert.equal(await addIpToList('1.2.3.4', list), false, '重入必须立即拒绝')
  resolve({ data: { added: true } })
  assert.equal(await first, true)
  assert.deepEqual(posted, ['/security/ip-lists/7/ips'])
  assert.equal(adding.value, false)
})

test('写入失败返回 false 且释放重入锁（错误提示归全局拦截器）', async () => {
  reset()
  g.__post = async () => {
    throw new Error('500')
  }
  const { adding, addIpToList } = useIpListAdd()
  assert.equal(await addIpToList('1.2.3.4', list), false)
  assert.equal(adding.value, false)
  assert.equal(callsOf('showSaveResult').length, 0, '失败不得弹成功/退化提示')
  // 失败后可再次发起（锁已释放）
  g.__post = async () => ({ data: { added: true } })
  assert.equal(await addIpToList('1.2.3.4', list), true)
})
