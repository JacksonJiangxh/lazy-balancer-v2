// 跨标签页会话同步的行为验收：令牌在另一个标签页被登出/改写时，本标签页的
// store 必须跟随——否则内存里的旧 JWT 让界面继续以「已登录」渲染，而请求层
// 只读 localStorage（已无令牌），每次操作静默 401：既不弹错误也回不到登录页。
//
// auth.ts 模块顶层读 location/localStorage，且依赖 pinia 与 element-plus 的
// 字节级链；本 spec 造最小浏览器宿主 + 替身后直测真实 store（不复刻逻辑）。
//
// 运行：cd web && node --test tests/authCrossTabSession.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createPinia, setActivePinia } from 'pinia'

import { registerModuleHooks } from './_helpers.ts'
import { dataModule } from './_stubs.ts'

// ── 最小浏览器宿主（只提供 auth store 的消费面） ──
const storage = new Map<string, string>()
const storageListeners: Array<(event: unknown) => void> = []
const timers = new Map<number, () => void>()
let nextTimerId = 1

const locationStub = { search: '', hash: '#/dashboard', href: 'http://panel.test/', pathname: '/' }

const windowStub = {
  location: locationStub,
  history: { replaceState: (): void => {} },
  addEventListener: (type: string, listener: (event: unknown) => void): void => {
    if (type === 'storage') storageListeners.push(listener)
  },
  setTimeout: (callback: () => void): number => {
    const id = nextTimerId++
    timers.set(id, callback)
    return id
  },
  clearTimeout: (id: number): void => {
    timers.delete(id)
  },
}

const host = globalThis as unknown as Record<string, unknown>
host.window = windowStub
host.location = locationStub
host.localStorage = {
  getItem: (key: string): string | null => storage.get(key) ?? null,
  setItem: (key: string, value: string): void => {
    storage.set(key, value)
  },
  removeItem: (key: string): void => {
    storage.delete(key)
  },
  clear: (): void => {
    storage.clear()
  },
}
host.document = { hidden: false, addEventListener: (): void => {} }
host.__authGet = async (url: string) => url === '/users/me'
  ? { data: { id: 7, username: 'alice', role: 'admin', is_enabled: true, display_name: 'Alice', mfa_enabled: false, auth_provider: 'local' } }
  : { data: { is_master: true, timezone: 'Asia/Shanghai', cert_renewal_days: 30, mfa_write_guard: false } }

storage.set('token', 'tok-tab-a')

registerModuleHooks({
  'element-plus': dataModule(`
export const ElMessage = Object.assign(
  () => {},
  { success: () => {}, error: () => {}, info: () => {}, warning: () => {} },
)
`),
  '@/utils/api': dataModule(`
export class ApiRequestError extends Error {
  constructor(message, status) { super(message); this.status = status; this.name = 'ApiRequestError' }
}
export const isTokenExpired = (token) => !token
export const request = { get: (url) => globalThis.__authGet(url), post: async () => ({ data: undefined }) }
`),
})

// 静态 import 不可行：auth.ts 的模块顶层就读 location/localStorage，必须先搭好
// 浏览器宿主再加载（且 element-plus 替身经 registerModuleHooks 注册，同样先于加载）。
const { useAuthStore } = await import('../src/stores/auth.ts')

const newStore = () => {
  // 定时器表是宿主状态：上一个用例的重试链不得计入本用例（各 store 实例的
  // 停表行为按自身断言）。
  timers.clear()
  setActivePinia(createPinia())
  return useAuthStore()
}

const dispatchStorage = (key: string | null): void => {
  for (const listener of storageListeners) listener({ key })
}

const flush = (): Promise<void> => {
  const { promise, resolve } = Promise.withResolvers<void>()
  setTimeout(resolve, 0)
  return promise
}

test('另一标签页登出：本标签页同步清空令牌/用户/节点模式并停表', () => {
  storage.set('token', 'tok-tab-a')
  const store = newStore()
  assert.equal(store.token, 'tok-tab-a')

  // 另一标签页 logout()：清 localStorage → 本标签页收到 storage 事件
  storage.delete('token')
  dispatchStorage('token')

  assert.equal(store.token, null, '内存令牌必须跟随 localStorage 清空（App.vue 据此回登录页）')
  assert.equal(store.user, null)
  assert.equal(store.nodeMode, null)
  assert.equal(store.intentionalLogout, true, '同步退出属主动登出，须抑制在途请求的会话失效弹窗')
  assert.equal(timers.size, 0, '同步退出必须停掉用户/配置重试定时器')
})

test('另一标签页 localStorage.clear()：key 为 null 同样按会话消失处理', () => {
  storage.set('token', 'tok-tab-a2')
  const store = newStore()
  assert.equal(store.token, 'tok-tab-a2')

  storage.clear()
  dispatchStorage(null)

  assert.equal(store.token, null)
  assert.equal(store.intentionalLogout, true)
})

test('另一标签页建立新会话：跟随令牌并重拉用户与节点模式（不沿用旧账号权限）', async () => {
  storage.set('token', 'tok-tab-b')
  const store = newStore()
  assert.equal(store.token, 'tok-tab-b')

  storage.set('token', 'tok-tab-c')
  dispatchStorage('token')

  assert.equal(store.token, 'tok-tab-c', '新令牌必须立即生效（旧令牌已被服务端吊销）')
  assert.equal(store.intentionalLogout, false)
  await flush()
  assert.equal(store.user?.username, 'alice', '新会话必须重拉用户信息')
  assert.equal(store.nodeMode, 'master', '新会话必须重拉节点模式')
})

test('首屏 init：/users/me 与 /config 并行发出（不叠成两次 30s 超时）', async () => {
  storage.set('token', 'tok-parallel')
  const store = newStore()
  const started: string[] = []
  const deferred = new Map<string, () => void>()
  const defaultGet = host.__authGet
  host.__authGet = (url: string) => {
    started.push(url)
    const { promise, resolve } = Promise.withResolvers<unknown>()
    deferred.set(url, () => resolve(url === '/users/me'
      ? { data: { id: 8, username: 'bob', role: 'admin', is_enabled: true, display_name: 'Bob', mfa_enabled: false, auth_provider: 'local' } }
      : { data: { is_master: true, timezone: 'Asia/Shanghai', cert_renewal_days: 30, mfa_write_guard: false } }))
    return promise
  }
  try {
    const pending = store.init()
    // 两个请求均未落地：串行实现此刻只会发出 /users/me（首屏最坏 30s×2 的来源）
    assert.deepEqual([...started].sort(), ['/config', '/users/me'], '首屏两个请求必须并行')
    for (const resolve of deferred.values()) resolve()
    await pending
    assert.equal(store.user?.username, 'bob')
    assert.equal(store.nodeMode, 'master')
  } finally {
    host.__authGet = defaultGet
  }
})

test('非令牌键的 storage 变更不触碰会话（多标签页导航互不干扰）', () => {
  storage.set('token', 'tok-tab-d')
  const store = newStore()

  storage.set('currentPage', 'rules')
  dispatchStorage('currentPage')

  assert.equal(store.token, 'tok-tab-d')
  assert.equal(store.user, null, '无关键不得触发重拉用户信息')
  assert.equal(store.intentionalLogout, false)
  assert.equal(timers.size, 0)
})
