// 会话级单飞加载（createSessionSingleFlight）验收：新旧会话不互相饿死（旧在途
// 请求失效后补取新会话）、同会话并发只发一次、失败可重试且加载态必收尾。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createSessionSingleFlight } from '../src/utils/sessionSingleFlight.ts'

test('CRS 新对话框会话不会被旧单飞请求饿死', async () => {
  // 场景：会话 1 的请求在途 → 会话 2 打开（旧请求失效）→ 旧请求后到。
  // 期望：旧结果丢弃、会话 2 追加一次请求并落地；（原子实现会让会话 2 空等且永不 loaded）
  const loads: number[] = []
  const applied: Array<{ session: number; value: string }> = []
  const first = Promise.withResolvers<string>()
  const second = Promise.withResolvers<string>()
  const loader = createSessionSingleFlight<string>({
    load: (session) => {
      loads.push(session)
      return session === 1 ? first.promise : second.promise
    },
    apply: (value, session) => { applied.push({ session, value }) },
  })
  const p1 = loader.ensure(1)
  const p2 = loader.ensure(2)
  assert.deepEqual(loads, [1], '会话 2 打开时复用旧在途请求，不并发双发')
  first.resolve('stale')
  await p1
  // 旧请求 settled 后链式补取会话 2
  assert.deepEqual(loads, [1, 2], '旧请求失效后必须补取新会话')
  second.resolve('fresh')
  await Promise.all([p1, p2])
  assert.deepEqual(applied, [{ session: 2, value: 'fresh' }], '旧会话返回必须丢弃')
  assert.equal(loader.loadedSession(), 2)
})

test('同会话并发 ensure 只发一次请求（单飞）', async () => {
  let calls = 0
  const gate = Promise.withResolvers<string>()
  const loader = createSessionSingleFlight<string>({
    load: () => { calls++; return gate.promise },
    apply: () => {},
  })
  const p = Promise.all([loader.ensure(7), loader.ensure(7), loader.ensure(7)])
  assert.equal(calls, 1)
  gate.resolve('ok')
  await p
  assert.equal(calls, 1)
  await loader.ensure(7)
  assert.equal(calls, 1, '已加载会话直接命中缓存')
})

test('失败不闩死：同会话再次 ensure 重试', async () => {
  let calls = 0
  const applied: string[] = []
  const loader = createSessionSingleFlight<string>({
    load: async () => {
      calls++
      if (calls === 1) throw new Error('network')
      return 'recovered'
    },
    apply: (value) => { applied.push(value) },
  })
  await loader.ensure(3)
  assert.equal(loader.loadedSession(), null)
  await loader.ensure(3)
  assert.equal(calls, 2)
  assert.deepEqual(applied, ['recovered'])
  assert.equal(loader.loadedSession(), 3)
})

test('旧会话失败不消耗新会话的加载态', async () => {
  const first = Promise.withResolvers<string>()
  const second = Promise.withResolvers<string>()
  const loadingStates: boolean[] = []
  const applied: string[] = []
  const loader = createSessionSingleFlight<string>({
    load: (session) => (session === 1 ? first.promise : second.promise),
    apply: (value) => { applied.push(value) },
    onLoadingChange: (value) => { loadingStates.push(value) },
  })
  const p1 = loader.ensure(1)
  const p2 = loader.ensure(2)
  first.reject(new Error('stale failure'))
  await Promise.resolve()
  second.resolve('fresh')
  await Promise.all([p1, p2])
  assert.deepEqual(applied, ['fresh'])
  assert.equal(loadingStates.at(-1), false, '最终必须收尾为未加载态')
})


// sessionSingleFlight 的 onError/requestedSession/isInflight ----

test('sessionSingleFlight：失败走 onError（带会话）且不落 loadedSession，在途状态可观测', async () => {
  const gate = Promise.withResolvers<string>()
  const errors: Array<{ error: unknown; session: number }> = []
  const loader = createSessionSingleFlight<string>({
    load: () => gate.promise,
    apply: () => {},
    onError: (error, session) => { errors.push({ error, session }) },
  })
  assert.equal(loader.requestedSession(), null)
  assert.equal(loader.isInflight(), false)
  const pending = loader.ensure(5)
  assert.equal(loader.requestedSession(), 5, '请求发起即登记最新会话')
  assert.equal(loader.isInflight(), true, '在途状态供调用方展示加载中')
  const boom = new Error('boom')
  gate.reject(boom)
  await pending
  assert.deepEqual(errors, [{ error: boom, session: 5 }])
  assert.equal(loader.isInflight(), false)
  assert.equal(loader.loadedSession(), null, '失败不得落 loadedSession（同会话可重试）')
  assert.equal(loader.requestedSession(), 5)
})
