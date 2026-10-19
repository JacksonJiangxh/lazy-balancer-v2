// 懒加载状态机验收（历史 历史问题）：并发单飞、失败可重试、成功永久命中。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import { createLazyLoader } from '../src/utils/lazyOnce.ts'
import { usePollingTask, type PollingTask } from '../src/composables/usePollingTask.ts'
import { createSessionSingleFlight } from '../src/utils/sessionSingleFlight.ts'

test('暂停轮询：中止在途任务信号、作废旧结果，恢复后用新信号（历史问题）', async () => {
  const gate = Promise.withResolvers<void>()
  const started = Promise.withResolvers<void>()
  const signals: AbortSignal[] = []
  let staleCurrent: boolean | null = null
  let calls = 0
  // A85WT-历史问题：usePollingTask 内部 onUnmounted 需要活跃组件实例——经 SSR 渲染
  // 提供真实实例上下文，不再以「无实例」状态触碰 Vue 生命周期（no-op 警告）。
  let polling!: PollingTask
  await renderToString(createSSRApp({
    setup() {
      polling = usePollingTask(async ({ signal, isCurrent }) => {
        calls++
        signals.push(signal)
        if (calls === 1) {
          started.resolve()
          await gate.promise
          staleCurrent = isCurrent()
        }
      })
      return () => h('div')
    },
  }))
  const firstRun = polling.run()
  await started.promise
  polling.pause()
  assert.equal(signals[0].aborted, true, 'pause 必须 abort 在途任务，而非只停定时器')
  polling.resume()
  gate.resolve()
  await firstRun
  assert.equal(staleCurrent, false, '暂停前任务不得再视为当前会话')
  assert.equal(calls, 2, 'resume 应立即补跑一轮')
  assert.notEqual(signals[1], signals[0])
  assert.equal(signals[1].aborted, false)
  polling.stop()
})

test('CRS 新对话框会话不会被旧单飞请求饿死（历史问题 行为）', async () => {
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

test('并发 ensure 只调用一次 loader（单飞）', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => {
    calls++
    const { promise, resolve } = Promise.withResolvers<void>()
    setTimeout(resolve, 5)
    await promise
    return { 中国: '中国' }
  })
  await Promise.all([loader.ensure(), loader.ensure(), loader.ensure()])
  assert.equal(calls, 1)
  assert.equal(loader.isLoaded(), true)
  assert.deepEqual(loader.get(), { 中国: '中国' })
})

test('成功后不再请求（会话级缓存）', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => { calls++; return 'ok' })
  await loader.ensure()
  await loader.ensure()
  assert.equal(calls, 1)
})

test('失败不闩死：下一次 ensure 重试并成功', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => {
    calls++
    if (calls === 1) throw new Error('network')
    return 'recovered'
  })
  await loader.ensure()
  assert.equal(loader.isLoaded(), false)
  assert.equal(loader.get(), null)
  await loader.ensure()
  assert.equal(calls, 2)
  assert.equal(loader.isLoaded(), true)
  assert.equal(loader.get(), 'recovered')
})

test('失败后并发重试同样单飞', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => {
    calls++
    if (calls === 1) throw new Error('first')
    const { promise, resolve } = Promise.withResolvers<void>()
    setTimeout(resolve, 5)
    await promise
    return 'v'
  })
  await loader.ensure()
  await Promise.all([loader.ensure(), loader.ensure()])
  assert.equal(calls, 2)
  assert.equal(loader.get(), 'v')
})

test('reset 丢弃值，下一次 ensure 重新加载', async () => {
  let calls = 0
  const loader = createLazyLoader(async () => { calls++; return calls })
  await loader.ensure()
  loader.reset()
  assert.equal(loader.isLoaded(), false)
  assert.equal(loader.get(), null)
  await loader.ensure()
  assert.equal(calls, 2)
})
