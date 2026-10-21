// 懒加载状态机验收（历史问题）：并发单飞、失败可重试、成功永久命中。
//
// 运行：cd web && npm test

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'
import { createSSRApp, h } from 'vue'
import { renderToString } from 'vue/server-renderer'

import { createLazyLoader } from '../src/utils/lazyOnce.ts'
import { usePollingTask, type PollingTask } from '../src/composables/usePollingTask.ts'
import { createSessionSingleFlight } from '../src/utils/sessionSingleFlight.ts'

/** 最小 document 宿主：只提供 usePollingTask 消费的 hidden + visibilitychange 监听。 */
class FakeDocument {
  hidden = false
  private readonly listeners = new Set<() => void>()
  addEventListener(_type: string, listener: () => void): void { this.listeners.add(listener) }
  removeEventListener(_type: string, listener: () => void): void { this.listeners.delete(listener) }
  get listenerCount(): number { return this.listeners.size }
  dispatch(): void { for (const l of [...this.listeners]) l() }
}

test('暂停轮询：中止在途任务信号、作废旧结果，恢复后用新信号（历史问题）', async () => {
  const gate = Promise.withResolvers<void>()
  const started = Promise.withResolvers<void>()
  const signals: AbortSignal[] = []
  let staleCurrent: boolean | null = null
  let calls = 0
  // 历史修复：usePollingTask 内部 onUnmounted 需要活跃组件实例——经 SSR 渲染
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

// ---- 历史修复④：usePollingTask 的 stop/invalidate/可见性/timer + 历史修复 覆盖 ----

test('usePollingTask.stop 释放：abort 在途、永久终止后续轮次', async () => {
  const gate = Promise.withResolvers<void>()
  let calls = 0
  const seen: { signal?: AbortSignal } = {}
  let polling!: PollingTask
  await renderToString(createSSRApp({
    setup() {
      polling = usePollingTask(async ({ signal }) => {
        calls++
        seen.signal = signal
        await gate.promise
      })
      return () => h('div')
    },
  }))
  const running = polling.run()
  assert.equal(calls, 1, 'run 必须立即执行任务')
  polling.stop()
  assert.equal(polling.isDisposed(), true)
  assert.equal(seen.signal?.aborted, true, 'stop 必须 abort 每轮任务信号')
  gate.resolve()
  await running
  await polling.run()
  assert.equal(calls, 1, 'stop 后 run 不得再执行任务')
})

test('usePollingTask：onError 自身抛错被就地吞掉，不中断后续轮次（FI-14）', async () => {
  const logged: unknown[][] = []
  const originalError = console.error
  console.error = (...args: unknown[]) => { logged.push(args) }
  try {
    let calls = 0
    let polling!: PollingTask
    await renderToString(createSSRApp({
      setup() {
        polling = usePollingTask(
          async () => { calls++; throw new Error('task failed') },
          { onError: () => { throw new Error('callback failed') } },
        )
        return () => h('div')
      },
    }))
    // 回调异常若经 drain→run 的 Promise 拒绝逃逸，这里的 await 会抛错（unhandled rejection 形态）
    await polling.run()
    assert.equal(calls, 1)
    assert.equal(logged.length, 1, 'onError 回调异常必须就地 console.error')
    await polling.run()
    assert.equal(calls, 2, '回调异常不得中断 drain，下一轮照常执行')
    polling.stop()
  } finally {
    console.error = originalError
  }
})

// invalidate 是 usePollingTask 的内部实现（未暴露在 PollingTask 接口上），其可观测
// 契约由 pause()/stop() 用例覆盖（作废序列 + abort 每轮任务信号 + isCurrent 失效）。

test('usePollingTask：document.hidden 停摆定时轮询，恢复可见立即补跑', async () => {
  const doc = new FakeDocument()
  const host = globalThis as { document?: unknown }
  host.document = doc
  let calls = 0
  let polling!: PollingTask
  const flush = (): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, 0))
  mock.timers.enable({ apis: ['setInterval'] })
  try {
    await renderToString(createSSRApp({
      setup() {
        polling = usePollingTask(async () => { calls++ }, { interval: 50 })
        return () => h('div')
      },
    }))
    polling.start()
    await flush()
    assert.equal(calls, 0, '定时轮询不立即首跑')
    mock.timers.tick(50)
    await flush()
    assert.equal(calls, 1, '可见时按 interval 轮询')
    doc.hidden = true
    doc.dispatch()
    mock.timers.tick(150)
    await flush()
    assert.equal(calls, 1, 'hidden 后定时轮次必须停摆')
    doc.hidden = false
    doc.dispatch()
    await flush()
    assert.equal(calls, 2, '恢复可见立即补跑一轮')
    mock.timers.tick(50)
    await flush()
    assert.equal(calls, 3, '定时器随可见性恢复')
    assert.equal(polling.isDisposed(), false)
    polling.stop()
    assert.equal(doc.listenerCount, 0, 'stop 必须摘除 visibilitychange 监听')
  } finally {
    polling?.stop()
    mock.timers.reset()
    delete host.document
  }
})

// ---- 历史修复④：sessionSingleFlight 的 onError/requestedSession/isInflight ----

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
