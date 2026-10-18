// 懒加载状态机验收（历史 历史问题）：并发单飞、失败可重试、成功永久命中。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

import { createLazyLoader } from '../src/utils/lazyOnce.ts'
import { usePollingTask } from '../src/composables/usePollingTask.ts'

test('暂停轮询：中止在途任务信号、作废旧结果，恢复后用新信号（历史问题）', async () => {
  const gate = Promise.withResolvers<void>()
  const started = Promise.withResolvers<void>()
  const signals: AbortSignal[] = []
  let staleCurrent: boolean | null = null
  let calls = 0
  const polling = usePollingTask(async ({ signal, isCurrent }) => {
    calls++
    signals.push(signal)
    if (calls === 1) {
      started.resolve()
      await gate.promise
      staleCurrent = isCurrent()
    }
  })
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

test('CRS 新对话框会话不会被旧单飞请求饿死（历史问题 源码契约）', () => {
  const src = readFileSync(new URL('../src/composables/useCrsRuleIndex.ts', import.meta.url), 'utf8')
  assert.match(src, /requestedSeq = openSeq\s+if \(inflight\)/, '新会话必须先登记，再复用旧请求')
  assert.match(src, /inflight\.then\(/, '旧请求若已失效，必须链式补取新会话')
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
