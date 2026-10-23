// 威胁大屏计数滚动（useCountUp）可见性行为：后台标签页 rAF 被浏览器节流/冻结，
// 继续排帧只会在不可见时积压——隐藏即停帧、隐藏期源值变化直接落值、恢复可见
// 直接落到源值（无积压补间）。用假 document + 假 rAF 驱动真实实现。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { nextTick, ref } from 'vue'

import { useCountUp } from '../src/composables/useCountUp.ts'
import { FakeDocument, mountForLifecycle, source } from './_helpers.ts'

class FakeFrames {
  private nextId = 1
  private readonly callbacks = new Map<number, FrameRequestCallback>()
  readonly request = (callback: FrameRequestCallback): number => {
    const id = this.nextId++
    this.callbacks.set(id, callback)
    return id
  }
  readonly cancel = (id: number): void => { this.callbacks.delete(id) }
  get size(): number { return this.callbacks.size }
  /** 推进一帧（清空当前排程后逐个执行，与浏览器「每帧取一次队列」同构） */
  step(now: number): void {
    const due = [...this.callbacks.values()]
    this.callbacks.clear()
    for (const callback of due) callback(now)
  }
}

interface Harness {
  doc: FakeDocument
  frames: FakeFrames
  dispose: () => void
}

const makeHarness = (): Harness => {
  const doc = new FakeDocument()
  const frames = new FakeFrames()
  const g = globalThis as unknown as {
    document?: unknown
    requestAnimationFrame?: unknown
    cancelAnimationFrame?: unknown
    warn: typeof console.warn
  }
  const previous = {
    document: g.document,
    raf: g.requestAnimationFrame,
    caf: g.cancelAnimationFrame,
  }
  g.document = doc
  g.requestAnimationFrame = frames.request
  g.cancelAnimationFrame = frames.cancel
  // onUnmounted 无组件实例会打印 Vue 警告——本文件只验证可见性行为，静音
  const warn = console.warn
  console.warn = () => {}
  return {
    doc,
    frames,
    dispose: () => {
      console.warn = warn
      g.document = previous.document
      g.requestAnimationFrame = previous.raf
      g.cancelAnimationFrame = previous.caf
    },
  }
}

test('可见时按帧补间到源值', async () => {
  const h = makeHarness()
  try {
    const source = ref(0)
    const display = useCountUp(source, 400)
    assert.equal(display.value, 0)

    source.value = 100
    await nextTick()
    assert.equal(h.frames.size, 1, '源值变化排一帧')

    h.frames.step(performance.now() + 400)
    assert.equal(display.value, 100, '补间终点=源值')
    assert.equal(h.frames.size, 0, '到达后不再排帧')
  } finally {
    h.dispose()
  }
})

test('页签隐藏即停帧，隐藏期源值直接落值，恢复可见落到源值', async () => {
  const h = makeHarness()
  try {
    const source = ref(0)
    const display = useCountUp(source, 1000)
    const startAt = performance.now()

    source.value = 1000
    await nextTick()
    h.frames.step(startAt + 200)
    assert.ok(display.value > 0 && display.value < 1000, '飞行中呈现中间值')
    assert.equal(h.frames.size, 1, '未到终点仍排着下一帧')

    h.doc.hidden = true
    h.doc.dispatch()
    assert.equal(h.frames.size, 0, '隐藏立即停帧（不积压后台帧）')

    source.value = 2000
    await nextTick()
    assert.equal(display.value, 2000, '隐藏期源值变化直接落值，不排帧')
    assert.equal(h.frames.size, 0)

    h.doc.hidden = false
    h.doc.dispatch()
    assert.equal(display.value, 2000, '恢复可见落到源值')
    assert.equal(h.frames.size, 0, '恢复可见不重新补间')
  } finally {
    h.dispose()
  }
})

test('飞行中恢复可见直接落到源值（无积压补间）', async () => {
  const h = makeHarness()
  try {
    const source = ref(0)
    const display = useCountUp(source, 1000)
    assert.equal(h.doc.listenerCount, 1, '挂一个 visibilitychange 监听')

    source.value = 800
    await nextTick()
    h.doc.dispatch()
    assert.equal(display.value, 800, '可见事件把显示值对到源值')
    assert.equal(h.frames.size, 0, '对值后不得残留补间帧')
  } finally {
    h.dispose()
  }
})

// 卸载清理（页面切换/大屏退出）：onUnmounted 里摘监听 + 停帧。组件实例由
// mountForLifecycle 提供（SSR 不执行卸载钩子，覆盖不到该路径）。
test('卸载时摘除可见性监听并取消在途补间帧', async () => {
  const h = makeHarness()
  try {
    const source = ref(0)
    const mounted = mountForLifecycle(() => {
      useCountUp(source, 1000)
    })
    assert.equal(h.doc.listenerCount, 1, '挂载后应有一个 visibilitychange 监听')

    source.value = 500
    await nextTick()
    assert.equal(h.frames.size, 1, '前置：补间帧在途')

    mounted.unmount()
    assert.equal(h.doc.listenerCount, 0, '卸载必须摘除 visibilitychange 监听（否则重进页面叠加监听→多倍补间）')
    assert.equal(h.frames.size, 0, '卸载必须取消在途帧（否则销毁后仍继续排帧）')
  } finally {
    h.dispose()
  }
})

// 消费侧接线钉：大屏四个 KPI 必须经 useCountUp 滚动（绕过时表现为数字不再
// 补间，纯函数用例不会红）。
test('ThreatScreen 接线：四个 KPI 均经 useCountUp', () => {
  const screen = source('src/views/security/ThreatScreen.vue')
  const calls = screen.match(/useCountUp\(/g) ?? []
  assert.equal(calls.length, 4, `ThreatScreen 的 useCountUp 调用点应为 4 处，实际 ${calls.length}`)
  assert.match(screen, /import \{ useCountUp \} from '@\/composables\/useCountUp'/)
})
