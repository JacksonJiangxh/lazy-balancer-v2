// 问题 行为测试：页面隐藏时间隔任务（时钟/弧光冲刷/采集租约心跳）必须
// 停摆，恢复可见时立即补 tick 并重启——纯行为断言（假 document/window 驱动
// 真实生产代码 createVisibilityIntervals），非源码文本钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createVisibilityIntervals, type VisibilityIntervals } from '../src/composables/useVisibilityIntervals.ts'
import { FakeDocument, FakeWindow } from './_helpers.ts'

interface Harness {
  doc: FakeDocument
  win: FakeWindow
  counts: Record<'clock' | 'arc' | 'collector', number>
  hiddenCalls: number
  visibleCalls: number
  loop: VisibilityIntervals
}

const makeHarness = (options?: { hidden?: boolean }): Harness => {
  const doc = new FakeDocument()
  doc.hidden = options?.hidden ?? false
  const win = new FakeWindow()
  const counts = { clock: 0, arc: 0, collector: 0 }
  const state = { hiddenCalls: 0, visibleCalls: 0 }
  const loop = createVisibilityIntervals({
    intervals: [
      { tick: () => { counts.clock += 1 }, ms: 1000, immediate: true },
      { tick: () => { counts.arc += 1 }, ms: 500 },
      { tick: () => { counts.collector += 1 }, ms: 10000, immediate: true },
    ],
    onHidden: () => { state.hiddenCalls += 1 },
    onVisible: () => { state.visibleCalls += 1 },
    doc,
    win,
  })
  return { doc, win, counts, get hiddenCalls() { return state.hiddenCalls }, get visibleCalls() { return state.visibleCalls }, loop }
}

test('start 立即补 immediate tick 并挂起全部间隔', () => {
  const h = makeHarness()
  h.loop.start()
  assert.equal(h.counts.clock, 1, '时钟首刷立即执行')
  assert.equal(h.counts.collector, 1, '采集租约立即获取')
  assert.equal(h.counts.arc, 0, '弧光冲刷无 immediate')
  assert.equal(h.win.size, 3, '三个间隔全部在跑')
  h.win.fire()
  assert.deepEqual(h.counts, { clock: 2, arc: 1, collector: 2 })
  h.loop.stop()
})

test('hidden 停止全部间隔并回调 onHidden（释放租约）', () => {
  const h = makeHarness()
  h.loop.start()
  h.doc.hidden = true
  h.doc.dispatch()
  assert.equal(h.win.size, 0, 'hidden 后不允许任何间隔继续跑')
  assert.equal(h.hiddenCalls, 1)
  const snapshot = { ...h.counts }
  h.win.fire()
  assert.deepEqual(h.counts, snapshot, 'hidden 后 tick 不得再发生')
  h.loop.stop()
})

test('visible 恢复间隔、立即补 tick 并回调 onVisible', () => {
  const h = makeHarness()
  h.loop.start()
  h.doc.hidden = true
  h.doc.dispatch()
  h.doc.hidden = false
  h.doc.dispatch()
  assert.equal(h.visibleCalls, 1)
  assert.equal(h.counts.clock, 2, '恢复可见立即补一次时钟')
  assert.equal(h.counts.collector, 2, '恢复可见立即重新获取租约')
  assert.equal(h.win.size, 3)
  h.win.fire()
  assert.deepEqual(h.counts, { clock: 3, arc: 1, collector: 3 })
  h.loop.stop()
})

test('重复 hidden/visible 不产生叠加间隔', () => {
  const h = makeHarness()
  h.loop.start()
  h.doc.hidden = true
  h.doc.dispatch()
  h.doc.dispatch()
  assert.equal(h.win.size, 0)
  h.doc.hidden = false
  h.doc.dispatch()
  h.doc.dispatch()
  assert.equal(h.win.size, 3, '重复 visible 不得叠加第二组间隔')
  h.loop.stop()
})

test('stop 摘除监听并清空间隔，幂等', () => {
  const h = makeHarness()
  h.loop.start()
  h.loop.stop()
  assert.equal(h.doc.listenerCount, 0, 'stop 后不得残留 visibilitychange 监听')
  assert.equal(h.win.size, 0)
  h.doc.hidden = true
  h.doc.dispatch()
  assert.equal(h.hiddenCalls, 0, 'stop 后事件不得再触达回调')
  h.loop.stop()
  assert.equal(h.win.size, 0, '幂等 stop 后仍无间隔')
})

test('挂载即 hidden 不起间隔不取租约，恢复可见后正常启动', () => {
  const h = makeHarness({ hidden: true })
  h.loop.start()
  assert.equal(h.win.size, 0, 'hidden 挂载不得启动任何间隔')
  assert.equal(h.counts.collector, 0, 'hidden 挂载不得获取采集租约')
  assert.equal(h.hiddenCalls, 1, 'hidden 挂载按 hidden 语义处理（暂停渲染/释放租约）')
  h.doc.hidden = false
  h.doc.dispatch()
  assert.equal(h.win.size, 3)
  assert.equal(h.counts.collector, 1)
  h.loop.stop()
})
