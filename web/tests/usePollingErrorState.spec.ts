// 轮询错误退避/横幅状态行为验收（Rules/CertJobs/ClusterSettings/TaskMonitor
// 四页共用）：仅 TypeError（契约违约）指数退避 30s→300s 封顶、错误文案 30s 节流、
// canRun/resetBackoff 门。此前只有一条源码文本钉，退避语义回归无行为拦截。
//
// 时间源用 mock.timers 控制 Date.now()——真实等待会让用例分钟级。
//
// 运行：cd web && npm test

import { test, mock } from 'node:test'
import assert from 'node:assert/strict'

import { usePollingErrorState } from '../src/composables/usePollingErrorState.ts'

const BASE = Date.parse('2026-10-22T00:00:00Z')

/** 每个用例独立的时间基准：mock Date 后不允许跨用例残留。 */
const withClock = (run: (now: { value: number }) => void): void => {
  mock.timers.enable({ apis: ['Date'], now: BASE })
  try {
    run({ value: BASE })
  } finally {
    mock.timers.reset()
  }
}

test('非 TypeError 不阻塞：canRun 恒 true、retryAt 清空', () => {
  withClock(() => {
    const state = usePollingErrorState()
    state.recordError(new Error('网络抖动'))
    assert.equal(state.canRun(), true)
    assert.equal(state.retryAt.value, '')
    assert.equal(state.errorMessage.value, '网络抖动')
  })
})

test('TypeError 指数退避 30s → 60s → … → 300s 封顶', () => {
  withClock((now) => {
    const state = usePollingErrorState()
    const expected = [30_000, 60_000, 120_000, 240_000, 300_000, 300_000]
    for (const [i, delay] of expected.entries()) {
      now.value = BASE + i * 1_000_000
      mock.timers.setTime(now.value)
      state.recordError(new TypeError('响应缺少 data 字段'))
      assert.equal(state.retryAt.value, new Date(now.value + delay).toISOString(), `第 ${i + 1} 次退避应为 ${delay}ms`)
      assert.equal(state.canRun(), false, `退避期间 canRun 必须 false（第 ${i + 1} 次）`)
      mock.timers.setTime(now.value + delay - 1)
      assert.equal(state.canRun(), false, 'retryAt 前 1ms 仍不可运行')
      mock.timers.setTime(now.value + delay)
      assert.equal(state.canRun(), true, 'retryAt 时刻起可运行')
    }
  })
})

test('非 TypeError 清零退避（契约违约与普通故障不叠加）', () => {
  withClock((now) => {
    const state = usePollingErrorState()
    state.recordError(new TypeError('契约违约'))
    assert.equal(state.canRun(), false)
    state.recordError(new Error('普通故障'))
    assert.equal(state.canRun(), true, '普通故障必须立即清零退避')
    assert.equal(state.retryAt.value, '')
    // 再违约从 30s 重新起算（计数已清零）
    now.value += 1_000
    mock.timers.setTime(now.value)
    state.recordError(new TypeError('再次违约'))
    assert.equal(state.retryAt.value, new Date(now.value + 30_000).toISOString())
  })
})

test('resetBackoff 立即放行且退避计数清零', () => {
  withClock((now) => {
    const state = usePollingErrorState()
    state.recordError(new TypeError('契约违约'))
    state.recordError(new TypeError('契约违约'))
    state.resetBackoff()
    assert.equal(state.canRun(), true)
    assert.equal(state.retryAt.value, '')
    now.value += 1_000
    mock.timers.setTime(now.value)
    state.recordError(new TypeError('重置后再违约'))
    assert.equal(state.retryAt.value, new Date(now.value + 30_000).toISOString(), '重置后退避重新从 30s 起算')
  })
})

test('错误文案 30s 节流：同文案窗内不刷新 lastErrorAt，换文案立即刷新', () => {
  withClock((now) => {
    const state = usePollingErrorState()
    state.recordError(new Error('甲'))
    const first = state.lastErrorAt.value
    assert.equal(first, new Date(now.value).toISOString())

    now.value += 10_000
    mock.timers.setTime(now.value)
    state.recordError(new Error('甲'))
    assert.equal(state.lastErrorAt.value, first, '同文案 30s 内不得刷新横幅时间')

    state.recordError(new Error('乙'))
    assert.equal(state.lastErrorAt.value, new Date(now.value).toISOString(), '换文案立即刷新')

    now.value += 30_000
    mock.timers.setTime(now.value)
    state.recordError(new Error('乙'))
    assert.equal(state.lastErrorAt.value, new Date(now.value).toISOString(), '超 30s 同文案也刷新')
  })
})

test('未知错误对象使用中文兜底文案', () => {
  withClock(() => {
    const state = usePollingErrorState()
    state.recordError('boom')
    assert.equal(state.errorMessage.value, '未知错误')
  })
})

test('clear 复位全部状态（含退避与节流窗）', () => {
  withClock((now) => {
    const state = usePollingErrorState()
    state.recordError(new TypeError('契约违约'))
    state.clear()
    assert.equal(state.errorMessage.value, null)
    assert.equal(state.lastErrorAt.value, '')
    assert.equal(state.retryAt.value, '')
    assert.equal(state.canRun(), true)
    now.value += 1_000
    mock.timers.setTime(now.value)
    state.recordError(new TypeError('清空后再违约'))
    assert.equal(state.retryAt.value, new Date(now.value + 30_000).toISOString(), 'clear 后计数从零起算')
  })
})
