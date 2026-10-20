// 轮询契约（usePollingTask 文件头承诺：「每轮独立 AbortController，pause/stop 可
// 取消真实请求」）——轮次 context.signal 与页级永久 signal 必须分离：pause 只中止
// 在途轮次，resume 后的新轮次拿未中止的 signal。另钉四处轮询页的接线：取数函数
// 必须接收本轮 signal（传永久 signal 会让 pause 取消不了真实请求，见 Dashboard/
// ClusterSettings/CertJobs/Rules 的原实现）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { usePollingTask } from '../src/composables/usePollingTask.ts'
import { source } from './_helpers.ts'

// onUnmounted 在无组件实例时会打印 Vue 警告——本文件只验证轮次契约，两个用例
// 各自在 finally 里恢复 console.warn。

test('每轮独立 signal：pause 中止在途轮次并作废序列，resume 后新轮次不继承取消', async () => {
  const warn = console.warn
  console.warn = () => {}
  try {
    const rounds: Array<{ signal: AbortSignal; isCurrent: () => boolean }> = []
    const releases: Array<() => void> = []
    const polling = usePollingTask((context) => new Promise<void>((resolve) => {
      rounds.push({ signal: context.signal, isCurrent: context.isCurrent })
      releases.push(resolve)
    }))

    const first = polling.run()
    assert.equal(rounds.length, 1, 'run() 立即启动一轮')
    assert.notEqual(rounds[0].signal, polling.signal, '轮次 signal 不得是页级永久 signal')
    assert.equal(rounds[0].isCurrent(), true)
    assert.equal(rounds[0].signal.aborted, false)

    polling.pause()
    assert.equal(rounds[0].signal.aborted, true, 'pause 必须中止在途轮次')
    assert.equal(polling.signal.aborted, false, 'pause 不得中止永久 signal（同页后续轮次继续用）')
    assert.equal(rounds[0].isCurrent(), false, '作废后迟到响应不得写回')

    releases[0]()
    await first

    const second = polling.run()
    assert.equal(rounds.length, 2, 'pause 之后 run() 起新一轮')
    assert.notEqual(rounds[1].signal, rounds[0].signal, '每轮新 controller')
    assert.equal(rounds[1].signal.aborted, false, '新一轮 signal 不继承上一轮的取消')
    releases[1]()
    await second

    polling.stop()
    assert.equal(polling.signal.aborted, true, 'stop 终止永久 signal')
    assert.equal(polling.isDisposed(), true)
  } finally {
    console.warn = warn
  }
})

test('stop 同时中止在途轮次，drain 不再起新轮', async () => {
  const warn = console.warn
  console.warn = () => {}
  try {
    const seen: AbortSignal[] = []
    const releases: Array<() => void> = []
    const polling = usePollingTask((context) => new Promise<void>((resolve) => {
      seen.push(context.signal)
      releases.push(resolve)
    }))

    const pending = polling.run()
    polling.stop()
    assert.equal(seen.length, 1)
    assert.equal(seen[0].aborted, true, 'stop 必须中止在途轮次')
    releases[0]()
    await pending
    await polling.run()
    assert.equal(seen.length, 1, 'disposed 后 run() 不得再起轮次')
  } finally {
    console.warn = warn
  }
})

test('轮询页接线：取数函数接收本轮 signal，永久 signal 只留给跨轮工作', () => {
  const dashboard = source('src/views/Dashboard.vue')
  assert.match(dashboard, /const dashboardPolling = usePollingTask\(async \(task\) => fetchAllData\(task\.signal\)/)
  assert.match(dashboard, /const fetchAllData = \(roundSignal\?: AbortSignal\)/)
  assert.match(dashboard, /const fetchRuleHealth = async \(currentRules: Rule\[\], version: number, roundSignal\?: AbortSignal\)/)
  assert.match(dashboard, /signal: roundSignal \?\? dashboardPolling\.signal/, '轮次取本轮 signal；Caddy 操作后的补偿刷新回落永久 signal')

  const cluster = source('src/views/settings/ClusterSettings.vue')
  assert.match(cluster, /await refreshCluster\(task\.signal\)/)
  assert.match(cluster, /const fetchStatus = async \(roundSignal\?: AbortSignal\)/)
  assert.match(cluster, /const fetchNodes = async \(roundSignal\?: AbortSignal\)/)

  const certJobs = source('src/views/settings/CertJobs.vue')
  assert.match(certJobs, /await fetchJobs\(task\.signal\)/)
  assert.match(certJobs, /const fetchJobs = async \(roundSignal\?: AbortSignal\)/)

  const rules = source('src/views/Rules.vue')
  assert.match(rules, /await fetchHealthStatus\(task\.signal\)/)
  assert.match(rules, /await fetchCertJobs\(task\.signal\)/)
  assert.match(rules, /const fetchHealthStatus = async \(roundSignal\?: AbortSignal\)/)
  assert.match(rules, /const fetchCertJobs = async \(roundSignal\?: AbortSignal\)/)
})
