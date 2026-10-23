// LogStorageBar 的数据层（useLogStorageStats）行为验收：
// - logKey / caddyId 变化 = 换了一行日志：必须先清空旧统计再取数。后端只返回
//   所看那一行的统计，旧值不会被覆盖——原实现只在 refreshKey 时重取，换行全靠
//   调用方重挂组件，漏挂即渲染上一行的名称/字节/百分比（隐式契约、无声错行）。
// - refreshKey 变化 = 同一行重取（保留/清理改变占用）：保留旧值，避免闪烁。
// - 换行后上一行的迟到响应不得写回（取数序号）。
//
// api.ts 用 data: 模块替身记录请求；被测组合子动态 import（钩子须先注册）。

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { nextTick, ref } from 'vue'

import { registerModuleHooks } from './_helpers.ts'
import { STUB_API } from './_stubs.ts'

interface GetRecord {
  url: string
  config?: unknown
}

type Harness = {
  __gets: GetRecord[]
  __get: (url: string, config?: unknown) => Promise<unknown>
}
const g = globalThis as unknown as Harness
g.__gets = []
g.__get = async () => ({ data: { logs: [] } })

registerModuleHooks({ '@/utils/api': STUB_API })
const { useLogStorageStats } = await import('../src/composables/useLogStorageStats.ts')

const flush = (): Promise<void> => new Promise<void>((resolve) => setTimeout(resolve, 0))

const deferred = (): { promise: Promise<unknown>; resolve: (value: unknown) => void } => {
  let resolve!: (value: unknown) => void
  const promise = new Promise<unknown>((r) => { resolve = r })
  return { promise, resolve }
}

const statsOf = (key: string, name: string): unknown => ({ data: { logs: [{ key, name }] } })

test('换行（logKey 变化）：先清空旧行统计，再取新行数据', async () => {
  const target = ref({ logKey: 'runtime', caddyId: 'main' })
  const pending = deferred()
  const requests: GetRecord[] = []
  g.__gets = requests
  let call = 0
  g.__get = async () => {
    call += 1
    if (call === 1) return statsOf('runtime', '运行日志')
    return pending.promise
  }
  const { info } = useLogStorageStats({ target: () => target.value, refreshKey: () => 0 })
  await flush()
  assert.equal(info.value?.name, '运行日志', '挂载即取当前行（refreshKey 初始触发）')
  assert.deepEqual(requests[0].config, { params: { key: 'runtime', caddy_id: 'main' } })

  target.value = { logKey: 'audit', caddyId: 'main' }
  await nextTick()
  const clearedOnKeyChange: unknown = info.value
  assert.equal(clearedOnKeyChange, null, '换行后必须立即清空——不得继续渲染上一行的统计')
  assert.equal(requests.length, 2, '换行必须重新取数（不依赖调用方重挂）')
  assert.deepEqual(requests[1].config, { params: { key: 'audit', caddy_id: 'main' } })

  pending.resolve(statsOf('audit', '操作日志'))
  await flush()
  assert.equal(info.value?.name, '操作日志')
})

test('caddyId 变化同样视为换行：清空并按新站点收窄取数', async () => {
  const target = ref<{ logKey: string; caddyId?: string }>({ logKey: 'caddy', caddyId: 'main' })
  const pending = deferred()
  const requests: GetRecord[] = []
  g.__gets = requests
  let call = 0
  g.__get = async () => {
    call += 1
    return call === 1 ? statsOf('caddy', 'Caddy 日志') : pending.promise
  }
  const { info } = useLogStorageStats({ target: () => target.value })
  await flush()
  assert.deepEqual(requests[0].config, { params: { key: 'caddy', caddy_id: 'main' } })

  target.value = { logKey: 'caddy', caddyId: 'slave-1' }
  await nextTick()
  const clearedOnSiteChange: unknown = info.value
  assert.equal(clearedOnSiteChange, null, '换站点必须先清空旧站点统计')
  assert.equal(requests.length, 2)
  assert.deepEqual(requests[1].config, { params: { key: 'caddy', caddy_id: 'slave-1' } })

  pending.resolve(statsOf('caddy', 'Caddy 日志（slave-1）'))
  await flush()
  assert.equal(info.value?.name, 'Caddy 日志（slave-1）')
})

test('refreshKey 变化：同一行重取且保留旧值（不闪烁）', async () => {
  const target = ref({ logKey: 'audit' })
  const refreshKey = ref(0)
  const pending = deferred()
  g.__gets = []
  let call = 0
  g.__get = async () => {
    call += 1
    return call === 1 ? statsOf('audit', '操作日志') : pending.promise
  }
  const { info } = useLogStorageStats({ target: () => target.value, refreshKey: () => refreshKey.value })
  await flush()
  assert.equal(info.value?.name, '操作日志')

  refreshKey.value += 1
  await nextTick()
  assert.equal(info.value?.name, '操作日志', '同一行重取期间保留旧值')
  assert.equal(g.__gets.length, 2)
  assert.deepEqual(g.__gets[1].config, { params: { key: 'audit' } }, '重取口径与首次相同')

  pending.resolve(statsOf('audit', '操作日志（新）'))
  await flush()
  assert.equal(info.value?.name, '操作日志（新）')
})

test('迟到响应不写回：换行后上一行的慢响应被丢弃', async () => {
  const target = ref({ logKey: 'runtime' })
  const slow = deferred()
  g.__gets = []
  let call = 0
  g.__get = async () => {
    call += 1
    return call === 1 ? slow.promise : statsOf('audit', '操作日志')
  }
  const { info } = useLogStorageStats({ target: () => target.value })
  await flush()
  const beforeFirstResponse: unknown = info.value
  assert.equal(beforeFirstResponse, null, '首轮未返回前无统计')

  target.value = { logKey: 'audit' }
  await flush()
  assert.equal(info.value?.name, '操作日志')

  slow.resolve(statsOf('runtime', '运行日志'))
  await flush()
  assert.equal(info.value?.name, '操作日志', '旧行迟到响应不得覆盖当前行')
})
