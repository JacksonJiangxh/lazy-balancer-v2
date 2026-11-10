// 省界表按需加载的状态机：首次请求缓存 in-flight、成功落缓存、失败降级为 null
// 且不缓存失败（下次下钻可重试）。模块级 state 在两条用例间共享，因此每条用例
// 都自带前置（失败用例先断言未加载；缓存命中用例自行 seed 并以 import 次数基线
// 判定）——单用例过滤/重排不产生假红或假绿。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'
import { dataModule } from './_stubs.ts'

const failStub = dataModule("throw new Error('省界数据加载失败')")
const okStub = dataModule("export const ADMIN1_PROVINCES = { 测试省: [{ name: '测试市' }] }")

let resolutions = 0
let nextStub = failStub
// 静态 import 会先于钩子注册执行，故被测模块只能动态 import（钩子必须先装）。
// 省界表是 ~1.9MB 静态段，用替身模块表达「首次失败、重试成功」。
registerModuleHooks({
  '@/utils/admin1Provinces': () => {
    resolutions += 1
    const url = nextStub
    nextStub = okStub
    return url
  },
})
const { loadAdmin1Tables, loadedAdmin1Tables } = await import('../src/utils/admin1Loader.ts')

test('加载失败降级为 null 且不缓存：并发重试共享同一 in-flight，成功后落缓存', async () => {
  assert.equal(loadedAdmin1Tables(), null, '未加载时同步读取必须是 null')
  const warnings: unknown[] = []
  const realWarn = console.warn
  console.warn = (...args: unknown[]) => {
    warnings.push(args[0])
  }
  try {
    assert.equal(await loadAdmin1Tables(), null, '失败必须降级为 null（调用方按无省层处理）')
  } finally {
    console.warn = realWarn
  }
  assert.deepEqual(warnings, ['load admin1 provinces failed'], '失败要留一条诊断，但不能抛出到调用方')
  assert.equal(loadedAdmin1Tables(), null, '失败不得写入缓存')
  assert.equal(resolutions, 1)

  const [first, second] = await Promise.all([loadAdmin1Tables(), loadAdmin1Tables()])
  assert.deepEqual(first, { 测试省: [{ name: '测试市' }] })
  assert.equal(first, second, '并发调用必须拿到同一个 in-flight 结果')
  assert.equal(resolutions, 2, '两个并发调用只允许触发一次 import')
  assert.equal(loadedAdmin1Tables(), first, '成功后同步读取立即可见')
})

test('已加载后既有缓存命中不再 import', async () => {
  // 自带 seed：本用例不消费前一条用例留下的缓存——`--test-only`/单用例过滤
  // 或文件内重排下同样成立（否则先跑此条即假红）。替身模块按「首次失败、
  // 重试成功」建模，故 seed 允许两次尝试（失败不缓存本身就是本文件的契约）。
  let loaded = loadedAdmin1Tables() ?? await loadAdmin1Tables()
  if (!loaded) loaded = await loadAdmin1Tables()
  assert.ok(loaded, '缓存命中前必须能读到已加载表（未加载时先 seed）')
  const resolutionsBefore = resolutions
  assert.equal(await loadAdmin1Tables(), loaded)
  assert.equal(resolutions, resolutionsBefore, '缓存命中不得重新 import（首屏零下载的承诺）')
})
