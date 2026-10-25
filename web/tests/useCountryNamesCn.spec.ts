// 国家中文名展示层单源：映射由后端 country_names_cn 下发（前端零复制表），
// 未命中/旧后端/请求失败一律回退英文原名；失败不得把整会话闩死（下一次调用
// 自然重试）。countryLabel 是三个消费方锁步的回退契约。
//
// 动态 import：api 替身须先于模块求值注册。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks, code, drainMicrotasks, waitForMicrotasks } from './_helpers.ts'
import { STUB_API } from './_stubs.ts'

interface GetCall {
  url: string
  config: unknown
}
type Harness = {
  __gets: GetCall[]
  __get: (url: string, config?: unknown) => Promise<unknown>
}
const g = globalThis as unknown as Harness
g.__gets = []

registerModuleHooks({ '@/utils/api': STUB_API })
const { useCountryNamesCn, countryLabel } = await import('../src/composables/useCountryNamesCn.ts')
test('原型键不得把函数当译名（映射是普通对象）', () => {
  const zh = { 美国: '美国(US)' }
  for (const key of ['constructor', 'toString', 'valueOf', '__proto__']) {
    const label = countryLabel(zh, key)
    assert.equal(typeof label, 'string', `${key} 译名必须是字符串（原型链函数不得外泄）`)
    assert.equal(label, key, `${key} 未收录按原文回退`)
  }
})

test('失败回退原名且不闩死：下一次调用重试并落地中文映射', async () => {
  g.__gets = []
  let mode: 'fail' | 'ok' = 'fail'
  g.__get = async (url: string) => {
    assert.equal(url, '/security/ip2region/regions')
    if (mode === 'fail') throw new Error('network')
    return { data: { country_names_cn: { 美国: '美国', 德国: '德国' } } }
  }
  // 首次（失败）：不得抛出，映射为空 → 展示英文原名
  const zh = useCountryNamesCn()
  await waitForMicrotasks(() => g.__gets.length === 1, '首轮映射请求必须发出')
  // 请求已发起后再推进链尾（catch/finally/返回共若干跳）：失败轮不得落地映射
  await drainMicrotasks()
  assert.deepEqual(zh.value, {})
  // 鉴别力：映射值与键不同，才能区分「命中映射」与「回退原名」——此前用
  // 映射外的键 + 恒等映射，两态输出相同（断言恒真）。
  assert.equal(countryLabel({ 美国: '美国(US)' }, '美国'), '美国(US)', '命中映射必须用映射值')
  assert.equal(countryLabel({ 美国: '美国(US)' }, '德国'), '德国', '映射缺失时回退原名')
  assert.equal(countryLabel(zh.value, '美国'), '美国', '空映射回退原名')

  // 第二次（成功）：失败未缓存，下一次调用必须重试。等待条件同时覆盖两条契约：
  // 请求数涨到 2（失败未闩死）且映射落地——任一不成立都在预算内报错，不会把
  // 未收敛的中间态当结果断言。
  mode = 'ok'
  useCountryNamesCn()
  await waitForMicrotasks(
    () => g.__gets.length === 2 && Object.keys(zh.value).length === 2,
    '失败未缓存：下一次调用必须重试并落地中文映射',
  )
  assert.deepEqual(zh.value, { 美国: '美国', 德国: '德国' })
  assert.equal(countryLabel(zh.value, '德国'), '德国')
  assert.equal(countryLabel(zh.value, '法国'), '法国', '未收录国名回退原名')
  assert.equal(g.__gets.length, 2, '每次调用一次请求（失败未缓存）')

  // 第三次：加载成功即会话级缓存，不再请求
  useCountryNamesCn()
  await drainMicrotasks()
  assert.equal(g.__gets.length, 2, '成功后不得重复拉取')
  assert.deepEqual(g.__gets[0].config, { silent: true }, '映射拉取必须静默（不与全局拦截器双 toast）')
})

test('countryLabel 是纯翻译：哨兵/省份/省市联值原样返回', () => {
  const zh = { 美国: '美国(US)', 日本: '日本(JP)' }
  assert.equal(countryLabel(zh, '美国'), '美国(US)')
  assert.equal(countryLabel(zh, '日本'), '日本(JP)')
  assert.equal(countryLabel(zh, '海外'), '海外', '「海外」哨兵不是国家名')
  assert.equal(countryLabel(zh, '广东省'), '广东省')
  assert.equal(countryLabel(zh, '中国·广东省'), '中国·广东省', '联值不拆分（拆分由消费方负责）')
  assert.equal(countryLabel(zh, ''), '')
  assert.equal(countryLabel({}, '德国'), '德国')
})

// 消费侧接线钉：createLazyLoader 的唯一生产消费点（省名懒加载）。
// 改用直接 fetch 会让「首次国家名未加载时省名即触发请求」的回退失效。
test('createLazyLoader 接线：省名映射经 lazyOnce 单源懒加载', () => {
  const composable = code('src/composables/useCountryNamesCn.ts')
  assert.match(composable, /import \{ createLazyLoader \} from '@\/utils\/lazyOnce'/, '必须复用 lazyOnce')
  assert.match(composable, /createLazyLoader\(/, '省名加载必须经 createLazyLoader')
})
