// 国家中文名展示层单源：映射由后端 country_names_cn 下发（前端零复制表），
// 未命中/旧后端/请求失败一律回退英文原名；失败不得把整会话闩死（下一次调用
// 自然重试）。countryLabel 是三个消费方锁步的回退契约。
//
// 动态 import：api 替身须先于模块求值注册。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'
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

const tick = async (): Promise<void> => {
  for (let i = 0; i < 4; i++) {
    const { promise, resolve } = Promise.withResolvers<void>()
    setTimeout(resolve, 0)
    await promise
  }
}

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
  await tick()
  assert.deepEqual(zh.value, {})
  assert.equal(countryLabel(zh.value, '美国'), '美国', '映射缺失时回退原名')

  // 第二次（成功）：失败未缓存，下一次调用必须重试
  mode = 'ok'
  useCountryNamesCn()
  await tick()
  assert.deepEqual(zh.value, { 美国: '美国', 德国: '德国' })
  assert.equal(countryLabel(zh.value, '德国'), '德国')
  assert.equal(countryLabel(zh.value, '法国'), '法国', '未收录国名回退原名')
  assert.equal(g.__gets.length, 2, '每次调用一次请求（失败未缓存）')

  // 第三次：加载成功即会话级缓存，不再请求
  useCountryNamesCn()
  await tick()
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
