// CRS 规则文件全量分页取回：触顶/取不满必须抛错，不得静默返回不完整清单。
//
// 不完整清单会让组名映射回退裸组码、策略页把取不到的规则组判成「已无此组」
// 而放行删除——两处消费都依赖这份集合完整。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'
import { STUB_API } from './_stubs.ts'

interface GetRecord {
  url: string
  config?: unknown
}

const g = globalThis as unknown as {
  __gets: GetRecord[]
  __get: (url: string, config?: unknown) => Promise<unknown>
}
g.__gets = []
g.__get = async () => ({ data: { rules: [], total: 0 } })

registerModuleHooks({ './api': STUB_API })
// 静态 import 会先于 registerModuleHooks 执行，被测模块将装载真实 api.ts
// （axios + DOM 依赖），故这里必须动态 import。
const { CRS_RULE_PAGE_SIZE, CRS_RULE_MAX_PAGES, fetchAllCrsRuleFiles } = await import('../src/utils/crsRuleFiles.ts')

const pageOf = (count: number, total?: number): unknown => ({
  data: {
    rules: Array.from({ length: count }, (_, i) => ({ filename: `f${i}.conf`, category: 'c' })),
    ...(typeof total === 'number' ? { total } : {}),
  },
})

test('短页收敛：末页不足一页即结束', async () => {
  g.__gets = []
  const total = CRS_RULE_PAGE_SIZE + 3
  let call = 0
  g.__get = async () => (++call === 1 ? pageOf(CRS_RULE_PAGE_SIZE, total) : pageOf(3, total))
  const all = await fetchAllCrsRuleFiles()
  assert.equal(all.length, total)
  assert.equal(g.__gets.length, 2, '短页后不得再请求下一页')
  assert.match(g.__gets[0].url, /page=1/)
  assert.match(g.__gets[1].url, /page=2/)
})

test('total 收敛：取满 total 即结束', async () => {
  g.__gets = []
  g.__get = async () => pageOf(CRS_RULE_PAGE_SIZE, CRS_RULE_PAGE_SIZE)
  const all = await fetchAllCrsRuleFiles()
  assert.equal(all.length, CRS_RULE_PAGE_SIZE)
  assert.equal(g.__gets.length, 1)
})

test('触顶仍未取满：必须抛错（不得静默截断）', async () => {
  g.__gets = []
  const total = CRS_RULE_PAGE_SIZE * CRS_RULE_MAX_PAGES + 1
  g.__get = async () => pageOf(CRS_RULE_PAGE_SIZE, total)
  await assert.rejects(() => fetchAllCrsRuleFiles(), /未取全/)
  assert.equal(g.__gets.length, CRS_RULE_MAX_PAGES, '必须在上限处停止请求')
})

test('服务端未给 total 且末页满页：视为未收敛并抛错', async () => {
  g.__gets = []
  g.__get = async () => pageOf(CRS_RULE_PAGE_SIZE)
  await assert.rejects(() => fetchAllCrsRuleFiles(), /未取全/)
})

test('短页但 total 声称更多：仍属不完整，必须抛错', async () => {
  g.__gets = []
  g.__get = async () => pageOf(3, 100)
  await assert.rejects(() => fetchAllCrsRuleFiles(), /未取全/)
})
