// 触发详情弹框（TriggerDetailDialog）的名单条目加载态：
// ensureSharedEntries 对单名单失败保持「未缓存」且不抛出（下次可重试契约），
// 因此弹框侧的 try/catch 永远不会被触发——条目缺失会被静默渲染成
// 「未定位到命中的地址列表」的业务结论（与真实未命中无法区分）。
// 必须显式失败（横幅 + 重试），并让「未定位」结论在失败态不可达；
// 范式与 IP 处置弹框（IPLocationAction）的 listsError 一致。
//
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），模板依赖
// element-plus 全局组件——不可在 node 下挂载，故用「限段 + 边界」文本钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, section, source } from './_helpers.ts'

const file = 'src/components/events/TriggerDetailDialog.vue'
const logic = code(file)
const markup = source(file)

test('名单条目失败不得静默：按 refIds 缺失显性置 entriesError', () => {
  assert.match(logic, /const entriesError = ref\(false\)/)
  const loadAll = section(logic, 'const loadAll = async', '\n}\n')
  assert.match(loadAll, /entriesError\.value = false/, '每轮装载先复位失败态')
  assert.match(
    loadAll,
    /entriesError\.value = missingSharedEntryIds\(refIds\)\.length > 0/,
    'ensureSharedEntries 单名单失败不抛出——必须按引用名单是否全部落地判定',
  )
  // 缺失判定必须在条目补齐之后（先判定再加载会把在途请求误报为失败）
  const ensured = loadAll.indexOf('await ensureSharedEntries(refIds')
  const flagged = loadAll.indexOf('entriesError.value = missingSharedEntryIds(refIds)')
  assert.ok(ensured > 0, 'loadAll 必须先补齐条目')
  assert.ok(flagged > ensured, '失败判定必须排在条目补齐之后')
})

test('失败态有横幅与重试入口（策略/条目同轮重取）', () => {
  assert.match(logic, /const retryLists = \(\): void => \{ void loadAll\(\) \}/)
  assert.match(markup, /<div v-if="entriesError && !loadError" class="info-note-bar">/)
  assert.match(markup, /地址列表条目加载失败/)
  assert.match(markup, /@click="retryLists">重新加载<\/el-button>/)
  // 策略信息失败同样不得只提示「关闭后重试」——弹框内可原地重试
  assert.match(markup, /<div v-if="loadError" class="info-note-bar">/)
})

test('失败态不得退化成「未定位到命中的地址列表」的业务结论', () => {
  const tipLine = markup.split('\n').find((line) => line.includes('未定位到命中的地址列表'))
  assert.ok(tipLine, '未定位提示仍在模板中')
  assert.match(tipLine!, /!entriesError/, '条目加载失败时「未定位」不成立')
  assert.match(tipLine!, /!loadError/, '策略/名单加载失败时「未定位」不成立')
})
