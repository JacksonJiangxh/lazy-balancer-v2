// IP 处置弹框（IPLocationAction）的地址列表加载态：名单/引用条目加载失败时，
// rowView 的 inList/inTrust 只剩内联口径——引用名单命中会被渲染成「未命中」，
// 与真实未命中无法区分。必须显式失败（横幅 + 重试）并暂停处置动作。
// 真实前提：node --test 无 .vue 装载器（本套件禁止静态 import .vue），且模板
// 依赖 element-plus 全局组件——不可在 node 下挂载，故用「限段 + 边界」文本钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

const page = source('src/views/security/IPLocationAction.vue')

test('名单加载失败不得静默：catch 置 listsError 并清空名单，成功分支按缺失条目重算', () => {
  assert.match(page, /const listsError = ref\(false\)/)

  const loadIpLists = section(page, 'const loadIpLists = async', '\n}\n')
  assert.match(loadIpLists, /listsError\.value = \[\.\.\.refIds\]\.some\(\(id\) => !\(id in sharedEntriesCache\)\)/,
    'ensureSharedEntries 单名单失败保持未缓存——引用条目缺失同属加载失败')
  // 失败分支：清空本次名单 → 置错误态（顺序按语句位置判定，不耦合空行/缩进）
  const catchAt = loadIpLists.indexOf('} catch {')
  assert.ok(catchAt >= 0, 'loadIpLists 必须有 catch 分支')
  const failure = loadIpLists.slice(catchAt)
  const cleared = failure.indexOf('ipLists.value = []')
  const flagged = failure.indexOf('listsError.value = true', cleared + 1)
  assert.ok(cleared > 0, '名单接口失败必须清空本次名单')
  assert.ok(flagged > cleared, '名单接口失败必须置错误态（清空之后）')
})

test('失败态有横幅与重试入口，处置动作在失败态禁用', () => {
  assert.match(page, /<div v-if="listsError" class="info-note-bar">/)
  assert.match(page, /@click="retryLists">重新加载<\/el-button>/)
  assert.match(page, /const retryLists = \(\): void => \{ void loadPolicies\(\) \}/)
  assert.match(page, /:disabled="act\.disabled"/, '动作按钮绑定禁用态')
  assert.match(page, /return listsError\.value \? acts\.map\(\(act\) => \(\{ \.\.\.act, disabled: true \}\)\) : acts/,
    '名单未就绪时整区动作禁用（依据不可靠不得写入）')
})
