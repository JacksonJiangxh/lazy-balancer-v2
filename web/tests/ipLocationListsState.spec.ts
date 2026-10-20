// IP 处置弹框（IPLocationAction）的地址列表加载态：名单/引用条目加载失败时，
// rowView 的 inList/inTrust 只剩内联口径——引用名单命中会被渲染成「未命中」，
// 与真实未命中无法区分。必须显式失败（横幅 + 重试）并暂停处置动作。
// SFC 无法在 node --test 下挂载，沿用本仓「源码钉」形态（限段 + 边界）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

const page = source('src/views/security/IPLocationAction.vue')

test('名单加载失败不得静默：catch 置 listsError，成功分支按缺失条目重算', () => {
  assert.match(page, /const listsError = ref\(false\)/)

  const loadIpLists = section(page, 'const loadIpLists = async', '\n}\n')
  assert.match(loadIpLists, /listsError\.value = \[\.\.\.refIds\]\.some\(\(id\) => !\(id in sharedEntriesCache\)\)/,
    'ensureSharedEntries 单名单失败保持未缓存——引用条目缺失同属加载失败')
  assert.match(loadIpLists, /ipLists\.value = \[\]\s*\n\s*listsError\.value = true/, '名单接口失败必须同时置错误态')
})

test('失败态有横幅与重试入口，处置动作在失败态禁用', () => {
  assert.match(page, /<div v-if="listsError" class="info-note-bar">/)
  assert.match(page, /@click="retryLists">重新加载<\/el-button>/)
  assert.match(page, /const retryLists = \(\): void => \{ void loadPolicies\(\) \}/)
  assert.match(page, /:disabled="act\.disabled"/, '动作按钮绑定禁用态')
  assert.match(page, /return listsError\.value \? acts\.map\(\(act\) => \(\{ \.\.\.act, disabled: true \}\)\) : acts/,
    '名单未就绪时整区动作禁用（依据不可靠不得写入）')
})
