// 任务监控页必须消费 cert_jobs_truncated：证书任务动态行触达采集上限时，列表
// 少行不能与「本来就没有」不可区分（后端 /system/tasks 已下发该标记）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { source } from './_helpers.ts'

const page = source('src/views/settings/TaskMonitor.vue')

test('证书任务截断标记进入响应类型并被读取', () => {
  assert.match(page, /cert_jobs_truncated\?: boolean/)
  assert.match(page, /certJobsTruncated\.value = !!res\.data\.cert_jobs_truncated/)
})

test('截断时渲染提示条（复用全局 info-note-bar 样式，不写局部 hack）', () => {
  const match = page.match(/\n\s*<div v-if="certJobsTruncated" class="([^"]+)">([\s\S]*?)<\/div>/)
  assert.ok(match, '缺少 v-if="certJobsTruncated" 提示条')
  const classes = match[1].split(/\s+/)
  assert.ok(classes.includes('info-note-bar'), `提示条必须复用全局 info-note-bar 类，got "${match[1]}"`)
  assert.match(match[2], /info-note-desc/)
  assert.match(match[2], /最近 100 条/)
  assert.doesNotMatch(page, /:deep\([^)]*\)\s*\{[^}]*info-note/)
})
