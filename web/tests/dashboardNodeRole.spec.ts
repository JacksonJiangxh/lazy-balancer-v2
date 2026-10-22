// 系统概览页的一致性 tag 在「节点角色未知」窗口必须 fail-closed：nodeMode 为
// null（/config 首拉失败或 15s 重试期内）时 configConsistent 不构成证据，展示层
// 不得宣告「配置正常」。分支顺序（从节点 → 角色未知 → 配置正常/异常）由源码钉。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

const dashboard = source('src/views/Dashboard.vue')

test('角色未知分支位于配置正常/异常之前，且文案与 tag 形态复用既有样式', () => {
  const chain = section(dashboard, 'v-if="authStore.isSlaveNode"', 'configConsistent === \'false\'')
  const unknownAt = chain.indexOf("nodeModeRole === 'unknown'")
  const consistentAt = chain.indexOf("configConsistent === 'true'")
  assert.ok(unknownAt > 0, '缺少 nodeModeRole === \'unknown\' 分支')
  assert.ok(consistentAt > unknownAt, '角色未知分支必须在「配置正常」之前（否则未知窗口仍显示配置正常）')
  const unknownBranch = chain.slice(unknownAt, consistentAt)
  assert.match(unknownBranch, /角色未知/)
  assert.match(unknownBranch, /<el-tag type="info" size="small" effect="plain">/)
})

test('三态节点角色派生根源于 nodeMode，null 归 unknown', () => {
  const role = section(dashboard, 'const nodeModeRole', 'const nodeModeTagType')
  assert.match(role, /authStore\.nodeMode === 'master'/)
  assert.match(role, /authStore\.nodeMode === 'slave'/)
  assert.match(role, /'unknown'/)
})
