import { test } from 'node:test'
import assert from 'node:assert/strict'

import { clusterWriteBlocked } from '../src/utils/clusterWriteGate.ts'
import { section, code } from './_helpers.ts'

// stores/auth 的 readOnlyReason 先判节点模式（slave 优先于角色短路）：
// 从节点上任何角色都只会得到 'slave'。旧实现只认 non-admin/unknown，
// 于是「从节点 + 非管理员」被判为可写——「提升为主节点」等破坏性按钮可点，
// 点击后只得到后端 403。

test('从节点非管理员只读（旧判据漏掉的组合）', () => {
  assert.equal(clusterWriteBlocked({ readOnlyReason: 'slave', role: 'user' }), true)
})

test('从节点 admin 仍可操作集群（既有契约：节点自身可提升为主节点）', () => {
  assert.equal(clusterWriteBlocked({ readOnlyReason: 'slave', role: 'admin' }), false)
})

test('主节点非管理员只读（non-admin 分支）', () => {
  assert.equal(clusterWriteBlocked({ readOnlyReason: 'non-admin', role: 'user' }), true)
})

test('主节点 admin 可写', () => {
  assert.equal(clusterWriteBlocked({ readOnlyReason: null, role: 'admin' }), false)
})

test('节点模式未知 fail-closed（即使角色已判定为 admin）', () => {
  assert.equal(clusterWriteBlocked({ readOnlyReason: 'unknown', role: 'admin' }), true)
})

test('角色缺失按只读处理（信息未就绪不得呈现可写）', () => {
  assert.equal(clusterWriteBlocked({ readOnlyReason: null, role: undefined }), true)
  assert.equal(clusterWriteBlocked({ readOnlyReason: null, role: null }), true)
})

test('视图消费单源：isReadOnlyProp 不再自行拼装 reason 集合', () => {
  const page = code('src/views/settings/ClusterSettings.vue')
  const block = section(page, 'const isReadOnlyProp = computed', 'const clusterModeChanging')
  assert.match(block, /clusterWriteBlocked\(/)
  assert.match(block, /role: authStore\.user\?\.role/, '角色必须独立参与判定')
  assert.doesNotMatch(block, /reason === 'non-admin' \|\| reason === 'unknown'/, '不得保留双源判定')
})
