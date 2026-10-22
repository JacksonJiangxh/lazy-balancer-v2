// 审计动作词色调验收：例外表 + 关键词派生 + 未命中告警。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { source } from './_helpers.ts'
import { actionTagType } from '../src/utils/auditActionTone.ts'

test('既有动作词色调不回归（例外表逐类代表）', () => {
  const expectations: Array<[string, string]> = [
    ['删除', 'danger'],
    ['禁用', 'danger'],
    ['配置漂移', 'danger'],
    ['渲染跳过', 'danger'], // 含「跳过」但语义是配置错误
    ['自动封禁', 'danger'],
    ['更新', 'warning'],
    ['重置密码', 'warning'],
    ['提升完成', 'warning'], // 含「完成」但风险操作
    ['同步应用', 'warning'],
    ['签发限流', 'warning'],
    ['创建', 'success'],
    ['重置', 'success'],
    ['自动解封', 'success'],
    ['自动检测', 'success'],
  ]
  for (const [action, tone] of expectations) {
    assert.equal(actionTagType(action), tone, `${action} 色调漂移`)
  }
})

test('关键词派生：新动作词自动归类（不再静默落灰色）', () => {
  assert.equal(actionTagType('突发异常'), 'danger')
  assert.equal(actionTagType('策略阻断'), 'danger')
  assert.equal(actionTagType('导入拒绝'), 'danger')
  assert.equal(actionTagType('导出警告'), 'warning')
  assert.equal(actionTagType('渲染跳过后续'), 'warning')
  assert.equal(actionTagType('缓存降级'), 'warning')
  assert.equal(actionTagType('同步完成'), 'success')
  assert.equal(actionTagType('签发成功'), 'success')
  assert.equal(actionTagType('例行巡检'), 'info')
})

test('未命中动作词只告警一次（去重）', () => {
  const warnings: string[] = []
  const original = console.warn
  console.warn = (...args: unknown[]) => { warnings.push(args.join(' ')) }
  try {
    assert.equal(actionTagType('神秘新动作'), 'info')
    assert.equal(actionTagType('神秘新动作'), 'info')
  } finally {
    console.warn = original
  }
  assert.equal(warnings.length, 1)
  assert.match(warnings[0], /神秘新动作/)
})

test('视图消费单源（不再自带百行字面量表）', () => {
  const page = source('src/views/AuditLog.vue')
  assert.match(page, /import \{ actionTagType \} from '@\/utils\/auditActionTone'/)
  assert.doesNotMatch(page, /ACTION_TAG_TABLE/)
})
