// 自动封禁状态卡黄条判据（行为化：原源码
// 正则断言改为纯函数行为断言）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isAutobanIneffective } from '../src/utils/autobanStatus.ts'
import { source } from './_helpers.ts'

test('启用且 ban_effective === false 时展示黄条', () => {
  assert.equal(isAutobanIneffective({ enabled: true, ban_effective: false }), true)
})

test('list_referenced 形态不再驱动黄条（判据只看 ban_effective）', () => {
  // 历史回归：仅被白名单/受信代理引用时 list_referenced=true，但名单未被 deny
  // 策略引用 → ban_effective=false。若判据误用 list_referenced 会两头都错：
  const onlyReferencedButEffective = { enabled: true, ban_effective: true } as const
  assert.equal(isAutobanIneffective(onlyReferencedButEffective), false)
  const referencedButNotEffective = { enabled: true, ban_effective: false } as const
  assert.equal(isAutobanIneffective(referencedButNotEffective), true)
})

test('未启用时不提示（黄条仅针对已启用但未生效）', () => {
  assert.equal(isAutobanIneffective({ enabled: false, ban_effective: false }), false)
  assert.equal(isAutobanIneffective({ enabled: false, ban_effective: true }), false)
})

test('fail-closed 默认：成功响应前 ban_effective 缺省不弹黄条', () => {
  assert.equal(isAutobanIneffective({ enabled: true }), false)
})

// 消费侧接线：纯函数用例拦不住「黄条绑定被删」——告警静默消失，用户以为封禁在生效。
test('事件页黄条由该判据派生（绑定与计算属性都在）', () => {
  const page = source('src/views/security/SecurityEvents.vue')
  assert.match(
    page,
    /const autobanIneffective = computed\(\(\) => isAutobanIneffective\(autobanStatus\.value\)\)/,
    '黄条判据必须来自共享纯函数',
  )
  assert.match(page, /v-if="autobanIneffective"/, '模板必须渲染该判据驱动的提示条')
})
