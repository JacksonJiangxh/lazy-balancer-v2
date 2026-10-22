// 深链 URL 构造单源验收：页面键受 PageId 约束、参数键常量导出，视图不得
// 再写 `/?page=` 字面量（改名时静默回落 dashboard）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { source } from './_helpers.ts'
import { DEEP_LINK_PARAMS, pageUrl } from '../src/utils/deepLink.ts'

test('pageUrl：基础形态与参数编码', () => {
  assert.equal(pageUrl('security-events'), '/?page=security-events')
  assert.equal(
    pageUrl('rules', { [DEEP_LINK_PARAMS.ruleSearch]: 'lb_a b' }),
    '/?page=rules&rs=lb_a+b',
  )
  assert.equal(
    pageUrl('security-policies', { [DEEP_LINK_PARAMS.policyId]: 7 }),
    '/?page=security-policies&sp=7',
  )
})

test('参数键常量与消费侧解析一致', () => {
  assert.equal(DEEP_LINK_PARAMS.ruleSearch, 'rs')
  assert.equal(DEEP_LINK_PARAMS.policyId, 'sp')
  assert.equal(DEEP_LINK_PARAMS.policySearch, 'sp-search')
  assert.equal(DEEP_LINK_PARAMS.securityRulesTab, 'tab')
})

test('五个交接入口改用 pageUrl，视图内不再出现 /?page= 字面量', () => {
  const views = [
    'src/views/security/SecurityEvents.vue',
    'src/views/security/SecurityPolicies.vue',
    'src/views/security/SecurityOverview.vue',
  ]
  for (const path of views) {
    const text = source(path)
    assert.match(text, /from '@\/utils\/deepLink'/, `${path} 未接入深链单源`)
    assert.doesNotMatch(text, /window\.open\('\/\?page=/, `${path} 仍有字面量深链`)
    assert.doesNotMatch(text, /window\.open\(`\/\?page=/, `${path} 仍有字面量深链`)
  }
  // 消费侧参数名同样走常量
  assert.match(source('src/views/Rules.vue'), /get\(DEEP_LINK_PARAMS\.ruleSearch\)/)
  assert.match(source('src/views/security/SecurityRules.vue'), /get\(DEEP_LINK_PARAMS\.securityRulesTab\)/)
  assert.match(source('src/views/security/SecurityPolicies.vue'), /get\(DEEP_LINK_PARAMS\.policySearch\)/)
})
