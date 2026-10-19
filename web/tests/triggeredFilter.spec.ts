// 事件「触发规则」筛选序列化行为验收（审计 87 W87-15）：
// 原实现内联在 SecurityEvents.fetchEvents，只有源码文本钉；本测试钉住可观察契约：
// 空选/全选不发参数、子集按族段展开、自定义 tag 原样并入、段序稳定。
//
// 后端契约：internal/handlers/security.go ruleTriggeredFamilyPrefixes（逐段 OR）。
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  TRIGGERED_CATEGORIES,
  TRIGGERED_FAMILY_SEGMENTS,
  serializeTriggeredFilter,
} from '../src/utils/triggeredFilter.ts'

test('空选 = 不过滤（不发 rule_triggered）', () => {
  assert.equal(serializeTriggeredFilter([]), null)
})

test('八类全中且无自定义 tag = 全选，不发参数', () => {
  assert.equal(serializeTriggeredFilter([...TRIGGERED_CATEGORIES]), null)
  // 重复选中不应破坏全选判定
  assert.equal(serializeTriggeredFilter([...TRIGGERED_CATEGORIES, 'WAF·CRS']), null)
})

test('类别子集按族段展开（段序 = 选中顺序）', () => {
  assert.equal(serializeTriggeredFilter(['WAF·CRS']), 'WAF·CRS')
  assert.equal(serializeTriggeredFilter(['信任名单', '地域拦截']), '信任名单,地域拦截')
  // WAF·自定义 保留双段（后端两 token 同族，历史契约）
  assert.equal(serializeTriggeredFilter(['WAF·自定义']), 'WAF·自定义,自定义规则')
})

test('七类子集（缺一类）视为过滤而非全选', () => {
  const missingOne = TRIGGERED_CATEGORIES.filter((c) => c !== '请求体异常')
  assert.equal(serializeTriggeredFilter(missingOne), '爬虫Bot,地域拦截,IP 访问控制,信任名单,威胁情报库,WAF·CRS,WAF·自定义,自定义规则')
})

test('自定义 tag 原样并入末尾（CRS 规则 ID / 消息关键词）', () => {
  assert.equal(serializeTriggeredFilter(['WAF·CRS', '942100']), 'WAF·CRS,942100')
  // 八类全中 + 自定义 tag = 仍需发送（只发自定义 tag，类别段全展开）
  const allPlusCustom = serializeTriggeredFilter([...TRIGGERED_CATEGORIES, '942100'])
  assert.ok(allPlusCustom !== null)
  assert.ok(allPlusCustom.endsWith(',942100'))
  assert.ok(allPlusCustom.includes('WAF·CRS'))
})

test('只有自定义 tag 时不产生类别段', () => {
  assert.equal(serializeTriggeredFilter(['942100']), '942100')
})

test('每个类别的族段非空且与后端 family 键同名（除已登记的双段类别）', () => {
  for (const category of TRIGGERED_CATEGORIES) {
    const segments = TRIGGERED_FAMILY_SEGMENTS[category]
    assert.ok(segments.length > 0, `${category} 必须有族段`)
    for (const segment of segments) assert.ok(segment.trim() !== '', `${category} 段不得为空`)
  }
})
