// 负载策略文案与卡片白名单：视图层不再手抄枚举——键集必须与后端
// validateStrategyForProtocol（internal/handlers/rule_features.go）的
// httpStrategies/tcpStrategies 双 map 逐项一致，文案不得漏映射（漏映射会让
// 面板直出英文枚举值）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  STRATEGY_CARD_OPTIONS,
  getStrategyLabel,
  strategyCardsForProtocol,
  strategyValuesForProtocol,
} from '../src/utils/strategyLabels.ts'
import { repoSource, section } from './_helpers.ts'

const goSrc = repoSource('internal/handlers/rule_features.go')
const goFn = section(goSrc, 'func validateStrategyForProtocol(', '\n}\n')
const goKeysOf = (declaration: string): string[] => {
  const block = section(goFn, declaration, '}')
  return [...block.matchAll(/"([a-z_]+)":\s*true/g)].map((match) => match[1])
}
const GO_HTTP = goKeysOf('httpStrategies := map[string]bool{')
const GO_TCP = goKeysOf('tcpStrategies := map[string]bool{')

test('策略键集与后端逐协议白名单一致（同集，顺序无关）', () => {
  assert.ok(GO_HTTP.length >= 6 && GO_TCP.length >= 5, '后端策略白名单未解析')
  assert.deepEqual([...strategyValuesForProtocol('http')].sort(), [...GO_HTTP].sort())
  assert.deepEqual([...strategyValuesForProtocol('tcp')].sort(), [...GO_TCP].sort())
  // cookie 仅 HTTP（TCP 白名单不含）
  assert.equal(GO_TCP.includes('cookie'), false)
  assert.deepEqual(GO_HTTP.filter((value) => !GO_TCP.includes(value)), ['cookie'])
})

test('卡片集按协议派生：TCP 剔除 cookie，HTTP 全量', () => {
  const http = strategyCardsForProtocol('http')
  const tcp = strategyCardsForProtocol('tcp')
  assert.equal(http.length, STRATEGY_CARD_OPTIONS.length)
  assert.equal(tcp.length, http.length - 1)
  assert.equal(tcp.some((card) => card.value === 'cookie'), false, 'TCP 不得出现 Cookie 粘滞卡片')
  assert.deepEqual([...strategyValuesForProtocol('http')], http.map((card) => card.value))
  assert.deepEqual([...strategyValuesForProtocol('tcp')], tcp.map((card) => card.value))
  for (const card of STRATEGY_CARD_OPTIONS) {
    assert.ok(card.title && card.desc, `${card.value} 缺少展示文案`)
  }
})

test('getStrategyLabel 覆盖后端全部枚举值，未知值原样回退', () => {
  for (const value of GO_HTTP) {
    const label = getStrategyLabel(value)
    assert.notEqual(label, value, `${value} 缺中文文案（会直出英文枚举）`)
    assert.ok(label.length > 0)
  }
  assert.equal(getStrategyLabel('weighted_round_robin'), '轮询')
  assert.equal(getStrategyLabel('least_conn'), '最少连接')
  assert.equal(getStrategyLabel('ip_hash'), 'IP 哈希')
  assert.equal(getStrategyLabel('cookie'), '粘滞')
  assert.equal(getStrategyLabel('first'), '首个可用')
  assert.equal(getStrategyLabel('random'), '随机')
  // 未知/空值回退原文（后端未来新增枚举时面板不炸）
  assert.equal(getStrategyLabel('least_response_time'), 'least_response_time')
  assert.equal(getStrategyLabel(''), '')
})
