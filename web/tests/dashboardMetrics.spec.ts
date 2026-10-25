import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRuleMetricsUnavailable, METRIC_RELOAD_RESET_NOTE, ruleMetricCellTitle, TCP_UPSTREAM_GRANULARITY_NOTE } from '../src/utils/dashboardMetrics.ts'

const rules = [
  { caddy_id: 'lb_enabled', enabled: true },
  { caddy_id: 'lb_disabled', enabled: false },
]

test('metrics 先失败、rules 后落地仍逐行显示采集失败', () => {
  assert.deepEqual(buildRuleMetricsUnavailable([], undefined, false), {})
  assert.deepEqual(buildRuleMetricsUnavailable(rules, undefined, false), {
    lb_enabled: true,
    lb_disabled: false,
  })
})

test('成功响应缺失某规则才标失败，已有指标保持可用', () => {
  assert.deepEqual(buildRuleMetricsUnavailable(rules, { lb_enabled: { requests: 3 } }, true), {
    lb_enabled: false,
    lb_disabled: false,
  })
  assert.deepEqual(buildRuleMetricsUnavailable(rules, {}, true), {
    lb_enabled: true,
    lb_disabled: false,
  })
})

test('指标表原型键不得把「无指标」判成「有指标」', () => {
  // caddy_id 来自外部字符串：直接下标会把 Object.prototype 上的函数当成指标值，
  // 采集失败列退化为 0（缺失不得呈现为有值）。
  const protoRules = [
    { caddy_id: 'constructor', enabled: true },
    { caddy_id: 'toString', enabled: true },
    { caddy_id: '__proto__', enabled: true },
  ]
  assert.deepEqual(Object.entries(buildRuleMetricsUnavailable(protoRules, {}, true)), [
    ['constructor', true],
    ['toString', true],
    ['__proto__', true],
  ])
  // 键存在且值为 0 属真实指标（可用），只有 undefined/缺键才算采集失败
  assert.deepEqual(Object.entries(buildRuleMetricsUnavailable(protoRules, { constructor: 0 }, true)), [
    ['constructor', false],
    ['toString', true],
    ['__proto__', true],
  ])
})

test('TCP 行指标 title 明示上游地址口径，HTTP 行/禁用/采集失败不受影响', () => {
  // TCP 行：口径明示 + 值括注
  const tcpTitle = ruleMetricCellTitle({ disabled: false, unavailable: false, tcp: true, value: '1,234' })
  assert.ok(tcpTitle.includes(TCP_UPSTREAM_GRANULARITY_NOTE))
  assert.ok(tcpTitle.includes('1,234'))
  // HTTP 行：值 + 重载归零口径（Caddy registry 每次 /load 重建）
  const httpTitle = ruleMetricCellTitle({ disabled: false, unavailable: false, tcp: false, value: '56' })
  assert.ok(httpTitle.startsWith('56'))
  assert.ok(httpTitle.includes(METRIC_RELOAD_RESET_NOTE))
  // 禁用/采集失败优先于口径明示
  assert.equal(ruleMetricCellTitle({ disabled: true, unavailable: false, tcp: true, value: '1' }), '已禁用')
  assert.equal(ruleMetricCellTitle({ disabled: false, unavailable: true, tcp: true, value: '-' }), '采集失败')
})
