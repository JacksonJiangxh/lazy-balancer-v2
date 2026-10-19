import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRuleMetricsUnavailable, ruleMetricCellTitle, TCP_UPSTREAM_GRANULARITY_NOTE } from '../src/utils/dashboardMetrics.ts'

const rules = [
  { caddy_id: 'lb_enabled', enabled: true },
  { caddy_id: 'lb_disabled', enabled: false },
]

test('历史问题-6：metrics 先失败、rules 后落地仍逐行显示采集失败', () => {
  assert.deepEqual(buildRuleMetricsUnavailable([], undefined, false), {})
  assert.deepEqual(buildRuleMetricsUnavailable(rules, undefined, false), {
    lb_enabled: true,
    lb_disabled: false,
  })
})

test('历史问题-6：成功响应缺失某规则才标失败，已有指标保持可用', () => {
  assert.deepEqual(buildRuleMetricsUnavailable(rules, { lb_enabled: { requests: 3 } }, true), {
    lb_enabled: false,
    lb_disabled: false,
  })
  assert.deepEqual(buildRuleMetricsUnavailable(rules, {}, true), {
    lb_enabled: true,
    lb_disabled: false,
  })
})

test('A86 历史问题：TCP 行指标 title 明示上游地址口径，HTTP 行/禁用/采集失败不受影响', () => {
  // TCP 行：口径明示 + 值括注
  const tcpTitle = ruleMetricCellTitle({ disabled: false, unavailable: false, tcp: true, value: '1,234' })
  assert.ok(tcpTitle.includes(TCP_UPSTREAM_GRANULARITY_NOTE))
  assert.ok(tcpTitle.includes('1,234'))
  // HTTP 行：仅值（插件按 caddy_id 精确归集）
  assert.equal(ruleMetricCellTitle({ disabled: false, unavailable: false, tcp: false, value: '56' }), '56')
  // 禁用/采集失败优先于口径明示
  assert.equal(ruleMetricCellTitle({ disabled: true, unavailable: false, tcp: true, value: '1' }), '已禁用')
  assert.equal(ruleMetricCellTitle({ disabled: false, unavailable: true, tcp: true, value: '-' }), '采集失败')
})
