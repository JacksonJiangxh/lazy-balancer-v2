import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRuleMetricsUnavailable } from '../src/utils/dashboardMetrics.ts'

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
