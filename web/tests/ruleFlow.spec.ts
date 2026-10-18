import { test } from 'node:test'
import assert from 'node:assert/strict'
import { projectRuleFlowPath } from '../src/utils/ruleFlow.ts'
import type { PathRule } from '../src/types/rules.ts'

const base: PathRule = {
  match_type: 'prefix', path: '/api', upstream_path: '', sort_order: 0, upstreams: null,
}

test('历史问题-02：upstreams=null 投影保留默认上游语义', () => {
  assert.deepEqual(projectRuleFlowPath(base), {
    path: '/api', match_type: 'prefix', upstreams: null,
  })
})

test('历史问题-02：自定义上游仍投影为启用明细', () => {
  assert.deepEqual(projectRuleFlowPath({
    ...base,
    upstreams: [{ protocol: 'http', address: '10.0.0.2', port: 8080, weight: 100 }],
  }), {
    path: '/api', match_type: 'prefix',
    upstreams: [{ host: '10.0.0.2', port: 8080, enabled: true }],
  })
})

test('历史问题-02：静态返回与 301 回归形状保持', () => {
  assert.deepEqual(projectRuleFlowPath({ ...base, response_mode: 'static', response_status: 204 }), {
    path: '/api', match_type: 'prefix', upstreams: null,
    response_mode: 'static', response_status: 204, redirect_to: '',
  })
  assert.equal(projectRuleFlowPath({ ...base, response_mode: 'redirect', redirect_to: 'https://example.com' }).response_mode, 'redirect')
})
