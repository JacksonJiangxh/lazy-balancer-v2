import { test } from 'node:test'
import assert from 'node:assert/strict'
import { projectRuleFlowPath } from '../src/utils/ruleFlow.ts'
import { stage1FootnoteText, stageSubLabel } from '../src/utils/securityStages.ts'
import type { PathRule } from '../src/types/rules.ts'

const base: PathRule = {
  match_type: 'prefix', path: '/api', upstream_path: '', sort_order: 0, upstreams: null,
}

test('upstreams=null 投影保留默认上游语义', () => {
  assert.deepEqual(projectRuleFlowPath(base), {
    path: '/api', match_type: 'prefix', upstreams: null,
  })
})

test('自定义上游仍投影为启用明细', () => {
  assert.deepEqual(projectRuleFlowPath({
    ...base,
    upstreams: [{ protocol: 'http', address: '10.0.0.2', port: 8080, weight: 100 }],
  }), {
    path: '/api', match_type: 'prefix',
    upstreams: [{ host: '10.0.0.2', port: 8080, enabled: true }],
  })
})

test('静态返回与 301 回归形状保持', () => {
  assert.deepEqual(projectRuleFlowPath({ ...base, response_mode: 'static', response_status: 204 }), {
    path: '/api', match_type: 'prefix', upstreams: null,
    response_mode: 'static', response_status: 204, redirect_to: '',
  })
  assert.equal(projectRuleFlowPath({ ...base, response_mode: 'redirect', redirect_to: 'https://example.com' }).response_mode, 'redirect')
})

// 处理流程弹框的阶段 1 文案：副标题与脚注必须覆盖渲染链全部拦截
// 来源——遗留黑名单字段 ip_blacklist（id:4 仍发射）与 v2.3.8 爬虫校验
// （豁免 810000-849999 / 伪装拦截 850000-899999），链序按发射顺序。
test('阶段 1 文案：副标题与脚注含爬虫校验，脚注含遗留黑名单且链序正确', () => {
  assert.match(stageSubLabel(1), /爬虫校验/)
  const footnote = stage1FootnoteText(false)
  assert.match(footnote, /遗留黑名单（旧字段）/)
  assert.match(footnote, /爬虫校验/)
  // 地域拦截取最后一次出现（「白名单命中豁免地域拦截」括号内先出现一次）
  const order: Array<[string, number]> = [
    ['信任', footnote.indexOf('信任')],
    ['黑名单', footnote.indexOf('黑名单')],
    ['遗留黑名单', footnote.indexOf('遗留黑名单')],
    ['白名单外拒绝', footnote.indexOf('白名单外拒绝')],
    ['爬虫校验', footnote.indexOf('爬虫校验')],
    ['地域拦截', footnote.lastIndexOf('地域拦截')],
  ]
  for (const [token, position] of order) assert.ok(position >= 0, `脚注缺少环节：${token}`)
  const positions = order.map(([, position]) => position)
  assert.deepEqual(positions, [...positions].sort((a, b) => a - b), '阶段 1 链序与渲染发射顺序不一致')
})

test('阶段 1 脚注：绑定保留检测信任策略时追加降级说明', () => {
  assert.match(stage1FootnoteText(true), /绑定「保留检测」信任策略时命中降级为检测事件，不终止/)
  assert.ok(stage1FootnoteText(true).length > stage1FootnoteText(false).length)
})
