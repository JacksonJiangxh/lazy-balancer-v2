import type { PathRule, RuleFlowPathRule } from '../types/rules.ts'

/** 规则详情 → 流程弹框路径投影；upstreams=null 必须保留「跟随主路由」语义。 */
export const projectRuleFlowPath = (rule: PathRule): RuleFlowPathRule => {
  const responseMode = rule.response_mode === 'static' || rule.response_mode === 'redirect' ? rule.response_mode : ''
  return {
    path: rule.path,
    match_type: rule.match_type,
    upstreams: rule.upstreams === null
      ? null
      : (rule.upstreams ?? []).map((upstream) => ({ host: upstream.address, port: upstream.port, enabled: true })),
    ...(responseMode
      ? { response_mode: responseMode, response_status: rule.response_status || 200, redirect_to: rule.redirect_to || '' }
      : {}),
  }
}
