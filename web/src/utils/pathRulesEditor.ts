// 路径规则编辑器（向导「自定义路由」步骤）的行内判定单源。
//
// 组件只做取值与渲染，判定全部在此——纯函数可被 node 行为求值，避免把
// 用户可见的重复/遮蔽/模式归一语义埋在 SFC 里只能靠文本钉。
import type { PathRule } from '@/types'
import {
  STATIC_RESPONSE_BODY_MAX_RUNES,
  canonicalPathKey,
  isRedirectResponseStatus,
  isResponseBodyAllowed,
  isValidRedirectTargetShape,
  pathDuplicateKey,
  pathRuleError,
} from './ruleValidation.ts'

/** 行内错误：字段级（空/非法/上游路径）+ 同类型查重 + 跨类型遮蔽互查。 */
export const pathRuleRowError = (rules: readonly PathRule[], index: number): string => {
  const rule = rules[index]
  if (!rule) return ''
  // 字段级判据与整组校验单源（ruleValidation.pathRuleError）：清空路径
  // 立即在行内标红，不再等到点保存才被整组拒绝（晚失败）。
  const fieldError = pathRuleError(rule)
  if (fieldError) return fieldError
  const canonical = canonicalPathKey(rule.match_type, rule.path)
  const duplicateKey = pathDuplicateKey(rule.match_type, rule.path)
  // 同类型查重按后端口径（exact 不剥尾 /，/a 与 /a/ 是两条独立 matcher）；
  // canonicalPathKey 归一键只用于跨类型遮蔽互查。
  const duplicateIndex = rules.findIndex((other, otherIndex) =>
    otherIndex !== index && other.path.trim() !== ''
      && (other.match_type === rule.match_type
        ? pathDuplicateKey(other.match_type, other.path) === duplicateKey
        : canonicalPathKey(other.match_type, other.path) === canonical))
  if (duplicateIndex >= 0) {
    const other = rules[duplicateIndex]
    if (!other) return ''
    return other.match_type === rule.match_type
      ? `与规则 ${duplicateIndex + 1} 重复`
      : `与规则 ${duplicateIndex + 1} 同路径前缀+精确互相遮蔽`
  }
  return ''
}

// 前序 prefix 规则遮蔽提示——后端有意放行（测试钉住），仅 UI 非阻断警告。
// 判定口径与 services/caddy.go pathMatcherSpecs + terminal 路由一致：prefix
// 渲染 [root, root/*] 双 matcher（root=剥尾 / 与 *，剥空 = /* 全匹配），路由按
// sort_order 稳定排序、先命中即终结，故前序 prefix P 遮蔽后序规则 Q 当且仅当
// canonical(Q)===root(P) 或以 root(P)+"/" 开头。
export const shadowedByIndex = (rules: readonly PathRule[], index: number): number => {
  const rule = rules[index]
  if (!rule) return -1
  // 非法/空路径由行内错误负责，不参与遮蔽判定（避免提示噪音）
  if (rule.path !== '' && !rule.path.startsWith('/')) return -1
  if (/[*?{}]/.test(rule.path)) return -1
  if (rule.path.trim() === '') return -1
  const canonical = canonicalPathKey(rule.match_type, rule.path)
  for (let priorIndex = 0; priorIndex < index; priorIndex++) {
    const prior = rules[priorIndex]
    if (!prior || prior.match_type !== 'prefix') continue
    if (prior.path.trim() === '' || !prior.path.startsWith('/') || /[*?{}]/.test(prior.path)) continue
    const root = canonicalPathKey('prefix', prior.path)
    if (root === '/' || canonical === root || canonical.startsWith(`${root}/`)) return priorIndex
  }
  return -1
}

export const pathRuleShadowWarning = (rules: readonly PathRule[], index: number): string => {
  const priorIndex = shadowedByIndex(rules, index)
  if (priorIndex < 0) return ''
  const prior = rules[priorIndex]
  return `被前序前缀规则 ${priorIndex + 1}（${prior?.path.trim() ?? ''}）遮蔽，不会生效`
}

// isForwardResponseMode 转发判定：''（API 形态）与 'forward'（UI 哨兵——el-select
// 空串选项不显示标签）同为转发；提交时归一为 ''。
export const isForwardResponseMode = (rule: PathRule): boolean =>
  !rule.response_mode || rule.response_mode === 'forward'

// applyResponseMode 模式切换归一：非转发模式清空转发专属字段（上游路径/自定义
// 上游），跳转/静态互清对方字段，静态进场补默认值（后端写侧同口径归一）。
export const applyResponseMode = (rule: PathRule): void => {
  if (!isForwardResponseMode(rule)) {
    rule.upstream_path = ''
    rule.upstreams = null
  }
  if (rule.response_mode === 'static') {
    rule.redirect_to = ''
    if (!rule.response_status) rule.response_status = 200
    if (!rule.response_content_type) rule.response_content_type = 'text/plain'
  } else if (rule.response_mode === 'redirect') {
    rule.response_body = ''
    rule.response_content_type = ''
  } else {
    rule.response_status = 200
    rule.response_body = ''
    rule.response_content_type = ''
    rule.redirect_to = ''
  }
}

/**
 * 行内校验（与后端 validateRuleFeatures / ruleValidation.ts 同口径）。
 *
 * 2026-11-11 TASK-2026-1111-01：static 模式此前**没有任何行内诊断**——选 3xx
 * 不填跳转地址、非 3xx 填了跳转地址、超长/控制字符内容都只在点保存时被整组
 * 拒绝且不定位到行（late failure）。现按后端同序补齐。
 */
export const pathRuleResponseError = (rule: PathRule): string => {
  if (rule.response_mode === 'redirect') {
    // redirect 不读 rule.response_status（残留值会误伤）；形状判定查原串。
    // 详见 docs/fork-notes/frontend.md §6
    // 后端按原串判定——`" http://x"`
    // 若前端 trim 后放行，会在离开该步时被整组拒绝（late failure 复发）。
    const raw = rule.redirect_to ?? ''
    if (!raw.trim()) return '301 跳转需要填写跳转地址'
    if (!isValidRedirectTargetShape(raw)) return '跳转地址须为 http(s):// 绝对地址或 / 开头路径，且不含空格与控制字符'
    return ''
  }
  if (rule.response_mode === 'static') {
    const status = rule.response_status || 200
    const body = rule.response_body ?? ''
    if (body !== '' && !isResponseBodyAllowed(status)) return `状态码 ${status} 按 RFC 9110 不得携带响应内容（请清空内容）`
    if ([...body].length > STATIC_RESPONSE_BODY_MAX_RUNES) return `响应内容不能超过 ${STATIC_RESPONSE_BODY_MAX_RUNES} 个字符`
    // eslint-disable-next-line no-control-regex
    if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(body)) return '响应内容含非法控制字符'
    const target = (rule.redirect_to ?? '').trim()
    if (isRedirectResponseStatus(status)) {
      if (!target) return `状态码 ${status} 是重定向，必须填写跳转地址`
      if (!isValidRedirectTargetShape(target)) return '跳转地址须为 http(s):// 绝对地址或 / 开头路径，且不含空格与控制字符'
    } else if (target) {
      return `状态码 ${status} 不是重定向，不应填写跳转地址（请清空）`
    }
  }
  return ''
}
