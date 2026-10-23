/**
 * 受信代理（CDN 回源）配置的行内校验，与后端判据单源：
 *
 * - `internal/services/caddy.go` 的 `TrustedProxyMinPrefixBits`（IPv4 /8、
 *   IPv6 /29）/ `TrustedProxyPrefixAllSpace`（全空间形态）；
 * - `internal/handlers/config_trustedproxy.go` 的 `normalizeTrustedProxyRanges`
 *   （内联网段上限 64 条，裸 IP 由后端补 /32 或 /128）、
 *   `normalizeTrustedProxyHeaders`（请求头条数 ≤8、字符集
 *   `^[A-Za-z0-9-]{1,64}$`）与 `trustedProxyMaxTotalCIDRs`
 *   （内联 + 引用展开 ≤2000）。
 *
 * 后端在 /config/preview 与 PUT /config 才拒绝非法形态，用户拿到的只是
 * 一次全局 toast 且无法定位是哪一条；同仓路径规则编辑器已把「清空即标红、
 * 不等到点保存才被整组拒绝」写成契约，本模块承担同一角色。
 *
 * 方向性约束：前端只在后端**必然拒绝**的形态上报错；不确定的形态一律放行，
 * 由后端兜底（前端误拒比晚失败更糟——会挡住合法配置）。
 */

import { isValidCidr } from './ruleValidation.ts'

/** 允许的最小前缀长度（/29 覆盖 Cloudflare 官方最宽回源段）。
 *  导出供跨栈对表测试与后端 TrustedProxyMinPrefixBits 直接同值比对。 */
export const TRUSTED_PROXY_MIN_PREFIX_BITS = { ipv4: 8, ipv6: 29 } as const

/** 内联网段条数上限（引用名单条目另计，后端总量门为 2000）。
 *  导出供跨栈对表测试与后端 normalizeTrustedProxyRanges 同值比对。 */
export const TRUSTED_PROXY_MAX_INLINE_ENTRIES = 64

/** 请求头条数上限（后端按去重前的原始条数判定）。
 *  导出供跨栈对表测试与后端 normalizeTrustedProxyHeaders 同值比对。 */
export const TRUSTED_PROXY_MAX_HEADERS = 8

/** 请求头名允许的字符集（与后端 trustedProxyHeaderPattern 逐字对齐）。 */
const TRUSTED_PROXY_HEADER_PATTERN = /^[A-Za-z0-9-]{1,64}$/

/** 受信网段总量上限：内联 ∪ 引用展开（与后端 trustedProxyMaxTotalCIDRs 同值）。 */
export const TRUSTED_PROXY_MAX_TOTAL_ENTRIES = 2000

/** 覆盖全部地址空间的形态（等同信任任意来源），逐条对齐后端 PrefixAllSpace。 */
const ALL_SPACE_PREFIXES: readonly string[] = ['0.0.0.0/8', '0.0.0.0/0', '::/0', '::ffff:0.0.0.0/96', '::ffff:0:0/96']

/**
 * 单条目校验：返回空串=通过，否则为可直接展示的原因。
 * 裸 IP 视为 /32 或 /128，宽度恒合法。
 */
export const trustedProxyRangeError = (rawValue: string): string => {
  const value = rawValue.trim()
  if (!value) return '不能为空'
  if (!isValidCidr(value)) return '不是合法的 IP 或 CIDR'
  const [address, bitsText] = value.split('/')
  if (bitsText === undefined) return ''
  const isIpv6 = address.includes(':')
  const minBits = isIpv6 ? TRUSTED_PROXY_MIN_PREFIX_BITS.ipv6 : TRUSTED_PROXY_MIN_PREFIX_BITS.ipv4
  if (ALL_SPACE_PREFIXES.includes(value)) return '覆盖全部地址空间，等同信任任意来源'
  if (Number(bitsText) < minBits) return `最小允许 /${TRUSTED_PROXY_MIN_PREFIX_BITS.ipv4}（IPv4）与 /${TRUSTED_PROXY_MIN_PREFIX_BITS.ipv6}（IPv6）`
  return ''
}

/**
 * 整列表校验：返回空串=全部通过，否则为一条「逐项点名」的汇总文案
 * （保存门与行内提示共用，避免两处文案漂移）。
 */
export const trustedProxyRangesError = (values: readonly string[]): string => {
  const problems = values
    .map((value) => ({ value: value.trim(), error: trustedProxyRangeError(value) }))
    .filter((item) => item.error !== '')
  const parts = problems.map((item) => `${item.value || '(空)'}（${item.error}）`)
  if (values.length > TRUSTED_PROXY_MAX_INLINE_ENTRIES) {
    parts.push(`内联网段最多 ${TRUSTED_PROXY_MAX_INLINE_ENTRIES} 条（当前 ${values.length} 条），超出部分请存为地址列表后引用`)
  }
  return parts.length === 0 ? '' : `受信网段不可用：${parts.join('；')}`
}

/**
 * 单个请求头校验：返回空串=通过。后端按原始值匹配字符集（不去空格），
 * 故这里同样不做 trim——带尾随空格的输入在后端必然 400。
 */
export const trustedProxyHeaderError = (rawValue: string): string =>
  TRUSTED_PROXY_HEADER_PATTERN.test(rawValue) ? '' : '非法请求头名（仅允许字母/数字/连字符，1-64 字符）'

/**
 * 整组请求头校验：空串=通过，否则为「逐项点名」的汇总文案。
 * 条数按原始条数判定（后端先判条数上限、后去重，重复项同样占额度）。
 */
export const trustedProxyHeadersError = (values: readonly string[]): string => {
  const parts = values
    .map((value) => ({ value, error: trustedProxyHeaderError(value) }))
    .filter((item) => item.error !== '')
    .map((item) => `${item.value || '(空)'}（${item.error}）`)
  if (values.length > TRUSTED_PROXY_MAX_HEADERS) {
    parts.push(`最多 ${TRUSTED_PROXY_MAX_HEADERS} 条（当前 ${values.length} 条，重复项也按原始条数计）`)
  }
  return parts.length === 0 ? '' : `受信代理请求头不可用：${parts.join('；')}`
}

/**
 * 总量门：内联 + 引用展开 ≤ 2000（后端内联面与引用面合并判定）。
 *
 * `referencedEntries` 来自 /security/ip-lists 的 entry_count 缓存，列表被他人
 * 改动时可能短暂偏差且缺失按 0 计——只在「已知合计已超限」时拦截（实际值只会
 * 更大），不确定形态交给后端兜底，避免误拒合法配置。
 */
export const trustedProxyTotalError = (inlineCount: number, referencedEntries: number): string => {
  const total = inlineCount + referencedEntries
  if (total <= TRUSTED_PROXY_MAX_TOTAL_ENTRIES) return ''
  return `受信网段总数超过 ${TRUSTED_PROXY_MAX_TOTAL_ENTRIES} 上限（内联 ${inlineCount} + 引用展开 ${referencedEntries} = ${total}），请收窄内联范围或减少引用列表`
}
