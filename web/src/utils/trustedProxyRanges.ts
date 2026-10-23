/**
 * 受信代理网段（CDN 回源 CIDR）的行内校验，与后端判据单源：
 *
 * - `internal/services/caddy.go` 的 `TrustedProxyMinPrefixBits`（IPv4 /8、
 *   IPv6 /29）/ `TrustedProxyPrefixAllSpace`（全空间形态）；
 * - `internal/handlers/config_trustedproxy.go` 的 `normalizeTrustedProxyRanges`
 *   （内联网段上限 64 条，裸 IP 由后端补 /32 或 /128）。
 *
 * 后端在 /config/preview 与 PUT /config 才拒绝非法/过宽条目，用户拿到的只是
 * 一次全局 toast 且无法定位是哪一条；同仓路径规则编辑器已把「清空即标红、
 * 不等到点保存才被整组拒绝」写成契约，本模块承担同一角色。
 *
 * 方向性约束：前端只在后端**必然拒绝**的形态上报错；不确定的形态一律放行，
 * 由后端兜底（前端误拒比晚失败更糟——会挡住合法配置）。
 */

import { isValidCidr } from './ruleValidation.ts'

/** 允许的最小前缀长度（/29 覆盖 Cloudflare 官方最宽回源段）。 */
export const TRUSTED_PROXY_MIN_PREFIX_BITS = { ipv4: 8, ipv6: 29 } as const

/** 内联网段条数上限（引用名单条目另计，后端总量门为 2000）。 */
export const TRUSTED_PROXY_MAX_INLINE_ENTRIES = 64

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
