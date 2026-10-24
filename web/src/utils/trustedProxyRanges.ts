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
 * 总量门：内联 ∪ 引用展开 ≤ 2000（与后端 `trustedProxyTotalGate` 同口径）。
 *
 * 后端按「规范化前缀集合大小」判定——同一网段既内联又出现在引用名单时只计
 * 一次；按条目数累加会把实际展开集合远小于上限的合法载荷拒掉。引用面的条目
 * 原文来自 `GET /security/ip-lists/:id`（`values`）；尚未拉取或拉取失败时
 * （`null`）退回 `entryCount`（列表接口缓存的条数）估算——只在「已知合计已
 * 超限」时拦截，不确定形态交给后端兜底，避免误拒合法配置。
 */
export interface TrustedProxyReferencedEntries {
  /** 名单条目原文；null = 尚未拉取或拉取失败（按 entryCount 计入且无法去重）。 */
  readonly values: readonly string[] | null
  /** 列表条数缓存（/security/ip-lists 的 entry_count）；values 已知时忽略。 */
  readonly entryCount: number
}

/** 展开规模（并集口径）。referenced 含与内联重叠的键，与后端错误文案同构。 */
export interface TrustedProxyExpansion {
  readonly union: number
  readonly inline: number
  readonly referenced: number
  /** 未能去重、按 entryCount 计入的条数（>0 时文案须声明为估算）。 */
  readonly unresolved: number
}

const ipv4Octets = (address: string): readonly number[] | null => {
  const parts = address.split('.')
  if (parts.length !== 4) return null
  const octets = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : Number.NaN))
  return octets.some((octet) => !Number.isInteger(octet) || octet > 255) ? null : octets
}

/** IPv6 地址 → 8 个十六进制组（小写、去前导零）；无法解析返回 null。
 *  内嵌 IPv4 尾（`::ffff:1.2.3.4`）按 32 位折算成两个组——使同一地址的不同
 *  书写形态落到同一键上（后端 netip 解析后同样视为同一 Addr）。 */
const ipv6Groups = (address: string): readonly number[] | null => {
  const text = address.trim().toLowerCase()
  if (!text.includes(':')) return null
  const lastColon = text.lastIndexOf(':')
  let normalized = text
  if (text.slice(lastColon + 1).includes('.')) {
    const octets = ipv4Octets(text.slice(lastColon + 1))
    if (!octets) return null
    const high = ((octets[0] ?? 0) << 8) | (octets[1] ?? 0)
    const low = ((octets[2] ?? 0) << 8) | (octets[3] ?? 0)
    normalized = `${text.slice(0, lastColon + 1)}${high.toString(16)}:${low.toString(16)}`
  }
  const doubleColon = normalized.indexOf('::')
  let groupsText: readonly string[]
  if (doubleColon >= 0) {
    if (normalized.indexOf('::', doubleColon + 1) >= 0) return null
    const left = normalized.slice(0, doubleColon)
    const right = normalized.slice(doubleColon + 2)
    const leftGroups = left === '' ? [] : left.split(':')
    const rightGroups = right === '' ? [] : right.split(':')
    const missing = 8 - leftGroups.length - rightGroups.length
    if (missing < 0) return null
    groupsText = [...leftGroups, ...Array.from({ length: missing }, () => '0'), ...rightGroups]
  } else {
    groupsText = normalized.split(':')
  }
  if (groupsText.length !== 8) return null
  const groups = groupsText.map((group) => (/^[0-9a-f]{1,4}$/.test(group) ? Number.parseInt(group, 16) : Number.NaN))
  return groups.some((group) => Number.isNaN(group)) ? null : groups
}

/**
 * 规范化前缀键（裸 IP 补 /32 或 /128）：只用于前端并集判定，故不必逐字等于
 * Go 的 `netip.Prefix.String()`——只需让**同一地址的同一前缀**落到同一键上。
 * 无法解析返回 null（非法形态由网段判据逐条点名，这里不计入并集）。
 */
export const trustedProxyPrefixKey = (rawValue: string): string | null => {
  const value = rawValue.trim()
  if (!value) return null
  const slash = value.indexOf('/')
  const address = slash < 0 ? value : value.slice(0, slash)
  const bitsText = slash < 0 ? '' : value.slice(slash + 1)
  const v4 = ipv4Octets(address)
  if (v4) {
    const bits = bitsText === '' ? 32 : Number(bitsText)
    if (!Number.isInteger(bits) || bits < 0 || bits > 32) return null
    return `v4:${v4.join('.')}/${bits}`
  }
  const v6 = ipv6Groups(address)
  if (!v6) return null
  const bits = bitsText === '' ? 128 : Number(bitsText)
  if (!Number.isInteger(bits) || bits < 0 || bits > 128) return null
  return `v6:${v6.join(':')}/${bits}`
}

/** 受信网段展开规模：内联 ∪ 引用展开（规范化前缀去重），与后端判定同口径。 */
export const trustedProxyExpansion = (
  inlineValues: readonly string[],
  referenced: readonly TrustedProxyReferencedEntries[],
): TrustedProxyExpansion => {
  const union = new Set<string>()
  for (const value of inlineValues) {
    const key = trustedProxyPrefixKey(value)
    if (key) union.add(key)
  }
  const inline = union.size
  let referencedKeys = 0
  let unresolved = 0
  for (const ref of referenced) {
    if (ref.values === null) {
      unresolved += Math.max(0, ref.entryCount)
      continue
    }
    const keys = new Set<string>()
    for (const value of ref.values) {
      const key = trustedProxyPrefixKey(value)
      if (key) keys.add(key)
    }
    referencedKeys += keys.size
    for (const key of keys) union.add(key)
  }
  return { union: union.size + unresolved, inline, referenced: referencedKeys + unresolved, unresolved }
}

/** 总量门：返回空串=通过，否则为可直接展示的汇总文案（与后端文案同结构）。 */
export const trustedProxyTotalError = (
  inlineValues: readonly string[],
  referenced: readonly TrustedProxyReferencedEntries[],
): string => {
  const { union, inline, referenced: referencedCount, unresolved } = trustedProxyExpansion(inlineValues, referenced)
  if (union <= TRUSTED_PROXY_MAX_TOTAL_ENTRIES) return ''
  const estimate = unresolved > 0
    ? `；其中 ${unresolved} 条按条数估算（引用名单条目未加载，重叠网段未参与去重）`
    : ''
  return `受信网段总数超过 ${TRUSTED_PROXY_MAX_TOTAL_ENTRIES} 上限（去重后合计 ${union}：内联 ${inline} + 引用展开 ${referencedCount}；重叠网段只计一次${estimate}），请收窄内联网段或减少引用列表`
}
