import { upstreamDedupeKey } from './upstreamKeys.ts'
import { isValidV4, isValidV6 } from './ipAddress.ts'

type PathUpstreamInput = {
  readonly protocol: 'http' | 'https'
  readonly address: string
  readonly port: number
  readonly weight: number
}

type PathRuleInput = {
  readonly match_type: 'prefix' | 'exact'
  readonly path: string
  readonly upstream_path?: string
  readonly sort_order: number
  readonly upstreams: readonly PathUpstreamInput[] | null
  // 直接返回/301 跳转（2026-10-10）：''=转发（现状）/static/redirect
  readonly response_mode?: '' | 'static' | 'redirect' | 'forward'
  readonly response_status?: number
  readonly response_body?: string
  readonly response_content_type?: string
  readonly redirect_to?: string
}
// isValidHostName 与后端 isValidHost（internal/handlers/helpers.go）逐条对齐的
// 主机名校验：标签字符 [A-Za-z0-9_-]、标签首尾须字母或数字、
// 单标签 ≤63、总长 ≤253。前端方向不放宽到 IP 字面量（SNI 语义不需要）。
export const isValidHostName = (value: string): boolean => {
  if (value === '' || value.length > 253) return false
  // 全数字点分串（999.1.1.1、1.2.3.4.5）并非合法 IP，却满足标签字符表：
  // 与后端同口径拒绝，避免前端放行、保存时才被 400 拦下。
  if (value.includes('.') && value.split('.').every((part) => /^\d+$/.test(part))) return false
  return value.split('.').every((part) => {
    if (part === '' || part.length > 63) return false
    if (!/^[A-Za-z0-9_-]+$/.test(part)) return false
    return /^[A-Za-z0-9]/.test(part) && /[A-Za-z0-9]$/.test(part)
  })
}


// 地址/CIDR 解析单源在 utils/ipAddress（写侧严格口径，拒前导零与 %zone）。
// M32：与后端 internal/handlers/rule_features.go:323-350 同源的路径归一键——
// prefix 渲染为 [路径, 路径/*] 双 matcher 故尾部的 / 与 * 一并剥离（Go
// TrimRight cutset 语义），exact 仅剥尾 /；剥空回退 "/"。
export const canonicalPathKey = (matchType: 'prefix' | 'exact', raw: string): string => {
  const trimmed = raw.trim()
  const canonical = matchType === 'prefix' ? trimmed.replace(/[*\/]+$/, '') : trimmed.replace(/\/+$/, '')
  return canonical === '' ? '/' : canonical
}

/**
 * 同类型路径查重键：与后端 rule_features.go 同口径——prefix 用归一键
 * （剥尾 / 与 *），exact 用 trim 后**原串**（不剥尾 /：`/a` 与 `/a/` 是两条独立
 * exact matcher，后端接受并渲染）。跨类型遮蔽互查仍用 canonicalPathKey。
 */
export const pathDuplicateKey = (matchType: 'prefix' | 'exact', raw: string): string =>
  `${matchType}:${matchType === 'prefix' ? canonicalPathKey('prefix', raw) : raw.trim()}`


// 直接返回的状态码白名单：19 码，与后端三处同集（parity 钉测双向核验）。
// 单源自此导出，编辑器下拉只 import，禁在组件侧再抄一份（曾双源：下拉可选但保存被拒）。
// 详见 docs/fork-notes/frontend.md §1
export const STATIC_RESPONSE_STATUSES: readonly number[] = [
  200, 201, 204,
  301, 302, 303, 307, 308,
  400, 401, 403, 404, 405, 410, 429,
  500, 502, 503, 504,
]

export const STATIC_RESPONSE_STATUS_REASONS: Readonly<Record<number, string>> = {
  200: 'OK', 201: 'Created', 204: 'No Content',
  301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 307: 'Temporary Redirect', 308: 'Permanent Redirect',
  400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found',
  405: 'Method Not Allowed', 410: 'Gone', 429: 'Too Many Requests',
  500: 'Internal Server Error', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
}

/** 重定向类状态码判定（3xx）：与后端 services.StaticResponseIsRedirectStatus 同口径。 */
export const isRedirectResponseStatus = (status: number): boolean => status >= 300 && status < 400

/** 响应体是否被允许（204/304 与全部 3xx 不允许，RFC 9110）——与后端同口径。
 *  详见 docs/fork-notes/frontend.md §2
 */
export const isResponseBodyAllowed = (status: number): boolean =>
  status !== 204 && status !== 304 && !isRedirectResponseStatus(status)

/** 响应体长度上限（按码点计），与后端 staticResponseBodyMaxRunes 同值。 */
export const STATIC_RESPONSE_BODY_MAX_RUNES = 4096

/** 跳转目标形状判定——与后端 isValidStaticRedirectTarget 同口径。
 *  详见 docs/fork-notes/frontend.md §3
 */
export const isValidRedirectTargetShape = (target: string): boolean => {
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(target)) return false
  if (/\s/.test(target)) return false
  if (target.startsWith('/')) return true
  const lower = target.toLowerCase()
  return lower.startsWith('http://') || lower.startsWith('https://')
}

const STATIC_RESPONSE_STATUS_SET: Readonly<Record<number, true>> = Object.fromEntries(
  STATIC_RESPONSE_STATUSES.map((code) => [code, true]),
)
/**
 * 上游路径改写单条判定（与后端 validateRuleFeatures 同口径）：空串=原样转发；
 * 非空须以 / 开头且不含空格 ? #（query/fragment 不允许）。路径编辑器与整组
 * 校验共用，避免两处口径漂移。
 */
export const upstreamPathRuleError = (upstreamPath: string): string | null => {
  if (!upstreamPath) return null
  if (!upstreamPath.startsWith('/')) return '必须以 / 开头'
  if (/[\s?#]/.test(upstreamPath)) return '不能包含空格 ? # 字符'
  return null
}

/**
 * 单条路径规则的**字段级**错误（不含行号，也不含整组判定——重复/遮蔽由
 * validatePathRules 负责）。组级校验与行内红框共用此函数：两套实现曾漂移到
 * 「组级拒空串、行级放行空串」，用户清空路径后行内无红框、点保存才整组被拒。
 * 文案不带行号，调用方按需加「第 N 条路径：」前缀（组级）或原样展示（行内）。
 */
export const pathRuleError = (rule: PathRuleInput): string | null => {
  // 与后端同口径：前缀校验用原始串（后端 HasPrefix 在 TrimSpace 之前）
  if (!rule.path.startsWith('/')) return '必须以 / 开头'
  if (/[*?{}]/.test(rule.path)) return '不能包含 * ? { } 通配字符'
  const upstreamError = upstreamPathRuleError(rule.upstream_path ?? '')
  if (upstreamError) return `上游路径${upstreamError}`
  return null
}

export const validatePathRules = (rules: readonly PathRuleInput[]): string | null => {
  const seen = new Map<string, number>()
  // 同后端：prefix 与 exact 在同一路径上并存时，路由按 SortOrder 首条终结
  // 匹配，靠后的一条必被遮蔽成死规则——保存前整组拒绝（跨类型互查）。
  const seenPrefixRoots = new Map<string, number>()
  const seenExactNorms = new Map<string, number>()
  for (const [index, rule] of rules.entries()) {
    const rowNumber = index + 1
    // 字段级错误优先于组级（重复/遮蔽）——与行内红框同一判据、同一文案。
    const fieldError = pathRuleError(rule)
    if (fieldError) return `第 ${rowNumber} 条路径：${fieldError}`
    const canonical = canonicalPathKey(rule.match_type, rule.path)
    const duplicateKey = pathDuplicateKey(rule.match_type, rule.path)
    const seenAt = seen.get(duplicateKey)
    if (seenAt !== undefined) return `第 ${rowNumber} 条路径与第 ${seenAt} 条重复（${rule.path.trim()}）`
    seen.set(duplicateKey, rowNumber)
    if (rule.match_type === 'prefix') {
      const shadowAt = seenExactNorms.get(canonical)
      if (shadowAt !== undefined) return `第 ${rowNumber} 条路径与第 ${shadowAt} 条：同一路径同时存在前缀与精确匹配规则会造成遮蔽，请调整`
      seenPrefixRoots.set(canonical, rowNumber)
    } else {
      const shadowAt = seenPrefixRoots.get(canonical)
      if (shadowAt !== undefined) return `第 ${rowNumber} 条路径与第 ${shadowAt} 条：同一路径同时存在前缀与精确匹配规则会造成遮蔽，请调整`
      seenExactNorms.set(canonical, rowNumber)
    }
    // 直接返回/301 跳转（2026-10-10 用户裁定）：与后端 validateRuleFeatures 同口径
    // 'forward' 为 UI 选择器哨兵（el-select 空串选项不显示标签），与 '' 同义
    const responseMode = rule.response_mode === 'forward' ? '' : (rule.response_mode ?? '')
    if (responseMode === 'static') {
      // 与后端 validateStaticResponseModeFields 逐条同口径同顺序，避免「前端放行、保存 400」。
      // 详见 docs/fork-notes/frontend.md §4
      const status = rule.response_status || 200
      if (!STATIC_RESPONSE_STATUS_SET[status]) return `第 ${rowNumber} 条路径：直接返回的状态码 ${status} 不在常用集合`
      const body = rule.response_body ?? ''
      if (body !== '' && !isResponseBodyAllowed(status)) return `第 ${rowNumber} 条路径：状态码 ${status} 按 RFC 9110 不得携带响应内容（请清空内容）`
      if ([...body].length > STATIC_RESPONSE_BODY_MAX_RUNES) return `第 ${rowNumber} 条路径：响应内容不能超过 ${STATIC_RESPONSE_BODY_MAX_RUNES} 个字符`
      // 放行常规空白（HTML/JSON 多行排版），拒其余控制字符
      // eslint-disable-next-line no-control-regex
      if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(body)) return `第 ${rowNumber} 条路径：响应内容含非法控制字符`
      const ct = rule.response_content_type ?? ''
      if (ct !== '' && ct !== 'text/plain' && ct !== 'application/json' && ct !== 'text/html') return `第 ${rowNumber} 条路径：响应格式仅支持纯文本/JSON/HTML`
      const target = (rule.redirect_to ?? '').trim()
      if (isRedirectResponseStatus(status)) {
        if (!target) return `第 ${rowNumber} 条路径：状态码 ${status} 是重定向，必须填写跳转地址`
        if (!isValidRedirectTargetShape(target)) return `第 ${rowNumber} 条路径：跳转地址须为 http(s):// 绝对地址或 / 开头路径，且不含空格与控制字符`
      } else if (target) {
        // 非 3xx 携带跳转地址属误配：后端显性拒绝，前端同句提示（不静默忽略）
        return `第 ${rowNumber} 条路径：状态码 ${status} 不是重定向，不应填写跳转地址（请清空）`
      }
      if (rule.upstreams !== null || rule.upstream_path) return `第 ${rowNumber} 条路径：直接返回模式与上游配置互斥`
      continue
    }
    if (responseMode === 'redirect') {
      // redirect 恒 301；不读 rule.response_status（切换模式残留值会误伤合法配置）。
      // 详见 docs/fork-notes/frontend.md §5
      const target = rule.redirect_to ?? ''
      if (!target.trim()) return `第 ${rowNumber} 条路径：301 跳转需要填写跳转地址`
      // 形状校验与后端 isValidStaticRedirectTarget 同源（多拒空格）
      if (!isValidRedirectTargetShape(target)) return `第 ${rowNumber} 条路径：跳转地址须为 http(s):// 绝对地址或 / 开头路径，且不含空格与控制字符`
      // 与后端同句——301 跳转与响应内容互斥
      //（UI 正常切换模式会清空内容，此处防回读载荷/残留表单态双携，后端恒 400）。
      if (rule.response_body || rule.response_content_type) return `第 ${rowNumber} 条路径：301 跳转与响应内容互斥（请清空内容/格式）`
      if (rule.upstreams !== null || rule.upstream_path) return `第 ${rowNumber} 条路径：301 跳转模式与上游配置互斥`
      continue
    }
    if (responseMode) return `第 ${rowNumber} 条路径：response_mode 无效`
    if (rule.upstreams === null) continue
    if (rule.upstreams.length === 0) return `第 ${rowNumber} 条路径至少需要一个自定义上游`

    // 自定义上游池：与后端 rule_features.go 同口径的三项池级
    // 校验——http/https 混布（同池 reverse_proxy 池级 TLS 传输下 http 上游静默
    // 全灭）、主机形态（后端 isValidHost：IP 字面量或主机名）、host:port 去重
    // （重复条使权重翻倍、均衡语义静默漂移）。此前只校验空/端口/权重，非法行
    // 行内无错、点保存才被全局 toast 拒绝且不定位到行。
    const poolProtocols = new Set(rule.upstreams.map((upstream) => (upstream.protocol || 'http')))
    if (poolProtocols.has('http') && poolProtocols.has('https')) {
      return `第 ${rowNumber} 条路径的自定义上游 http/https 混布（同一上游池协议须一致）`
    }
    const seenHostPorts = new Set<string>()
    for (const upstream of rule.upstreams) {
      const address = upstream.address.trim()
      if (!address) return `第 ${rowNumber} 条路径的自定义上游地址不能为空`
      // 上游地址接受 IP 字面量与主机名（isValidHostName 有意排除 IP 字面量——
      // SNI 语义不需要，上游地址需要），与后端 isValidHost 同形。
      if (!(isValidV4(address) || isValidV6(address) || isValidHostName(address))) {
        return `第 ${rowNumber} 条路径的自定义上游主机「${address}」无效`
      }
      if (upstream.port < 1 || upstream.port > 65535) return `第 ${rowNumber} 条路径的自定义上游端口无效`
      const protocol = (upstream.protocol ?? '') as string
      if (protocol !== '' && protocol !== 'http' && protocol !== 'https') {
        return `第 ${rowNumber} 条路径的自定义上游协议只能是 http 或 https`
      }
      if (upstream.weight < 1) return `第 ${rowNumber} 条路径的自定义上游权重必须大于 0`
      // 与后端 upstreamDedupeHost 同口径：IP 按地址语义归一（IPv6 等价写法
      // 是同一后端），主机名 lower+trim；后端写侧是权威门。
      const hostPort = upstreamDedupeKey(address, upstream.port)
      if (seenHostPorts.has(hostPort)) return `第 ${rowNumber} 条路径的自定义上游 ${hostPort} 重复`
      seenHostPorts.add(hostPort)
    }
  }
  return null
}

// ── 数值边界单源（表单控件 ↔ 后端写侧门）──
// 控件边界此前各自写死且与写侧门漂移（间隔 min 5 vs 后端 ≥1、超时 max 30 vs
// 后端无上限、重试间隔 max 10000 vs 后端 60000、最大连接 max 100000 vs 后端
// 无上限）——API/MCP/导入写入的合法值在向导中被 spinner 静默夹回 UI 边界。
// 后端口径：internal/handlers/handlers.go（间隔/超时 ≥1，无上限）、
// rule_features.go（重试窗口/间隔 [-1|0, 60000]）、max_connections ≥0 无上限。
// el-input-number 只在交互（spinner/输入失焦）时夹紧，库值超界回显不被改写。
export const RULE_NUMERIC_LIMITS = {
  healthCheckIntervalMin: 1,
  healthCheckTimeoutMin: 1,
  tcpTryIntervalMax: 60000,
  maxConnectionsMin: 0,
} as const

// ── TLS 透传（JJC-20261112-01 S3 前端接入）──
// 以下三个判定与后端 internal/handlers/rule_features.go 的 validateSNIDomain /
// validatePassthroughRule 上游门 / sniDomainsOverlap 逐条同口径同顺序
// （本仓 docs/fork-notes/ 未设本节台账，后端源码即对表单源；行内注释逐条
// 标注对应 Go 行为，防两端口径漂移——纪律：前端放行、保存 400 不允许）。

/** SNI 域名归一：TrimSpace + 小写（与 validatePassthroughRule 入口归一同形）。 */
export const normalizeSNIDomain = (raw: string): string => raw.trim().toLowerCase()

// 输入须已经 normalizeSNIDomain 归一（与后端约定一致：调用方统一归一后传入）。
// 字节长度口径：Go len() 是字节数，非 ASCII 由标签字母表门拒绝，此处仍按
// 字节计（TextEncoder）保持逐条同形。
export const sniDomainError = (domain: string): string | null => {
  if (domain === '') return 'SNI 域名不能为空'
  // 后端 ContainsAny(domain, " \t\r\n")
  if (/[ \t\r\n]/.test(domain)) return `SNI 域名 ${JSON.stringify(domain)} 不能包含空白字符`
  // 后端逐 rune 拒 <0x20 或 0x7f
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(domain)) return `SNI 域名 ${JSON.stringify(domain)} 含非法控制字符`
  if (domain.includes(':')) return `SNI 域名 ${JSON.stringify(domain)} 不能包含端口尾缀（SNI 匹配按域名进行，不带端口）`
  if (domain.endsWith('.')) return `SNI 域名 ${JSON.stringify(domain)} 不能以点结尾`
  // IP 字面量拒绝（Layer4 按 ClientHello SNI 匹配，IP 直连不携带 SNI）。
  // import 单源 utils/ipAddress（写侧严格口径），与 net.ParseIP 同收:
  // 前导零/zone 后缀该口径均拒——从严方向与后端一致。
  if (isValidV4(domain) || isValidV6(domain)) {
    return `SNI 域名 ${JSON.stringify(domain)} 是 IP 字面量——Layer4 按 ClientHello 的 SNI（域名）分流，IP 直连不携带 SNI，请改用域名`
  }
  if (domain.length > 253) return `SNI 域名长度不能超过 253 字符（当前 ${domain.length}）`
  const labels = domain.split('.')
  let rest = labels
  if (labels[0] === '*') {
    // * 独占最左标签后至少保留两级域名（*.example.com）
    if (labels.length < 3) return `通配 SNI 域名 ${JSON.stringify(domain)} 无效（* 后至少须保留两级域名，如 *.example.com）`
    rest = labels.slice(1)
  } else if (domain.includes('*')) {
    return `SNI 域名 ${JSON.stringify(domain)} 的 * 只能作为最左标签整体出现（如 *.example.com）`
  }
  for (const label of rest) {
    if (label === '') return `SNI 域名 ${JSON.stringify(domain)} 含空标签`
    if (label.length > 63) return `SNI 域名 ${JSON.stringify(domain)} 的标签超长（每段 ≤63 字符）`
    // 后端字节 alphabet：小写字母/数字开头结尾，主体仅字母/数字/连字符
    //（输入已小写化，大写字母在后端同样非法——归一在前端调用点完成）。
    if (!/^[a-z0-9]$/.test(label[0]) || !/^[a-z0-9]$/.test(label[label.length - 1])) {
      return `SNI 域名 ${JSON.stringify(domain)} 的标签只能以字母或数字开头/结尾`
    }
    if (!/^[a-z0-9-]+$/.test(label)) {
      return `SNI 域名 ${JSON.stringify(domain)} 含非法字符（仅支持字母/数字/连字符）`
    }
  }
  return null
}

/**
 * 透传保存门第①段（必填/单值/形状，与 validatePassthroughRule 开头同序）：
 * 空值与逗号列表在形状校验之前拦截（后端同序）。
 */
export const passthroughSniError = (rawDomain: string): string | null => {
  const domain = normalizeSNIDomain(rawDomain)
  if (domain === '') return '透传规则的 SNI 域名必填（Layer4 按 ClientHello 的 SNI 分流）'
  if (domain.includes(',')) {
    return `透传规则的 SNI 域名只支持单个域名（当前 ${JSON.stringify(domain)}）——多条 SNI 请拆分为多条透传规则`
  }
  return sniDomainError(domain)
}

/**
 * 透传上游 host:port 校验（与 validatePassthroughRule 上游门逐条同口径）：
 * SplitHostPort 形态（host:port / [v6]:port；不带方括号的多冒号串与后端
 * 同样拒绝）、端口 1-65535、主机为 IP 字面量或主机名（isValidHost 同形，
 * 消费 utils/ipAddress 与 isValidHostName 单源）。
 */
export const passthroughUpstreamError = (rawUpstream: string): string | null => {
  const upstream = rawUpstream.trim()
  if (upstream === '') {
    return '透传上游地址必填（host:port 形态，passthrough_upstream）——上游自带反代与证书，本系统只做字节流转发'
  }
  const lastColon = upstream.lastIndexOf(':')
  if (lastColon < 0) {
    return `透传上游地址 ${JSON.stringify(upstream)} 无效：须为 host:port 形态（passthrough_upstream）`
  }
  let host = upstream.slice(0, lastColon)
  const portText = upstream.slice(lastColon + 1)
  if (host.startsWith('[')) {
    // [v6]:port —— 剥方括号后按 IP 字面量校验
    if (!host.endsWith(']')) {
      return `透传上游地址 ${JSON.stringify(upstream)} 无效：须为 host:port 形态（passthrough_upstream）`
    }
    host = host.slice(1, -1)
  } else if (host.includes(':')) {
    // 与 Go net.SplitHostPort 同拒：不带方括号的多冒号串（::1:10443）
    return `透传上游地址 ${JSON.stringify(upstream)} 无效：须为 host:port 形态（passthrough_upstream）`
  }
  const port = Number(portText)
  if (!/^\d+$/.test(portText) || !Number.isInteger(port) || port < 1 || port > 65535) {
    return `透传上游地址 ${JSON.stringify(upstream)} 的端口无效（须为 1-65535 的整数）`
  }
  const trimmedHost = host.trim()
  if (trimmedHost === '' || !(isValidV4(trimmedHost) || isValidV6(trimmedHost) || isValidHostName(trimmedHost))) {
    return `透传上游地址 ${JSON.stringify(upstream)} 的主机无效`
  }
  return null
}

/**
 * 两个规范化（小写、TrimSpace 后）SNI 域名是否可能命中同一 ClientHello——
 * 与后端 sniDomainsOverlap 逐条同口径：精确相等，或一方为通配且另一方落在
 * 其覆盖域内（保守多级覆盖：*.a.com 同时视为覆盖 b.a.com 与 c.b.a.com）。
 */
export const sniDomainsOverlap = (a: string, b: string): boolean => {
  if (a === b) return true
  const aWildcard = a.startsWith('*.')
  const bWildcard = b.startsWith('*.')
  if (aWildcard && bWildcard) {
    const aBase = a.slice(2)
    const bBase = b.slice(2)
    return bBase.endsWith(`.${aBase}`) || aBase.endsWith(`.${bBase}`)
  }
  if (aWildcard) {
    const base = a.slice(2)
    return b === base || b.endsWith(`.${base}`)
  }
  if (bWildcard) {
    const base = b.slice(2)
    return a === base || a.endsWith(`.${base}`)
  }
  return false
}

/** passthroughSaveGateError 输入（existingRules 供行内冲突提示，可省略）。 */
interface PassthroughGateInput {
  readonly domain: string
  readonly upstream: string
  readonly listenPort: number
  readonly httpsPort: number
}

/**
 * 透传保存门前三段组合（与 validatePassthroughRule 同序）：SNI 必填/单值/形状
 * → 上游 host:port → 监听端口跟随部署 HTTPS 默认口。返回 '' 表示通过；
 * 冲突双门（同端口同 SNI / 与本地终结域名冲突）依赖规则面板数据，由
 * Rules.vue 的 passthroughConflictWarning 单独承担。
 */
export const passthroughSaveGateError = (input: PassthroughGateInput): string => {
  const sniError = passthroughSniError(input.domain)
  if (sniError) return sniError
  const upstreamError = passthroughUpstreamError(input.upstream)
  if (upstreamError) return upstreamError
  if (input.listenPort !== input.httpsPort) {
    return `透传规则监听端口必须为部署侧 HTTPS 默认口 ${input.httpsPort}（当前 ${input.listenPort}；第一期透传仅在 HTTPS 默认口做 SNI 分流）`
  }
  return ''
}
