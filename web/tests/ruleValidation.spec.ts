// 路径规则校验与后端 rule_features.go 同口径验收
//   自定义上游池：主机形态 / host:port 去重 / http-https 混布
//   同类型查重按后端键（exact 不剥尾 /），跨类型遮蔽仍归一键
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  pathDuplicateKey,
  STATIC_RESPONSE_STATUSES,
  upstreamPathRuleError,
  validatePathRules,
} from '../src/utils/ruleValidation.ts'
import { repoCode, section } from './_helpers.ts'
import { hostPortKey } from '../src/utils/upstreamKeys.ts'

type Upstream = {
  readonly protocol: 'http' | 'https'
  readonly address: string
  readonly port: number
  readonly weight: number
}

const rule = (overrides: Partial<{
  match_type: 'prefix' | 'exact'
  path: string
  upstreams: readonly Upstream[] | null
  upstream_path: string
  response_mode: '' | 'static' | 'redirect' | 'forward'
  response_status: number
  response_body: string
  response_content_type: string
  redirect_to: string
}> = {}) => ({
  match_type: 'prefix' as const,
  path: '/api',
  sort_order: 0,
  upstreams: null,
  ...overrides,
})

const upstream = (overrides: Partial<Upstream> = {}): Upstream => ({
  protocol: 'http',
  address: '10.0.0.1',
  port: 8080,
  weight: 1,
  ...overrides,
})

test('同类型查重：exact /a 与 /a/ 是两条独立 matcher（后端接受）', () => {
  assert.equal(pathDuplicateKey('exact', '/a'), 'exact:/a')
  assert.equal(pathDuplicateKey('exact', '/a/'), 'exact:/a/')
  assert.notEqual(pathDuplicateKey('exact', '/a'), pathDuplicateKey('exact', '/a/'))
  assert.equal(validatePathRules([
    rule({ match_type: 'exact', path: '/a' }),
    rule({ match_type: 'exact', path: '/a/' }),
  ]), null)
  // 完全相同的 exact 仍拒绝
  assert.match(
    String(validatePathRules([rule({ match_type: 'exact', path: '/a' }), rule({ match_type: 'exact', path: '/a ' })])),
    /重复/,
  )
  // prefix 归一键不回归：/api 与 /api/ 同键（* 在 UI 层本身被拒绝，仅键函数单测）
  assert.equal(pathDuplicateKey('prefix', '/api'), pathDuplicateKey('prefix', '/api/*'))
  assert.match(String(validatePathRules([rule({ path: '/api' }), rule({ path: '/api/' })])), /重复/)
  // 跨类型遮蔽仍按归一键检测（exact /a/ 与 prefix /a 同根）
  assert.match(
    String(validatePathRules([rule({ path: '/a' }), rule({ match_type: 'exact', path: '/a/' })])),
    /遮蔽/,
  )
})

test('上游池：非法主机在行内被拒绝（不再放行到后端 400）', () => {
  const invalid = ['bad_host!', '-leading.example.com', 'trailing-.example.com', 'a..b', 'exa mple.com']
  for (const address of invalid) {
    assert.match(
      String(validatePathRules([rule({ upstreams: [upstream({ address })] })])),
      /自定义上游主机/,
      `非法主机 ${address} 必须被前端拒绝`,
    )
  }
  // 合法形态：IPv4 / IPv6 字面量 / 主机名 / Docker 下划线服务名
  for (const address of ['10.0.0.1', '::1', '2001:db8::5', 'api.example.com', 'my_backend']) {
    assert.equal(validatePathRules([rule({ upstreams: [upstream({ address })] })]), null, `${address} 应放行`)
  }
})

test('上游池：host:port 去重（大小写不敏感、IPv6 方括号键）', () => {
  assert.match(
    String(validatePathRules([rule({ upstreams: [upstream(), upstream()] })])),
    /重复/,
  )
  assert.match(
    String(validatePathRules([rule({ upstreams: [upstream({ address: 'API.Example.com' }), upstream({ address: 'api.example.com' })] })])),
    /重复/,
    '主机名大小写不得绕过查重（后端 strings.ToLower(JoinHostPort)）',
  )
  // 同主机不同端口合法
  assert.equal(validatePathRules([rule({ upstreams: [upstream({ port: 8080 }), upstream({ port: 8081 })] })]), null)
  // IPv6 方括号键（upstreamKeys.hostPortKey 分支）：裸拼 ::1:8080 形态
  // 会让前端去重键与后端 net.JoinHostPort（"[::1]:80"）分叉。
  assert.match(
    String(validatePathRules([rule({ upstreams: [upstream({ address: '::1' }), upstream({ address: '::1' })] })])),
    /重复/,
    'IPv6 上游必须按方括号键去重',
  )
  assert.match(
    String(validatePathRules([rule({ upstreams: [upstream({ address: '2001:db8::5', port: 8080 }), upstream({ address: '2001:db8::5', port: 8080 })] })])),
    /重复/,
    'IPv6 同址同端口必须判重',
  )
  // IPv6 同址不同端口合法（键含端口）
  assert.equal(
    validatePathRules([rule({ upstreams: [upstream({ address: '::1', port: 8080 }), upstream({ address: '::1', port: 8081 })] })]),
    null,
  )
  // 键形态本身（与后端 net.JoinHostPort 同形）：方括号分支被删后裸拼
  // `::1:80` 与后端 "[::1]:80" 分叉——直接钉分支输出（纯去重断言两侧同变，
  // 无法发现分支缺失）。
  assert.equal(hostPortKey('::1', 80), '[::1]:80')
  assert.equal(hostPortKey('2001:db8::5', 8080), '[2001:db8::5]:8080')
  assert.equal(hostPortKey('api.example.com', 443), 'api.example.com:443')
})

test('上游池：http/https 混布拒绝（同池 TLS 传输下 http 上游静默全灭）', () => {
  assert.match(
    String(validatePathRules([rule({ upstreams: [upstream({ protocol: 'http' }), upstream({ protocol: 'https', port: 8081 })] })])),
    /混布/,
  )
  assert.equal(validatePathRules([rule({ upstreams: [upstream({ protocol: 'https' }), upstream({ protocol: 'https', port: 8081 })] })]), null)
})

test('上游空/端口/权重校验不回归', () => {
  assert.match(String(validatePathRules([rule({ upstreams: [upstream({ address: '  ' })] })])), /地址不能为空/)
  assert.match(String(validatePathRules([rule({ upstreams: [upstream({ port: 0 })] })])), /端口无效/)
  assert.match(String(validatePathRules([rule({ upstreams: [upstream({ weight: 0 })] })])), /权重必须大于 0/)
  // 无自定义上游（跟随主上游）不进入池校验
  assert.equal(validatePathRules([rule({ upstreams: null })]), null)
  assert.equal(validatePathRules([rule({ upstreams: [] })]), '第 1 条路径至少需要一个自定义上游')
})

test('权重门跨栈同口径：前端 <1 拒绝与后端路径池/主池一致（机械钉）', () => {
  // 前端声称「与后端同口径」曾分叉（前端 <1、后端路径池 <0 放行 0）——
  // 渲染层虽归一为 1，落库 0 会让「权重 0=停用」直觉落空。钉住两侧门槛。
  const frontend = String(validatePathRules([rule({ upstreams: [upstream({ weight: 0 })] })]))
  assert.match(frontend, /权重必须大于 0/, '前端必须拒绝 weight=0')
  // 限段到各自校验函数后断言门表达式，并计「文件内该判据只出现一次」——
  // 全文 includes 在全文件别处新增第二条门时无感（多处门只对表一处）。
  const goPath = section(repoCode('internal/handlers/rule_features.go'), 'func validateRuleFeatures(', '\nfunc ')
  assert.match(goPath, /if upstream\.Weight < 1 \{/, '后端路径池权重门必须为 <1（与前端同口径）')
  assert.equal(
    (goPath.match(/upstream\.Weight < 1/g) ?? []).length,
    1,
    '路径池权重判据在 validateRuleFeatures 内只允许一处',
  )
  const goMain = section(repoCode('internal/handlers/handlers.go'), 'func validateRuleUpstreams(', '\nfunc ')
  assert.match(goMain, /if u\.Weight < 1 \{/, '后端主池权重门必须为 <1')
  assert.equal((goMain.match(/u\.Weight < 1/g) ?? []).length, 1, '主池权重判据在 validateRuleUpstreams 内只允许一处')
})

// ── 直接返回 / 301 跳转 / 上游路径改写 ──
// 这三段是保存前唯一的前端门槛（Rules.vue 保存前调 validatePathRules 给出警告，
// 行内红框复用 pathRuleError/upstreamPathRuleError），文案与后端
// rule_features.go 的 `switch pathRule.ResponseMode` 同口径。此前只有自定义
// 上游池有覆盖，模式相关整块（含上游路径改写）零执行。

test('上游路径改写：空串放行，非空须以 / 开头且不含空格 ? #', () => {
  assert.equal(upstreamPathRuleError(''), null, '空串=原样转发')
  assert.equal(upstreamPathRuleError('/v1/api'), null)
  assert.equal(upstreamPathRuleError('v1/api'), '必须以 / 开头')
  for (const bad of ['/v1 api', '/v1?x=1', '/v1#frag']) {
    assert.equal(upstreamPathRuleError(bad), '不能包含空格 ? # 字符', `${bad} 必须被拒`)
  }
  // 组级入口与行内红框同源：同一判据叠「第 N 条路径：上游路径」前缀
  assert.equal(validatePathRules([rule({ upstream_path: 'v1' })]), '第 1 条路径：上游路径必须以 / 开头')
  assert.equal(validatePathRules([rule({ upstream_path: '/v1', upstreams: [upstream()] })]), null)
})

test('直接返回：状态码白名单与后端同集，响应内容按码点计 64 界值', () => {
  // 前端数组 = 后端 map 键集（双向相等，非抽样）：任一侧增删一个码即红。
  const goBlock = section(repoCode('internal/handlers/rule_features.go'), 'var validStaticResponseStatuses = map[int]bool{', '}')
  const goCodes = [...goBlock.matchAll(/(\d{3}):\s*true/g)].map((m) => Number(m[1])).sort((a, b) => a - b)
  assert.deepEqual(
    [...STATIC_RESPONSE_STATUSES].sort((a, b) => a - b),
    goCodes,
    '前端白名单必须与后端 validStaticResponseStatuses 同集',
  )
  assert.deepEqual(goCodes, [200, 201, 204, 400, 401, 403, 404, 410, 500, 502, 503])

  assert.equal(validatePathRules([rule({ response_mode: 'static' })]), null, '缺省状态码按 200')
  for (const status of STATIC_RESPONSE_STATUSES) {
    assert.equal(
      validatePathRules([rule({ response_mode: 'static', response_status: status })]),
      null,
      `${status} 属常用集合`,
    )
  }
  assert.equal(
    validatePathRules([rule({ response_mode: 'static', response_status: 418 })]),
    '第 1 条路径：直接返回的状态码 418 不在常用集合',
  )
  // 后端用 len([]rune(...))：64 个码点合法、65 拒绝；代理对按 1 个字符算
  assert.equal(validatePathRules([rule({ response_mode: 'static', response_body: 'x'.repeat(64) })]), null)
  assert.equal(
    validatePathRules([rule({ response_mode: 'static', response_body: 'x'.repeat(65) })]),
    '第 1 条路径：响应内容不能超过 64 个字符',
  )
  assert.equal(
    validatePathRules([rule({ response_mode: 'static', response_body: '🙂'.repeat(64) })]),
    null,
    '长度按码点计——代理对不得按 UTF-16 长度算成 128',
  )
})

test('直接返回：响应格式枚举与两处互斥', () => {
  for (const contentType of ['text/plain', 'application/json', 'text/html']) {
    assert.equal(
      validatePathRules([rule({ response_mode: 'static', response_content_type: contentType })]),
      null,
      `${contentType} 合法`,
    )
  }
  assert.equal(
    validatePathRules([rule({ response_mode: 'static', response_content_type: 'text/xml' })]),
    '第 1 条路径：响应格式仅支持纯文本/JSON/HTML',
  )
  assert.equal(
    validatePathRules([rule({ response_mode: 'static', redirect_to: 'https://old.example.com' })]),
    '第 1 条路径：直接返回与跳转地址互斥',
  )
  for (const conflicting of [{ upstream_path: '/v1' }, { upstreams: [upstream()] }]) {
    assert.equal(
      validatePathRules([rule({ response_mode: 'static', ...conflicting })]),
      '第 1 条路径：直接返回模式与上游配置互斥',
    )
  }
})

test('301 跳转：目标必填、控制字符、形状、与响应内容/上游互斥', () => {
  assert.equal(validatePathRules([rule({ response_mode: 'redirect' })]), '第 1 条路径：301 跳转需要填写跳转地址')
  assert.equal(
    validatePathRules([rule({ response_mode: 'redirect', redirect_to: '   ' })]),
    '第 1 条路径：301 跳转需要填写跳转地址',
    '纯空白同样视为未填',
  )
  // 控制字符查原串且先于形状判定（与后端逐 rune 判同位）
  assert.equal(
    validatePathRules([rule({ response_mode: 'redirect', redirect_to: 'https://x.example.com/\x00' })]),
    '第 1 条路径：跳转地址含非法字符',
  )
  assert.equal(
    validatePathRules([rule({ response_mode: 'redirect', redirect_to: 'https://x.example.com/\t' })]),
    '第 1 条路径：跳转地址含非法字符',
  )
  for (const target of ['https://new.example.com', 'http://new.example.com/a', '/relative/path']) {
    assert.equal(
      validatePathRules([rule({ response_mode: 'redirect', redirect_to: target })]),
      null,
      `${target} 合法`,
    )
  }
  for (const target of ['new.example.com', 'ftp://new.example.com', 'https:/new.example.com']) {
    assert.equal(
      validatePathRules([rule({ response_mode: 'redirect', redirect_to: target })]),
      '第 1 条路径：跳转地址须为 http(s):// 绝对地址或 / 开头路径',
      `${target} 形状非法`,
    )
  }
  for (const residue of [{ response_body: 'ok' }, { response_content_type: 'text/plain' }]) {
    assert.equal(
      validatePathRules([rule({ response_mode: 'redirect', redirect_to: '/a', ...residue })]),
      '第 1 条路径：301 跳转与响应内容互斥（请清空内容/格式）',
    )
  }
  for (const conflicting of [{ upstream_path: '/v1' }, { upstreams: [upstream()] }]) {
    assert.equal(
      validatePathRules([rule({ response_mode: 'redirect', redirect_to: '/a', ...conflicting })]),
      '第 1 条路径：301 跳转模式与上游配置互斥',
    )
  }
})

test('response_mode：forward 是 UI 哨兵（等价空串），未知值显式拒绝', () => {
  assert.equal(validatePathRules([rule({ response_mode: 'forward' })]), null)
  assert.equal(validatePathRules([rule({ response_mode: '' })]), null)
  assert.equal(
    validatePathRules([rule({ response_mode: 'forward', upstreams: [upstream()] })]),
    null,
    '哨兵形态仍按转发校验上游池',
  )
  const unknownMode = { ...rule(), response_mode: 'proxy' } as unknown as Parameters<typeof validatePathRules>[0][number]
  assert.equal(validatePathRules([unknownMode]), '第 1 条路径：response_mode 无效')
})

test('自定义上游协议枚举：空串/http/https 之外一律拒绝（h2c 等）', () => {
  const h2c = upstream({ protocol: 'h2c' as unknown as 'http' })
  assert.equal(validatePathRules([rule({ upstreams: [h2c] })]), '第 1 条路径的自定义上游协议只能是 http 或 https')
  assert.equal(validatePathRules([rule({ upstreams: [upstream({ protocol: 'https' })] })]), null)
  const implicit = { ...upstream(), protocol: '' as unknown as 'http' }
  assert.equal(validatePathRules([rule({ upstreams: [implicit] })]), null, '空串=默认 http')
})
