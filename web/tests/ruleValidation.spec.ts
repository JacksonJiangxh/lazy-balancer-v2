// 路径规则校验与后端 rule_features.go 同口径验收（历史修复）：
//   历史问题-06 自定义上游池：主机形态 / host:port 去重 / http-https 混布
//   历史问题-07 同类型查重按后端键（exact 不剥尾 /），跨类型遮蔽仍归一键
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { pathDuplicateKey, validatePathRules } from '../src/utils/ruleValidation.ts'

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

test('历史问题-07 同类型查重：exact /a 与 /a/ 是两条独立 matcher（后端接受）', () => {
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

test('历史问题-06 上游池：非法主机在行内被拒绝（不再放行到后端 400）', () => {
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

test('历史问题-06 上游池：host:port 去重（大小写不敏感、IPv6 方括号键）', () => {
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
})

test('历史问题-06 上游池：http/https 混布拒绝（同池 TLS 传输下 http 上游静默全灭）', () => {
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
