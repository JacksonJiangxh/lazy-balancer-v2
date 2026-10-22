// 事件详情「请求头掩码」名单跨栈同源守卫：后端 securityEventSensitiveHeaderNames
// 是权威（非管理员/只读 Key 的响应在服务端掩码），前端 CTX_SENSITIVE_HEADERS 只
// 决定管理员查看时默认掩码哪些头。两侧任何一边新增都必须同步——名单分裂会让
// 一侧静默漏掩码（第三方凭据头曾长期只有 4 个经典头）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { member, repoSource, source } from './_helpers.ts'

/** Go map 字面量里的头名（小写键）。 */
const backendHeaders = (): string[] => {
  const src = repoSource('internal/handlers/security.go')
  const body = member(src, 'securityEventSensitiveHeaderNames = map[string]struct{}{')
  return [...body.matchAll(/"([^"]+)":/g)].map((m) => m[1])
}

/** 前端 Set 字面量里的头名。 */
const frontendHeaders = (): string[] => {
  const src = source('src/views/security/SecurityEvents.vue')
  const start = src.indexOf('const CTX_SENSITIVE_HEADERS = new Set([')
  assert.notEqual(start, -1, '缺少 CTX_SENSITIVE_HEADERS')
  const open = src.indexOf('[', start)
  const close = src.indexOf('])', open)
  assert.ok(close > open, 'CTX_SENSITIVE_HEADERS 数组边界异常')
  return [...src.slice(open, close).matchAll(/'([^']+)'/g)].map((m) => m[1])
}

test('请求头掩码名单：前后端逐项一致（后端为权威口径）', () => {
  const backend = backendHeaders()
  const frontend = frontendHeaders()
  assert.ok(backend.length >= 4, `后端名单解析异常: ${JSON.stringify(backend)}`)
  assert.deepEqual(
    [...frontend].sort(),
    [...backend].sort(),
    '前端 CTX_SENSITIVE_HEADERS 必须与后端 securityEventSensitiveHeaderNames 逐项一致',
  )
})

test('请求头掩码名单：全部为小写（掩码判定按 strings.ToLower 比对，大小写混写会漏掩）', () => {
  for (const name of [...backendHeaders(), ...frontendHeaders()]) {
    assert.equal(name, name.toLowerCase(), `头名必须小写: ${name}`)
  }
  // 第三方凭据头必须在内（回归：曾被裁到只剩 4 个经典头）
  for (const required of ['x-api-key', 'x-auth-token', 'x-csrf-token', 'x-xsrf-token', 'x-amz-security-token', 'x-goog-api-key']) {
    assert.ok(frontendHeaders().includes(required), `前端名单缺少 ${required}`)
  }
})
