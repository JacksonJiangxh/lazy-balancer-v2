// 事件详情「请求头掩码」名单跨栈同源守卫：后端 securityEventSensitiveHeaderNames
// 是权威（非管理员/只读 Key 的响应在服务端掩码），前端 CTX_SENSITIVE_HEADERS 只
// 决定管理员查看时默认掩码哪些头。两侧任何一边新增都必须同步——名单分裂会让
// 一侧静默漏掩码（第三方凭据头曾长期只有 4 个经典头）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, repoCode } from './_helpers.ts'

/** Go map 字面量里的头名（小写键）。 */
const backendHeaders = (): string[] => {
  // 剥注释视图：注释掉的条目不得计入名单（raw 视图下「注释缩减名单」双绿）。
  const src = repoCode('internal/handlers/security.go')
  const body = member(src, 'securityEventSensitiveHeaderNames = map[string]struct{}{')
  // 解析窗口边界钉：窗口必须起于 map 字面量、止于其闭括号，不得跨到后续声明。
  assert.match(body, /^securityEventSensitiveHeaderNames = map\[string\]struct\{\}\{/, '解析窗口未从 map 字面量起始')
  assert.match(body, /\}\s*$/, '解析窗口未止于 map 闭括号')
  return [...body.matchAll(/"([^"]+)":/g)].map((m) => m[1])
}

/** 前端 Set 字面量里的头名。 */
const frontendHeaders = (): string[] => {
  const src = code('src/views/security/SecurityEvents.vue')
  const startMarker = 'const CTX_SENSITIVE_HEADERS = new Set(['
  const start = src.indexOf(startMarker)
  assert.notEqual(start, -1, '缺少 CTX_SENSITIVE_HEADERS（剥注释视图）')
  const open = start + startMarker.length - 1
  const close = src.indexOf('])', open)
  assert.ok(close > open, 'CTX_SENSITIVE_HEADERS 数组边界异常')
  // 边界钉：窗口必须恰落在 new Set([ … ]) 内——越界会把后续语句里的字符串
  // 当成名单条目（或反向漏掉闭括号前的条目）。
  const window = src.slice(open, close + 2)
  assert.ok(window.startsWith('[') && window.endsWith('])'), `CTX_SENSITIVE_HEADERS 解析窗口越界: ${window.slice(0, 80)}`)
  assert.doesNotMatch(window, /\n\s*(?:const|function|export)\s/, '解析窗口越过 Set 字面量边界')
  return [...window.matchAll(/'([^']+)'/g)].map((m) => m[1])
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
