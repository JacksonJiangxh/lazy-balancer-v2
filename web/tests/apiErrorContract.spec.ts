// 业务码 / HTTP 状态同值契约（前端按 status 分类的前提）。
//
// 前端响应拦截器的业务码失败分支把 **HTTP status** 装进 ApiRequestError
// （api.ts 内注释即契约）：调用方按 `status === 409` 之类分类（如
// useLibUpdateDialog）——若后端出现「HTTP 200 + code≠0」或状态与业务码不同值，
// 分类与重试逻辑会静默绕过。本 spec 双向钉住：
//   ① 前端确实携带 response.status（源码钉）；
//   ② 后端所有 `http.StatusXXX, ...{Code: NNN}` 形态的 NNN 与状态名同义
//      （全仓 handlers 非测试文件机械扫描）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'

import { repoSource, section, source } from './_helpers.ts'

/** handlers 非测试 Go 文件（目录扫描，不手抄清单——新增 handler 自动纳入）。 */
const handlerFiles = (): string[] => readdirSync(new URL('../../internal/handlers/', import.meta.url))
  .filter((name) => name.endsWith('.go') && !name.endsWith('_test.go'))
  .map((name) => `internal/handlers/${name}`)

const STATUS_CODES: Record<string, number> = {
  BadRequest: 400,
  Unauthorized: 401,
  Forbidden: 403,
  NotFound: 404,
  MethodNotAllowed: 405,
  Conflict: 409,
  StatusRequestEntityTooLarge: 413,
  UnprocessableEntity: 422,
  PreconditionRequired: 428,
  TooManyRequests: 429,
  InternalServerError: 500,
  StatusBadGateway: 502,
  ServiceUnavailable: 503,
  StatusGatewayTimeout: 504,
}

test('前端业务码失败分支携带 HTTP status（api.ts 契约）', () => {
  const api = source('src/utils/api.ts')
  const branch = section(api, 'if (res.code !== undefined && res.code !== 0 && res.code !== 200) {', 'return res')
  assert.match(branch, /new ApiRequestError\(res\.message \|\| '请求失败', response\.status\)/, '必须携带 response.status')
  assert.doesNotMatch(branch, /new ApiRequestError\([^)]*,\s*res\.code\)/, '不得改携带业务码（调用方按 status 分类）')
})

test('后端不存在「HTTP 200 + 非零业务码」形态', () => {
  for (const file of handlerFiles()) {
    const go = repoSource(file)
    assert.doesNotMatch(
      go,
      /http\.StatusOK,\s*(?:models\.APIResponse|gin\.H)\{Code:\s*[1-9]/,
      `${file}：HTTP 200 配非零业务码——前端按 status 分类会漏判`,
    )
  }
})

test('后端状态名与业务码同值（机械扫描 handlers 非测试文件）', () => {
  const mismatched: string[] = []
  let pairs = 0
  for (const file of handlerFiles()) {
    const go = repoSource(file)
    // 两种载荷形态：models.APIResponse{Code: N} 与 gin.H{"code": N}
    for (const match of go.matchAll(/http\.Status([A-Za-z]+),\s*(?:models\.APIResponse\{Code:|gin\.H\{"code":)\s*(\d+)/g)) {
      const expected = STATUS_CODES[match[1]]
      if (expected === undefined) continue
      pairs += 1
      if (Number(match[2]) !== expected) mismatched.push(`${file}: Status${match[1]} 配 Code ${match[2]}`)
    }
  }
  assert.ok(pairs > 10, `扫描到的状态/业务码配对过少（${pairs}）——正则或被改坏`)
  assert.deepEqual(mismatched, [], '状态名与业务码不同值——前端按 status 分类会误判')
})
