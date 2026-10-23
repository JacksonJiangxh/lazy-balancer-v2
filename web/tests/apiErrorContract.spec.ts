// 业务码 / HTTP 状态同值契约（前端按 status 分类的前提）。
//
// 前端响应拦截器的业务码失败分支把 **HTTP status** 装进 ApiRequestError
// （api.ts 内注释即契约）：调用方按 `status === 409` 之类分类（如
// useLibUpdateDialog）——若后端出现「HTTP 200 + code≠0」或状态与业务码不同值，
// 分类与重试逻辑会静默绕过。本 spec 双向钉住：
//   ① 前端确实携带 response.status（源码钉）；
//   ② 后端信封（handlers + middleware）每条响应的业务码与 HTTP 状态同义
//      （机械扫描全部非测试文件）。
//
// 扫描必须「零跳过」：状态名未登记、业务码写成非常量（http.StatusX 之外的形态）
// 都算失败——否则一条查不到映射的配对会被 continue 静默跳过，守卫假绿。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync } from 'node:fs'

import { repoSource, section, source } from './_helpers.ts'

/** 生产同一响应信封的目录（前端拦截器对两者一视同仁）。 */
const SCAN_DIRS = ['internal/handlers', 'internal/middleware'] as const

/** 目录内非测试 Go 文件（目录扫描，不手抄清单——新增文件自动纳入）。 */
const goFiles = (dir: (typeof SCAN_DIRS)[number]): string[] => readdirSync(new URL(`../../${dir}/`, import.meta.url))
  .filter((name) => name.endsWith('.go') && !name.endsWith('_test.go'))
  .map((name) => `${dir}/${name}`)

/** 状态名 → 数值。键名与 `http.Status<Name>` 的后缀逐字相同（不得带 Status 前缀）。 */
const HTTP_STATUS: Record<string, number> = {
  OK: 200,
  Created: 201,
  Accepted: 202,
  NoContent: 204,
  BadRequest: 400,
  Unauthorized: 401,
  Forbidden: 403,
  NotFound: 404,
  MethodNotAllowed: 405,
  Conflict: 409,
  RequestEntityTooLarge: 413,
  UnprocessableEntity: 422,
  PreconditionRequired: 428,
  TooManyRequests: 429,
  InternalServerError: 500,
  BadGateway: 502,
  ServiceUnavailable: 503,
  GatewayTimeout: 504,
}

// 两种信封形态（models.APIResponse{Code: N} 与 gin.H{"code": N}）都真实存在；
// 业务码既可能是整数字面量，也可能是 `http.StatusX` 符号（实测 20 处）。
// `\s*` 跨换行：`models.APIResponse{\n\tCode: …` 是仓内惯用多行写法。
const ENVELOPE = /http\.Status([A-Za-z]+),\s*(?:models\.APIResponse\{\s*Code:|gin\.H\{\s*"code":)\s*(?:http\.Status([A-Za-z]+)|(\d+))/g

// 宽口径：只认「信封 + code 键」的头，不要求业务码可解析。用于交叉核对窄正则
// 没有漏掉任何一条信封响应（漏掉即无法参与同值断言）。
const ENVELOPE_HEAD = /http\.Status([A-Za-z]+),\s*(?:models\.APIResponse\{|gin\.H\{\s*"(?:code|Code)"\s*:)/g

interface Envelope {
  status: string
  /** 整数字面量或 http.StatusX 的状态名 */
  code: string
}

const envelopes = (go: string): Envelope[] =>
  [...go.matchAll(ENVELOPE)].map((match) => ({ status: match[1], code: match[2] ?? match[3] }))

/**
 * 业务码与 HTTP 状态是否同义。2xx 是成功信封（业务码 0；200 与前端
 * `code !== 200` 判据等价），其余状态必须逐值相同，调用方的 status 分支才成立。
 * 返回 undefined 表示状态名/业务码形态未登记（不可判，必须显式失败）。
 */
const pairConsistent = (pair: Envelope): boolean | undefined => {
  const httpStatus = HTTP_STATUS[pair.status]
  if (httpStatus === undefined) return undefined
  const value = /^\d+$/.test(pair.code) ? Number(pair.code) : HTTP_STATUS[pair.code]
  if (value === undefined) return undefined
  return httpStatus < 300 ? value === 0 || value === 200 : value === httpStatus
}

test('前端业务码失败分支携带 HTTP status（api.ts 契约）', () => {
  const api = source('src/utils/api.ts')
  const branch = section(api, 'if (res.code !== undefined && res.code !== 0 && res.code !== 200) {', 'return res')
  assert.match(branch, /new ApiRequestError\(res\.message \|\| '请求失败', response\.status\)/, '必须携带 response.status')
  assert.doesNotMatch(branch, /new ApiRequestError\([^)]*,\s*res\.code\)/, '不得改携带业务码（调用方按 status 分类）')
})

test('扫描器形态自测：同行/多行、两种信封、符号业务码都命中，非信封不命中', () => {
  const fixtures = [
    'c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "x"})',
    'c.JSON(http.StatusBadGateway, models.APIResponse{\n\t\tCode: 502,\n\t\tMessage: "x",\n\t})',
    'c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "message": "x"})',
    'c.JSON(http.StatusConflict, gin.H{\n\t\t"code": 409,\n\t})',
    'c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "x"})',
    'c.JSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest})',
  ]
  for (const fixture of fixtures) {
    assert.equal(envelopes(fixture).length, 1, `扫描器漏形态：${fixture}`)
  }
  assert.deepEqual(envelopes(fixtures[4]), [{ status: 'Conflict', code: 'Conflict' }], '符号业务码必须解出状态名')
  // 非信封载荷（登录响应、服务层结构体、自定义 gin.H 键）不参与同值契约
  assert.equal(envelopes('c.JSON(http.StatusOK, models.LoginResponse{Token: t})').length, 0)
  assert.equal(envelopes('c.JSON(http.StatusOK, gin.H{"status": "ok"})').length, 0)
})

test('后端信封：每条业务码与 HTTP 状态同义（handlers + middleware 全量）', () => {
  const mismatched: string[] = []
  const unparsed: string[] = []
  const unknown: string[] = []
  let pairs = 0
  let heads = 0
  for (const dir of SCAN_DIRS) {
    for (const file of goFiles(dir)) {
      const go = repoSource(file)
      const declared = [...go.matchAll(ENVELOPE_HEAD)].length
      const parsed = envelopes(go)
      heads += declared
      pairs += parsed.length
      if (declared !== parsed.length) unparsed.push(`${file}: 信封 ${declared} 条，解析出 ${parsed.length} 条`)
      for (const pair of parsed) {
        const verdict = pairConsistent(pair)
        if (verdict === undefined) unknown.push(`${file}: Status${pair.status} 配 Code ${pair.code}`)
        else if (!verdict) mismatched.push(`${file}: Status${pair.status} 配 Code ${pair.code}`)
      }
    }
  }
  assert.ok(pairs > 1000, `扫描到的状态/业务码配对过少（${pairs}）——正则或被改坏`)
  assert.deepEqual(unparsed, [], `存在业务码不可解析的信封响应（${heads} 条信封共解析 ${pairs} 条）`)
  assert.deepEqual(unknown, [], '存在未登记的状态名或业务码形态——不可判定就必须显式失败，不得静默跳过')
  assert.deepEqual(mismatched, [], '状态与业务码不同义——前端按 status 分类会误判')
})

test('负断言形态：HTTP 200/201 配非零非 200 业务码必须被同值契约判为不同值', () => {
  for (const fixture of [
    'c.JSON(http.StatusOK, models.APIResponse{Code: 500})',
    'c.JSON(http.StatusOK, gin.H{"code": 500})',
    'c.JSON(http.StatusOK, models.APIResponse{\n\tCode: 500,\n})',
    'c.JSON(http.StatusCreated, models.APIResponse{Code: 400})',
    'c.JSON(http.StatusBadRequest, models.APIResponse{Code: http.StatusConflict})',
  ]) {
    const [pair] = envelopes(fixture)
    assert.ok(pair, `扫描器漏形态：${fixture}`)
    assert.equal(pairConsistent(pair), false, `守卫必须判定为不同值：${fixture}`)
  }
  // 合法形态（成功信封 0 / 状态同值 / 符号同值）
  for (const fixture of [
    'c.JSON(http.StatusOK, models.APIResponse{Code: 0})',
    'c.JSON(http.StatusCreated, models.APIResponse{Code: 0})',
    'c.JSON(http.StatusConflict, models.APIResponse{Code: 409})',
    'c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict})',
  ]) {
    assert.equal(pairConsistent(envelopes(fixture)[0]), true, `守卫误报：${fixture}`)
  }
  // 未登记状态名必须不可判定（而非默认通过）
  assert.equal(pairConsistent({ status: 'Teapot', code: '418' }), undefined)
})
