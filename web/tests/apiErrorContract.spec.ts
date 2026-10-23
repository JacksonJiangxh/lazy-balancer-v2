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
// 业务码既可能是整数字面量/`http.StatusX` 符号，也可能是**助手变量**——
// 失败助手与 2xx 成功助手惯用 `c.JSON(status, …{Code: status})`，这类动态
// 形态必须参与扫描（旧正则要求字面量 `http.StatusX` 打头，动态信封被两个
// 正则同时跳过，`unparsed` 恒空 = 静默假绿）。
// 响应方法含 `c.JSON` 与 `c.AbortWithStatusJSON`（middleware 惯用后者）；
// `\s*` 跨换行：`models.APIResponse{\n\tCode: …` 是仓内惯用多行写法。
const ENVELOPE = /c\.(?:JSON|AbortWithStatusJSON)\(\s*((?:http\.Status[A-Za-z]+)|[A-Za-z_][\w.]*)\s*,\s*(?:models\.APIResponse\{\s*Code:|gin\.H\{\s*"(?:code|Code)":)\s*((?:http\.Status[A-Za-z]+)|[A-Za-z_][\w.]*|\d+)/g

// 宽口径：只认「信封 + code 键」的头，不要求业务码可解析。用于交叉核对窄正则
// 没有漏掉任何一条信封响应（漏掉即无法参与同值断言）。动态状态与窄正则同口径。
const ENVELOPE_HEAD = /c\.(?:JSON|AbortWithStatusJSON)\(\s*((?:http\.Status[A-Za-z]+)|[A-Za-z_][\w.]*)\s*,\s*(?:models\.APIResponse\{|gin\.H\{\s*"(?:code|Code)"\s*:)/g

interface Envelope {
  /** 第一实参原文：`http.StatusX` 字面量或助手变量名 */
  status: string
  /** Code 实参原文：整数字面量、`http.StatusX` 或助手变量名 */
  code: string
  /** 在 Go 源中的偏移（2xx-only 助手白名单按所属函数判定） */
  index: number
}

const envelopes = (go: string): Envelope[] =>
  [...go.matchAll(ENVELOPE)].map((match) => ({ status: match[1], code: match[2], index: match.index ?? 0 }))

/** `http.StatusX` → `X`；动态表达式返回 undefined。 */
const literalStatusName = (expr: string): string | undefined => /^http\.Status([A-Za-z]+)$/.exec(expr)?.[1]

/** 业务码实参 → 数值；动态表达式返回 undefined（同值只能靠同一变量证明）。 */
const codeValue = (expr: string): number | undefined => {
  if (/^\d+$/.test(expr)) return Number(expr)
  const name = literalStatusName(expr)
  return name === undefined ? undefined : HTTP_STATUS[name]
}

/**
 * 业务码与 HTTP 状态是否同义。2xx 是成功信封（业务码 0；200 与前端
 * `code !== 200` 判据等价），其余状态必须逐值相同，调用方的 status 分支才成立。
 *
 * 动态状态（助手变量）唯一可由本函数机械证明的同义形态是「业务码取同一
 * 表达式」；`Code: 0` 属 2xx-only 助手语义，交由调用侧显式白名单放行。
 * 返回 undefined 表示不可判定（不得默认通过）。
 */
const pairConsistent = (pair: Envelope): boolean | undefined => {
  const statusName = literalStatusName(pair.status)
  if (statusName === undefined) {
    if (pair.code === pair.status) return true
    const value = codeValue(pair.code)
    if (value === 0 || value === 200) return undefined
    // 动态状态配异值业务码：无法证明同义，且形态上就是旧门禁要拦的错配
    return value === undefined ? undefined : false
  }
  const httpStatus = HTTP_STATUS[statusName]
  if (httpStatus === undefined) return undefined
  const value = codeValue(pair.code)
  if (value === undefined) return undefined
  return httpStatus < 300 ? value === 0 || value === 200 : value === httpStatus
}

test('前端业务码失败分支携带 HTTP status（api.ts 契约）', () => {
  const api = source('src/utils/api.ts')
  const branch = section(api, 'if (res.code !== undefined && res.code !== 0 && res.code !== 200) {', 'return res')
  assert.match(branch, /new ApiRequestError\(res\.message \|\| '请求失败', response\.status\)/, '必须携带 response.status')
  assert.doesNotMatch(branch, /new ApiRequestError\([^)]*,\s*res\.code\)/, '不得改携带业务码（调用方按 status 分类）')
})

test('扫描器形态自测：同行/多行、两种方法/信封、字面量与动态业务码都命中', () => {
  const symbolic = 'c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "x"})'
  const dynamic = 'c.JSON(outcome.status, gin.H{"code": outcome.status})'
  const fixtures = [
    'c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "x"})',
    'c.JSON(http.StatusBadGateway, models.APIResponse{\n\t\tCode: 502,\n\t\tMessage: "x",\n\t})',
    'c.JSON(http.StatusTooManyRequests, gin.H{"code": 429, "message": "x"})',
    'c.JSON(http.StatusConflict, gin.H{\n\t\t"code": 409,\n\t})',
    symbolic,
    'c.JSON(http.StatusBadRequest, gin.H{"code": http.StatusBadRequest})',
    'c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"code": 403, "message": "x"})',
    // 动态形态（助手变量）：第一实参与 Code 都非字面量，旧正则两处同时跳过
    'c.JSON(status, models.APIResponse{Code: status, Message: "x"})',
    'c.JSON(statusCode, models.APIResponse{\n\t\tCode: statusCode,\n\t\tMessage: "x",\n\t})',
    dynamic,
  ]
  for (const fixture of fixtures) {
    assert.equal(envelopes(fixture).length, 1, `扫描器漏形态：${fixture}`)
  }
  assert.deepEqual(
    envelopes(symbolic).map(({ status, code }) => ({ status, code })),
    [{ status: 'http.StatusConflict', code: 'http.StatusConflict' }],
    '符号业务码必须原样解出',
  )
  assert.deepEqual(
    envelopes(dynamic).map(({ status, code }) => ({ status, code })),
    [{ status: 'outcome.status', code: 'outcome.status' }],
    '动态形态必须解出同一表达式',
  )
  // 非信封载荷（登录响应、服务层结构体、自定义 gin.H 键、无 body 的 Abort）不参与
  assert.equal(envelopes('c.JSON(http.StatusOK, models.LoginResponse{Token: t})').length, 0)
  assert.equal(envelopes('c.JSON(http.StatusOK, gin.H{"status": "ok"})').length, 0)
  assert.equal(envelopes('c.AbortWithStatus(http.StatusUnauthorized)').length, 0)
})

/**
 * 2xx-only 助手白名单：状态取自 `f.SuccessStatus`（0 归一为 200），业务码固定 0。
 * 按「文件 + 所属函数」登记（重排/行号漂移不误报）；条目必须实际命中，
 * 死条目同样失败。
 */
const SUCCESS_ENVELOPE_WHITELIST: Record<string, true> = {
  'internal/handlers/handlers.go#finishTxApply': true,
  'internal/handlers/securityiplists.go#tryIPListHotPathApply': true,
}

/** 目录级信封下限：整个目录被排除时总量阈值（>1000）不可见，分目录才可发现。 */
const MIN_ENVELOPES: Record<(typeof SCAN_DIRS)[number], number> = {
  'internal/handlers': 1300,
  'internal/middleware': 40,
}

/** 信封所在函数（最近的上一个 `func` 声明）。 */
const enclosingFunc = (go: string, index: number): string => {
  const matches = [...go.slice(0, index).matchAll(/^func (?:\([^)]*\) )?([A-Za-z0-9_]+)/gm)]
  return matches.length ? matches[matches.length - 1][1] : ''
}

test('后端信封：每条业务码与 HTTP 状态同义（handlers + middleware 全量）', () => {
  const mismatched: string[] = []
  const unparsed: string[] = []
  const unknown: string[] = []
  const usedWhitelist = new Set<string>()
  const perDir: Record<string, number> = {}
  let pairs = 0
  let heads = 0
  for (const dir of SCAN_DIRS) {
    let dirPairs = 0
    for (const file of goFiles(dir)) {
      const go = repoSource(file)
      const declared = [...go.matchAll(ENVELOPE_HEAD)].length
      const parsed = envelopes(go)
      heads += declared
      pairs += parsed.length
      dirPairs += parsed.length
      if (declared !== parsed.length) unparsed.push(`${file}: 信封 ${declared} 条，解析出 ${parsed.length} 条`)
      for (const pair of parsed) {
        const verdict = pairConsistent(pair)
        if (verdict === true) continue
        const where = `${file}: ${pair.status} 配 Code ${pair.code}`
        if (verdict === false) {
          mismatched.push(where)
          continue
        }
        // undefined = 动态状态 + Code 0（2xx-only 助手）：必须显式白名单放行
        const key = `${file}#${enclosingFunc(go, pair.index)}`
        if (pair.code === '0' && SUCCESS_ENVELOPE_WHITELIST[key] === true) usedWhitelist.add(key)
        else unknown.push(`${where}（${enclosingFunc(go, pair.index)}）`)
      }
    }
    perDir[dir] = dirPairs
  }
  for (const dir of SCAN_DIRS) {
    assert.ok(perDir[dir] >= MIN_ENVELOPES[dir], `${dir} 配对过少（${perDir[dir]} < ${MIN_ENVELOPES[dir]}）——目录被排除或正则失效`)
  }
  assert.ok(pairs > 1000, `扫描到的状态/业务码配对过少（${pairs}）——正则或被改坏`)
  assert.deepEqual(unparsed, [], `存在业务码不可解析的信封响应（${heads} 条信封共解析 ${pairs} 条）`)
  assert.deepEqual(unknown, [], '动态状态信封不可判定——同值形态或 2xx-only 助手白名单必须显式登记')
  assert.deepEqual(mismatched, [], '状态与业务码不同义——前端按 status 分类会误判')
  assert.deepEqual(
    Object.keys(SUCCESS_ENVELOPE_WHITELIST).filter((key) => !usedWhitelist.has(key)),
    [],
    '白名单条目已无命中——删除死条目',
  )
})

test('负断言形态：成功状态配非零业务码 / 动态状态配异值业务码必须被判为不同值', () => {
  for (const fixture of [
    'c.JSON(http.StatusOK, models.APIResponse{Code: 500})',
    'c.JSON(http.StatusOK, gin.H{"code": 500})',
    'c.JSON(http.StatusOK, models.APIResponse{\n\tCode: 500,\n})',
    'c.JSON(http.StatusCreated, models.APIResponse{Code: 400})',
    'c.JSON(http.StatusBadRequest, models.APIResponse{Code: http.StatusConflict})',
    'c.JSON(status, models.APIResponse{Code: 500})',
    'c.JSON(status, models.APIResponse{Code: http.StatusConflict})',
  ]) {
    const [pair] = envelopes(fixture)
    assert.ok(pair, `扫描器漏形态：${fixture}`)
    assert.equal(pairConsistent(pair), false, `守卫必须判定为不同值：${fixture}`)
  }
  // 合法形态（成功信封 0 / 状态同值 / 符号同值 / 动态同表达式）
  for (const fixture of [
    'c.JSON(http.StatusOK, models.APIResponse{Code: 0})',
    'c.JSON(http.StatusCreated, models.APIResponse{Code: 0})',
    'c.JSON(http.StatusConflict, models.APIResponse{Code: 409})',
    'c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict})',
    'c.JSON(status, models.APIResponse{Code: status})',
  ]) {
    assert.equal(pairConsistent(envelopes(fixture)[0]), true, `守卫误报：${fixture}`)
  }
  // 动态状态 + Code 0 = 2xx-only 助手语义，只能由调用侧白名单放行，不得默认通过
  assert.equal(pairConsistent(envelopes('c.JSON(status, models.APIResponse{Code: 0})')[0]), undefined)
  // 未登记状态名必须不可判定（而非默认通过）
  assert.equal(pairConsistent({ status: 'http.StatusTeapot', code: '418', index: 0 }), undefined)
})
