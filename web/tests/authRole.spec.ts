// A85历史问题-9：全站 nodeMode 必须随 /config 成功响应持续刷新，而非只在登录、
// 失败重试或集群设置页更新。运行：cd web && node --test tests/authRole.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const source = readFileSync(new URL('../src/stores/auth.ts', import.meta.url), 'utf8')

test('A85历史问题-9：成功拉取配置后排下一轮全站角色刷新', () => {
  const fetchStart = source.indexOf('async function fetchConfig')
  const fetchEnd = source.indexOf('interface LoginResult', fetchStart)
  assert.ok(fetchStart >= 0 && fetchEnd > fetchStart, 'fetchConfig 边界必须存在')
  const fetchBody = source.slice(fetchStart, fetchEnd)
  const successStart = fetchBody.indexOf('if (res.data) {')
  const successEnd = fetchBody.indexOf('} else {', successStart)
  assert.ok(successStart >= 0 && successEnd > successStart, 'fetchConfig 成功分支边界必须存在')
  const successBranch = fetchBody.slice(successStart, successEnd)
  assert.match(successBranch, /nodeMode\.value = res\.data\.is_master \? 'master' : 'slave'/)
  assert.match(successBranch, /scheduleConfigRetry\(\)/, '成功响应也必须续排刷新，否则其他页面永久保留旧 nodeMode')

  // 回归/异常形状：单定时器防重、空 data 与非 401 失败仍保留原重试链。
  assert.match(source, /if \(configRetryTimer !== null \|\| !token\.value\) return/)
  assert.match(fetchBody, /\} else \{\s*scheduleConfigRetry\(\)/)
  assert.match(fetchBody, /!\(e instanceof ApiRequestError && e\.status === 401\)\) scheduleConfigRetry\(\)/)
  assert.match(source, /function localLogout[\s\S]*?clearConfigRetryTimer\(\)/)
})
