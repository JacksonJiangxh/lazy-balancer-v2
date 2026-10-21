// 历史问题：全站 nodeMode 必须随 /config 成功响应持续刷新，而非只在登录、
// 失败重试或集群设置页更新。运行：cd web && node --test tests/authRole.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { source } from './_helpers.ts'

const authSrc = source('src/stores/auth.ts')

test('成功拉取配置后排下一轮全站角色刷新', () => {
  const fetchStart = authSrc.indexOf('async function fetchConfig')
  const fetchEnd = authSrc.indexOf('interface LoginResult', fetchStart)
  assert.ok(fetchStart >= 0 && fetchEnd > fetchStart, 'fetchConfig 边界必须存在')
  const fetchBody = authSrc.slice(fetchStart, fetchEnd)
  const successStart = fetchBody.indexOf('if (res.data) {')
  const successEnd = fetchBody.indexOf('} else {', successStart)
  assert.ok(successStart >= 0 && successEnd > successStart, 'fetchConfig 成功分支边界必须存在')
  const successBranch = fetchBody.slice(successStart, successEnd)
  assert.match(successBranch, /nodeMode\.value = res\.data\.is_master \? 'master' : 'slave'/)
  assert.match(successBranch, /scheduleConfigRetry\(\)/, '成功响应也必须续排刷新，否则其他页面永久保留旧 nodeMode')

  // 回归/异常形状：单定时器防重、空 data 与非 401 失败仍保留原重试链。
  assert.match(authSrc, /if \(configRetryTimer !== null \|\| !token\.value\) return/)
  assert.match(fetchBody, /\} else \{\s*scheduleConfigRetry\(\)/)
  assert.match(fetchBody, /!\(e instanceof ApiRequestError && e\.status === 401\)\) scheduleConfigRetry\(\)/)
  assert.match(authSrc, /function localLogout[\s\S]*?clearConfigRetryTimer\(\)/)
})

test('mfa_write_guard 随 /config 投影单源：Users 页不再单独整取 GET /config', () => {
  const fetchStart = authSrc.indexOf('async function fetchConfig')
  const fetchEnd = authSrc.indexOf('interface LoginResult', fetchStart)
  const fetchBody = authSrc.slice(fetchStart, fetchEnd)
  assert.match(fetchBody, /mfa_write_guard\?: boolean/, '/config 契约声明该键')
  assert.match(fetchBody, /mfaWriteGuard\.value = res\.data\.mfa_write_guard === true/)
  assert.match(authSrc, /const mfaWriteGuard = ref\(false\)/, '首值 false = 守卫关闭的保守形态')
  assert.match(authSrc, /^\s+mfaWriteGuard,$/m, 'store 对外暴露 ref')

  const users = source('src/views/Users.vue')
  assert.match(users, /const mfaWriteGuard = computed\(\(\) => authStore\.mfaWriteGuard\)/)
  assert.doesNotMatch(users, /request\.get\('\/config'\)/, '不得再为单键重复拉整份配置')
})
