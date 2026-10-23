// 全站 nodeMode 必须随 /config 成功响应持续刷新，而非只在登录、
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
  assert.match(authSrc, /if \(configRetryTimer !== null \|\| !token\.value\)\s+return/)
  assert.match(fetchBody, /\} else \{\s*scheduleConfigRetry\(\)/)
  assert.match(fetchBody, /!\(e instanceof ApiRequestError && e\.status === 401\)\)\s+scheduleConfigRetry\(\)/)
  assert.match(authSrc, /function localLogout[\s\S]*?clearConfigRetryTimer\(\)/)
})

test('配置补查在途门：fetchConfig 一轮在飞时新触发直接跳过', () => {
  const fetchStart = authSrc.indexOf('async function fetchConfig')
  const fetchEnd = authSrc.indexOf('interface LoginResult', fetchStart)
  const fetchBody = authSrc.slice(fetchStart, fetchEnd)
  assert.match(fetchBody, /\|\| configFetchInFlight\) return/, 'visibilitychange 补查与 15s 轮询可能同时点火，须在途门防双发')
  assert.match(fetchBody, /configFetchInFlight = true/)
  assert.match(fetchBody, /finally \{\s*configFetchInFlight = false\s*\}/, '在途标记必须 finally 复位（含失败路径）')
})

test('mfa_write_guard 随 /config 投影单源：Users 页不再单独整取 GET /config', () => {
  const fetchStart = authSrc.indexOf('async function fetchConfig')
  const fetchEnd = authSrc.indexOf('interface LoginResult', fetchStart)
  const fetchBody = authSrc.slice(fetchStart, fetchEnd)
  // /config 投影复用 GlobalConfigData 声明（Pick），mfa_write_guard 键由该接口提供
  assert.match(authSrc, /Pick<GlobalConfigData, 'timezone' \| 'cert_renewal_days' \| 'mfa_write_guard'>/, '/config 投影必须 Pick GlobalConfigData（单一事实源）')
  assert.match(fetchBody, /mfaWriteGuard\.value = res\.data\.mfa_write_guard === true/)
  assert.match(authSrc, /const mfaWriteGuard = ref\(false\)/, '首值 false = 守卫关闭的保守形态')
  assert.match(authSrc, /^\s+mfaWriteGuard,$/m, 'store 对外暴露 ref')

  const users = source('src/views/Users.vue')
  assert.match(users, /const mfaWriteGuard = computed\(\(\) => authStore\.mfaWriteGuard\)/)
  assert.doesNotMatch(users, /request\.get\('\/config'\)/, '不得再为单键重复拉整份配置')
})
