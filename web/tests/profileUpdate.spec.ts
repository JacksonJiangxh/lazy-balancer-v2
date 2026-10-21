import test from 'node:test'
import assert from 'node:assert/strict'
import { isCurrentPasswordRejection } from '../src/utils/profileUpdate.ts'

test('历史问题：仅当前密码错误的 PATCH /users/me 401 豁免会话失效', () => {
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '当前密码错误'), true)
  assert.equal(isCurrentPasswordRejection('PATCH', '/api/v1/users/me?from=profile', 401, '当前密码错误'), true)
})

test('历史问题：同端点的会话过期 401 不得误判为当前密码错误', () => {
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '未登录或登录已过期'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '登录状态已失效'), false)
})

test('历史问题：其它方法、路径、状态与文案保持原会话处理', () => {
  assert.equal(isCurrentPasswordRejection('get', '/api/v1/users/me', 401, '当前密码错误'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/2', 401, '当前密码错误'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 400, '当前密码错误'), false)
  assert.equal(isCurrentPasswordRejection('patch', '/api/v1/users/me', 401, '用户名或密码错误'), false)
})
