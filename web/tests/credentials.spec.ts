// 用户名/密码前端策略单源验收（历史问题-01/02）：
//   A. 字符集与长度口径与后端 validateUsernamePolicy / validatePasswordPolicy 对齐
//   B. 三处密码入口 + 用户管理/首次设置用户名均消费同一模块（不得各写正则/文案）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  validateUsername,
  validatePassword,
  USERNAME_POLICY_MESSAGE,
  USERNAME_LENGTH_MESSAGE,
  PASSWORD_LENGTH_MESSAGE,
  PASSWORD_CHARSET_MESSAGE,
} from '../src/utils/credentials.ts'
import { source } from './_helpers.ts'

test('A 用户名字符集：小写字母开头 + 小写字母/数字，长度 3-50', () => {
  assert.equal(validateUsername(''), null, '空值由调用方按入口语义拦截')
  assert.equal(validateUsername('admin'), null)
  assert.equal(validateUsername('user01'), null)
  assert.equal(validateUsername('Admin'), USERNAME_POLICY_MESSAGE, '大写必须拒绝（后端 ^[a-z][a-z0-9]*$）')
  assert.equal(validateUsername('1user'), USERNAME_POLICY_MESSAGE)
  assert.equal(validateUsername('user_name'), USERNAME_POLICY_MESSAGE)
  assert.equal(validateUsername('用户名abc'), USERNAME_POLICY_MESSAGE, '含汉字必须拒绝')
  assert.equal(validateUsername('ab'), USERNAME_LENGTH_MESSAGE)
  assert.equal(validateUsername('a'.repeat(51)), USERNAME_LENGTH_MESSAGE)
})

test('A 密码字符集：8-24 位可打印 ASCII；汉字/控制符前置拒绝', () => {
  assert.equal(validatePassword(''), null, '留空=不修改')
  assert.equal(validatePassword('Abc12345'), null)
  assert.equal(validatePassword('!@#$%^&*Aa1'), null)
  assert.equal(validatePassword('Abc1234'), PASSWORD_LENGTH_MESSAGE)
  assert.equal(validatePassword('A'.repeat(25)), PASSWORD_LENGTH_MESSAGE)
  assert.equal(validatePassword('密码12345678'), PASSWORD_CHARSET_MESSAGE)
  assert.equal(validatePassword('Abc12345\t'), PASSWORD_CHARSET_MESSAGE)
  assert.equal(validatePassword('Ａbc12345'), PASSWORD_CHARSET_MESSAGE, '全角字母同样属于非 ASCII')
})

test('B 三处密码入口 + 两处用户名入口均消费 credentials 单源', () => {
  const users = source('src/views/Users.vue')
  const layout = source('src/components/layout/AppLayout.vue')
  const login = source('src/views/Login.vue')
  for (const [name, text] of [['Users', users], ['AppLayout', layout], ['Login', login]] as const) {
    assert.match(text, /from '@\/utils\/credentials'/, `${name} 必须导入共享校验`)
  }
  // Users：创建/编辑 + 重置密码两入口
  assert.match(users, /const usernameError = validateUsername\(/)
  assert.match(users, /const passwordError = validatePassword\(/)
  assert.equal([...users.matchAll(/validatePassword\(/g)].length, 2, 'Users 两处密码入口必须同源')
  // 个人资料
  assert.match(layout, /const passwordError = validatePassword\(/)
  // 首次设置管理员：用户名/密码规则均走 validator
  assert.match(login, /validateUsername\(value\)/)
  assert.match(login, /validatePassword\(value\)/)
  // 不得回流本地正则/长度字面量
  assert.doesNotMatch(login, /const usernamePolicyRe = \/\^\[a-z\]\[a-z0-9\]\*\$\//, '本地用户名字符集正则必须退役')
  assert.doesNotMatch(users, /密码长度8-24位，仅限数字、大小写字母和特殊字符/, '本地密码文案必须退役')
})
