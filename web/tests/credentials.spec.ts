// 用户名/密码前端策略单源验收
//   A. 字符集与长度口径与后端 validateUsernamePolicy / validatePasswordPolicy 对齐
//   B. 三处密码入口 + 用户管理/首次设置用户名均消费同一模块（不得各写正则/文案）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  validateUsername,
  validatePassword,
  USERNAME_MIN_LENGTH,
  USERNAME_MAX_LENGTH,
  USERNAME_POLICY_RE,
  PASSWORD_MIN_LENGTH,
  PASSWORD_MAX_LENGTH,
  USERNAME_POLICY_MESSAGE,
  USERNAME_LENGTH_MESSAGE,
  PASSWORD_LENGTH_MESSAGE,
  PASSWORD_CHARSET_MESSAGE,
} from '../src/utils/credentials.ts'
import { repoSource, section, source } from './_helpers.ts'

// 跨栈权威源：用户名/密码策略在后端是字面量（auth.go 的密码常量 + 用户名正则、
// models.go 的 CreateUserRequest 长度标签）。下方行为断言的长度/字符集边界全部
// 由 Go 源派生——前端手抄表与后端单侧漂移即红，不再依赖人工核对。
const authGo = repoSource('internal/handlers/auth.go')
const GO_PASSWORD_MIN = Number(/minPasswordLength = (\d+)/.exec(authGo)?.[1])
const GO_PASSWORD_MAX = Number(/maxPasswordLength = (\d+)/.exec(authGo)?.[1])
const GO_USERNAME_PATTERN = /usernamePolicyRe = regexp\.MustCompile\(`([^`]+)`\)/.exec(authGo)?.[1] ?? ''
const createUserGo = section(repoSource('internal/models/models.go'), 'type CreateUserRequest struct', '\n}')
const GO_USERNAME_BINDING = /binding:"required,min=(\d+),max=(\d+)"/.exec(createUserGo)
const GO_USERNAME_MIN = Number(GO_USERNAME_BINDING?.[1])
const GO_USERNAME_MAX = Number(GO_USERNAME_BINDING?.[2])

test('策略常量与后端声明逐项对表（任一侧变更必红）', () => {
  assert.ok(GO_PASSWORD_MIN > 0 && GO_PASSWORD_MAX > GO_PASSWORD_MIN, 'auth.go 密码长度常量未解析')
  assert.ok(GO_USERNAME_PATTERN && GO_USERNAME_MIN > 0, 'auth.go/models.go 用户名策略未解析')
  assert.equal(PASSWORD_MIN_LENGTH, GO_PASSWORD_MIN)
  assert.equal(PASSWORD_MAX_LENGTH, GO_PASSWORD_MAX)
  assert.equal(USERNAME_MIN_LENGTH, GO_USERNAME_MIN)
  assert.equal(USERNAME_MAX_LENGTH, GO_USERNAME_MAX)
  assert.equal(USERNAME_POLICY_RE.source, GO_USERNAME_PATTERN, '用户名字符集正则必须与后端同源同形')
})

test('A 用户名字符集：小写字母开头 + 小写字母/数字，长度由 Go binding 派生', () => {
  assert.equal(validateUsername(''), null, '空值由调用方按入口语义拦截')
  assert.equal(validateUsername('admin'), null)
  assert.equal(validateUsername('user01'), null)
  assert.equal(validateUsername('Admin'), USERNAME_POLICY_MESSAGE, '大写必须拒绝（后端正则不含 A-Z）')
  assert.equal(validateUsername('1user'), USERNAME_POLICY_MESSAGE)
  assert.equal(validateUsername('user_name'), USERNAME_POLICY_MESSAGE)
  assert.equal(validateUsername('用户名abc'), USERNAME_POLICY_MESSAGE, '含汉字必须拒绝')
  assert.equal(validateUsername('a'.repeat(GO_USERNAME_MIN - 1)), USERNAME_LENGTH_MESSAGE)
  assert.equal(validateUsername('a'.repeat(GO_USERNAME_MAX)), null, '后端 binding 上界内必须放行')
  assert.equal(validateUsername('a'.repeat(GO_USERNAME_MAX + 1)), USERNAME_LENGTH_MESSAGE)
})

test('A 密码字符集：Go 常量派生的长度区间 + 可打印 ASCII；汉字/控制符前置拒绝', () => {
  assert.equal(validatePassword(''), null, '留空=不修改')
  assert.equal(validatePassword('Abc12345'), null)
  assert.equal(validatePassword('!@#$%^&*Aa1'), null)
  assert.equal(validatePassword('A'.repeat(GO_PASSWORD_MIN - 1)), PASSWORD_LENGTH_MESSAGE)
  assert.equal(validatePassword('A'.repeat(GO_PASSWORD_MIN)), null, '下界本身必须接受')
  assert.equal(validatePassword('A'.repeat(GO_PASSWORD_MAX)), null, '上界本身必须接受')
  assert.equal(validatePassword('A'.repeat(GO_PASSWORD_MAX + 1)), PASSWORD_LENGTH_MESSAGE)
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

// 编辑态用户名前置校验必须对齐后端 usernameChanged 口径（users.go：仅在用户名
// 实际变更时过策略，OIDC 行整体豁免）——OIDC 用户名可含 . / _ / 大写，无条件
// 校验会把 OIDC 用户的角色编辑在 UI 层永久拦死。
test('编辑门控：用户名校验仅创建/实际改名且非 OIDC 行执行', () => {
  const users = source('src/views/Users.vue')
  const submit = section(users, 'const handleSubmit = async ()', 'closeForm()')
  assert.match(
    submit,
    /const usernameChanged = editingUser\.value !== null && form\.value\.username !== editingUser\.value\.username/,
    '须按后端 usernameChanged 口径计算用户名实际变更',
  )
  assert.match(
    submit,
    /!editingUser\.value \|\| \(usernameChanged && !editingIsOIDC\.value\)/,
    '编辑态未改名或 OIDC 行不得执行用户名策略校验',
  )
  // OIDC 行编辑提交仍不落 username/display_name/password（后端 400 守卫的前端镜像）
  assert.match(submit, /username: oidcTarget \? undefined : form\.value\.username/)
})
