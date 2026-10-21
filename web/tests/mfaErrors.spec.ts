// MFA 端点 401 分类验收（历史问题-04）：凭证/挑战错误豁免会话失效流程，
// 同端点的「未登录或登录已过期」必须继续走重新登录。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isMfaCredentialRejection } from '../src/utils/mfaErrors.ts'
import { MFA_SCOPE_GROUPS } from '../src/utils/mfaScopeGroups.ts'
import { source } from './_helpers.ts'

const SESSION_EXPIRED = '未登录或登录已过期'

test('验码/挑战错误 → 豁免会话失效（只传播文案供重试）', () => {
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 401, '验证码错误'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/disable', 401, '验证码错误'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/setup', 401, '验证码错误'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/activate', 401, '验证码错误次数过多，绑定已作废，请重新开始绑定'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify', 401, 'MFA 挑战无效或已过期，请重新登录'), true)
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify', 401, 'MFA 挑战已被使用，请重新登录'), true)
  // 管理员重置端点（Users.vue 展示后端文案供重试）
  assert.equal(isMfaCredentialRejection('/users/3/mfa/reset', 401, '验证码错误'), true)
})

test('同端点的会话过期 401 不得被豁免（428→verify-step 窗口）', () => {
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 401, SESSION_EXPIRED), false)
  assert.equal(isMfaCredentialRejection('/auth/mfa/status', 401, SESSION_EXPIRED), false)
  assert.equal(isMfaCredentialRejection('/users/3/mfa/reset', 401, SESSION_EXPIRED), false)
})

test('非 MFA 端点与其它状态码一律不豁免', () => {
  assert.equal(isMfaCredentialRejection('/auth/login', 401, '验证码错误'), false)
  assert.equal(isMfaCredentialRejection('/rules', 401, SESSION_EXPIRED), false)
  // 验证码错误若由非 401（400 表单校验/422）返回，本守卫不参与
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 400, '验证码错误'), false)
  // 未知文案 fail-safe：走会话失效流程（原实现按路径一律豁免，会吞掉真过期）
  assert.equal(isMfaCredentialRejection('/auth/mfa/verify-step', 401, '用户不可用'), false)
  assert.equal(isMfaCredentialRejection(undefined, 401, '验证码错误'), false)
})

// 历史修复：写操作验证「支持的操作」清单必须与后端 mfaStepUpGuard 的拦截面同源。
// 任务监控操作 / 节点服务控制 / 站点坐标 / 指纹补救 / 自动封禁 / 爬虫库 / IP 名单 /
// DNS 凭证连通性测试 等族曾被漏列——用户对这些写操作被要求验码会感到意外（守卫
// 仍生效，不构成绕过）。清单单源在 utils/mfaScopeGroups，测试直接 import。
test('WS-05：MFA「支持的操作」清单覆盖 middleware 各写端点族', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  assert.match(page, /v-for="group in MFA_SCOPE_GROUPS"/, '弹框必须直接渲染单源清单')
  const flat = MFA_SCOPE_GROUPS.map((g) => `${g.title}｜${g.items.join('、')}`).join('\n')
  for (const anchor of ['任务监控 运行', '服务控制', '节点站点坐标', '指纹钉', '自动封禁', '爬虫库', 'IP 名单', 'DNS 凭证连通性测试']) {
    assert.ok(flat.includes(anchor), `MFA 清单缺「${anchor}」——用户对这些写操作会被要求验码`)
  }
  assert.match(page, /subtitle="覆盖全部管理写操作（只读语义 POST 与 MFA 自助端点除外）"/)
  // 证书配置/CA 测试会真实写 DNS/EAB，不得再宣称「测试连接…不受影响」
  assert.doesNotMatch(page, /测试连接、预览、解析类操作不受影响/)
})
