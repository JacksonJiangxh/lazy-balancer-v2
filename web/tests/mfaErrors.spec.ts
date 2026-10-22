// MFA 端点 401 分类验收：凭证/挑战错误豁免会话失效流程，
// 同端点的「未登录或登录已过期」必须继续走重新登录。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { isMfaCredentialRejection } from '../src/utils/mfaErrors.ts'
import { MFA_SCOPE_GROUPS } from '../src/utils/mfaScopeGroups.ts'
import { repoSource, section, source } from './_helpers.ts'

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

test('401 豁免白名单与后端 mfa.go 文案逐字对齐（跨栈钉）', () => {
  // 前端按后端中文字面量分类——后端润色文案（改字/加标点）会静默改变分类：
  // 真会话过期被当验码错误不弹重登，或反之误杀会话。逐字钉住 Go 侧出处。
  const go = repoSource('internal/handlers/mfa.go')
  for (const msg of [
    '验证码错误',
    '验证码错误次数过多，绑定已作废，请重新开始绑定',
    'MFA 挑战无效或已过期，请重新登录',
    'MFA 挑战已被使用，请重新登录',
  ]) {
    assert.ok(go.includes(`Message: "${msg}"`), `mfa.go 不再产生 401 文案「${msg}」——前端白名单失配`)
  }
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

// 写操作验证「支持的操作」清单必须与后端 mfaStepUpGuard 的拦截面同源。
// 任务监控操作 / 节点服务控制 / 站点坐标 / 指纹补救 / 自动封禁 / 爬虫库 / IP 名单 /
// DNS 凭证连通性测试 等族曾被漏列——用户对这些写操作被要求验码会感到意外（守卫
// 仍生效，不构成绕过）。清单单源在 utils/mfaScopeGroups，测试直接 import。
test('MFA「支持的操作」清单覆盖 middleware 各写端点族', () => {
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

// 反查钉：从 middleware.go 的 admin/business 组枚举全部写路由（含与写同级的
// 敏感导出 GET），逐族要求清单有锚点——新增写端点族未登记时本测试红，清单
// 不再靠人肉对齐。豁免面与守卫同一事实源：readOnlyWriteRoutes（只读语义写）
// + /auth/mfa/ 自助端点。
test('MFA 清单反查：middleware 全部写路由族均有清单锚点', () => {
  const mw = repoSource('internal/middleware/middleware.go')
  const policy = repoSource('internal/services/auditpolicy.go')
  const flat = MFA_SCOPE_GROUPS.map((g) => `${g.title}｜${g.items.join('、')}`).join('\n')

  const exemptBlock = section(policy, 'var readOnlyWriteRoutes = map[string]struct{}{', '\n}')
  const exempt = new Set([...exemptBlock.matchAll(/"([A-Z]+) (\/api\/v1[^"]+)"/g)].map((m) => `${m[1]} ${m[2]}`))
  const sensitiveBlock = section(mw, 'var sensitiveExportGetRoutes = map[string]bool{', '\n}')
  const sensitiveGets = [...sensitiveBlock.matchAll(/"(\/api\/v1[^"]+)":\s*true/g)].map((m) => `GET ${m[1]}`)

  const routes: string[] = [...sensitiveGets]
  for (const m of mw.matchAll(/\b(?:admin|business)\.(POST|PUT|PATCH|DELETE)\("([^"]+)"/g)) {
    routes.push(`${m[1]} /api/v1${m[2]}`)
  }
  assert.ok(routes.length > 60, `写路由枚举失效（仅 ${routes.length} 条）`)

  // 族锚点表（前缀有序，具体先于通用）：新增写端点族须在此登记锚点，
  // 否则落到 unmapped 报红——这就是「清单低估受保护范围」的机械保证。
  const familyAnchors: ReadonlyArray<readonly [string, string]> = [
    ['/api/v1/users/me/api-keys', 'API 密钥'],
    ['/api/v1/users/me', '个人资料修改'],
    ['/api/v1/users/:id/mfa/reset', '重置 MFA'],
    ['/api/v1/users', '用户增删改'],
    ['/api/v1/admin-tls', '管理 TLS'],
    ['/api/v1/system/restart', '系统重启'],
    ['/api/v1/system/tasks/', '任务监控'],
    ['/api/v1/caddy/config', 'Caddyfile 手动编辑'],
    ['/api/v1/caddy/', 'Caddy 服务启动'],
    ['/api/v1/api-keys', 'API 密钥'],
    ['/api/v1/ca-providers/', 'CA 提供商'],
    ['/api/v1/cluster/register-tokens', '注册令牌'],
    ['/api/v1/cluster/nodes/:id/login-ticket', '登录从节点'],
    ['/api/v1/cluster/nodes/:id/access-url', '访问地址修改'],
    ['/api/v1/cluster/nodes/:id/site', '节点站点坐标'],
    ['/api/v1/cluster/nodes/:id/service', '服务控制'],
    ['/api/v1/cluster/nodes/:id/forget-pin', '指纹钉'],
    ['/api/v1/cluster/nodes', '节点审批'],
    ['/api/v1/cluster/mode', '主从模式切换'],
    ['/api/v1/cluster/promote', '主从模式切换'],
    ['/api/v1/cluster/sync/pull', '手动同步'],
    ['/api/v1/cluster/settings', '集群同步设置'],
    ['/api/v1/cluster/forget-pins', '指纹钉'],
    ['/api/v1/config/export', '配置导出'],
    ['/api/v1/config/import', '配置导入'],
    ['/api/v1/config/reload', '配置重载'],
    ['/api/v1/config/validate', '配置重载'],
    ['/api/v1/config', '基础设置'],
    ['/api/v1/settings/auto-backup', '自动备份'],
    ['/api/v1/auto-backup', '自动备份'],
    ['/api/v1/settings/oidc', 'OIDC 配置'],
    ['/api/v1/security/policies', '安全策略'],
    ['/api/v1/security/rules/', '安全策略'],
    ['/api/v1/security/crs/', 'CRS'],
    ['/api/v1/security/ip2region/', 'IP 库'],
    ['/api/v1/security/threat-lib/', '威胁情报库'],
    ['/api/v1/security/crawler-lib/', '爬虫库'],
    ['/api/v1/security/custom-rules', '自定义规则'],
    ['/api/v1/security/block-pages', '拦截页面'],
    ['/api/v1/security/ip-lists', 'IP 名单'],
    ['/api/v1/security/autoban', '自动封禁'],
    ['/api/v1/rules/batch-block-pages', '拦截页面'],
    ['/api/v1/rules', '负载规则'],
    ['/api/v1/certificate-configs/test', 'DNS 凭证连通性测试'],
    ['/api/v1/certificate-configs/:id/test', 'DNS 凭证连通性测试'],
    ['/api/v1/certificate-configs', '证书配置'],
    ['/api/v1/certificates/issue', '触发证书签发'],
    ['/api/v1/certificates/jobs', '证书任务'],
  ]

  const unmapped: string[] = []
  const missingAnchor: string[] = []
  for (const route of routes) {
    if (exempt.has(route)) continue
    const path = route.slice(route.indexOf(' '))
    if (path.startsWith(' /api/v1/auth/mfa/')) continue // MFA 自助端点（弹框 subtitle 明示除外）
    const family = familyAnchors.find(([prefix]) => path.startsWith(` ${prefix}`))
    if (!family) {
      unmapped.push(route)
    } else if (!flat.includes(family[1])) {
      missingAnchor.push(`${route} → 「${family[1]}」`)
    }
  }
  assert.deepEqual(unmapped, [], '新增写端点族未登记族锚点（清单会低估受保护范围）')
  assert.deepEqual(missingAnchor, [], '清单缺族锚点')
})
