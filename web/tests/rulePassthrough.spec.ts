// TLS 透传（JJC-20261112-01 S3）前端接入验收：
//   utils/ruleValidation 透传族单源（SNI 形状 / 上游 host:port / 通配重叠 /
//   保存门同序组合）——与后端 internal/handlers/rule_features.go 的
//   validateSNIDomain / validatePassthroughRule / sniDomainsOverlap 逐条同口径
//   Rules.vue 协议分支隔离（透传逻辑只在新分支内，HTTP/TCP 表单行为不变）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  normalizeSNIDomain,
  passthroughSniError,
  passthroughUpstreamError,
  passthroughSaveGateError,
  sniDomainError,
  sniDomainsOverlap,
} from '../src/utils/ruleValidation.ts'
import { strategyCardsForProtocol, strategyValuesForProtocol } from '../src/utils/strategyLabels.ts'
import { code, repoCode, section } from './_helpers.ts'

const page = code('src/views/Rules.vue')

// ── SNI 域名形状（与后端 validateSNIDomain 逐条同口径同顺序）──

test('SNI 合法形态：精确域名 / 通配最左标签 / 连字符 / 多级', () => {
  for (const domain of ['app.example.com', '*.example.com', 'a-b.example.com', 'x1.y2.z3.example.com', 'a.co']) {
    assert.equal(sniDomainError(domain), null, domain)
    assert.equal(passthroughSniError(domain), null, domain)
  }
})

test('SNI 拒绝形态（与后端同句）：空/空白/控制字符/端口尾缀/尾缀点', () => {
  assert.match(sniDomainError('')!, /不能为空/)
  assert.match(sniDomainError('app example.com')!, /不能包含空白字符/)
  assert.match(sniDomainError('app\texample.com')!, /不能包含空白字符/)
  assert.match(sniDomainError('app\nexample.com')!, /不能包含空白字符/)
  // eslint-disable-next-line no-control-regex
  assert.match(sniDomainError('app\x01example.com')!, /含非法控制字符/)
  assert.match(sniDomainError('app.example.com:443')!, /不能包含端口尾缀/)
  assert.match(sniDomainError('app.example.com.')!, /不能以点结尾/)
})

test('SNI 拒绝 IP 字面量与超长（后端 net.ParseIP / len>253 同位）', () => {
  assert.match(sniDomainError('10.0.0.1')!, /IP 字面量/)
  // 裸 IPv6 含冒号：与后端同序——端口尾缀门先于 ParseIP 门命中
  assert.match(sniDomainError('::1')!, /不能包含端口尾缀/)
  assert.match(sniDomainError('a'.repeat(254))!, /不能超过 253 字符/)
  // 253 恰好合法（每段 ≤63：79 个 'ab' 标签 + 16 字符尾段 = 253）
  assert.equal(sniDomainError('ab.'.repeat(79) + 'app1.example.com'), null)
})

test('SNI 通配语义：* 独占最左标签且至少保留两级', () => {
  assert.match(sniDomainError('*.com')!, /至少须保留两级域名/)
  assert.match(sniDomainError('*')!, /至少须保留两级域名/)
  assert.match(sniDomainError('a.*.example.com')!, /只能作为最左标签/)
  // *.example.*：* 独占最左后，尾标签 * 不在字母表内 → 标签门拒绝
  assert.match(sniDomainError('*.example.*')!, /标签只能以字母或数字开头\/结尾/)
})

test('SNI 标签门：空标签/超长/首尾非字母数字/非法字符', () => {
  assert.match(sniDomainError('app..example.com')!, /含空标签/)
  assert.match(sniDomainError(`${'a'.repeat(64)}.example.com`)!, /标签超长/)
  assert.match(sniDomainError('-app.example.com')!, /标签只能以字母或数字开头\/结尾/)
  assert.match(sniDomainError('app-.example.com')!, /标签只能以字母或数字开头\/结尾/)
  assert.match(sniDomainError('app.example.com_')!, /标签只能以字母或数字开头\/结尾/)
  assert.match(sniDomainError('app.exa_mple.com')!, /含非法字符/)
  // 大写输入须先归一（后端由 validatePassthroughRule 统一小写化后调用）
  assert.match(sniDomainError('APP.example.com')!, /非法字符|字母或数字/)
  assert.equal(sniDomainError(normalizeSNIDomain('APP.example.com')), null)
})

test('passthroughSniError：必填与单值门先于形状（后端同序）', () => {
  assert.match(passthroughSniError('')!, /SNI 域名必填/)
  assert.match(passthroughSniError('   ')!, /SNI 域名必填/)
  assert.match(passthroughSniError('a.com,b.com')!, /只支持单个域名/)
  // 归一口径：trim + 小写
  assert.equal(passthroughSniError('  App.Example.COM '), null)
})

// ── 透传上游 host:port（与后端 validatePassthroughRule 上游门同口径）──

test('上游合法形态：host:port / IPv4 / 主机名 / [IPv6]:port', () => {
  for (const upstream of ['10.0.0.5:10443', 'app.internal:8443', '[2001:db8::1]:10443', '[::1]:443']) {
    assert.equal(passthroughUpstreamError(upstream), null, upstream)
  }
})

test('上游拒绝形态：空/无端口/端口越界/多冒号/坏主机（后端 SplitHostPort 同拒）', () => {
  assert.match(passthroughUpstreamError('')!, /透传上游地址必填/)
  assert.match(passthroughUpstreamError('   ')!, /透传上游地址必填/)
  assert.match(passthroughUpstreamError('10.0.0.5')!, /须为 host:port 形态/)
  assert.match(passthroughUpstreamError('10.0.0.5:')!, /端口无效/)
  assert.match(passthroughUpstreamError('10.0.0.5:0')!, /端口无效/)
  assert.match(passthroughUpstreamError('10.0.0.5:65536')!, /端口无效/)
  assert.match(passthroughUpstreamError('10.0.0.5:abc')!, /端口无效/)
  // 不带方括号的多冒号串与 Go net.SplitHostPort 同拒（保存门不放行、渲染再报错）
  assert.match(passthroughUpstreamError('::1:10443')!, /须为 host:port 形态/)
  assert.match(passthroughUpstreamError(':10443')!, /主机无效/)
  assert.match(passthroughUpstreamError('999.1.1.1:8443')!, /主机无效/)
  assert.match(passthroughUpstreamError('app.internal..:8443')!, /主机无效/)
})

// ── 通配重叠（与后端 sniDomainsOverlap 同口径：保守多级覆盖）──

test('sniDomainsOverlap：精确相等 / 通配覆盖单级与多级 / 双通配祖先域', () => {
  assert.equal(sniDomainsOverlap('a.com', 'a.com'), true)
  assert.equal(sniDomainsOverlap('*.a.com', 'b.a.com'), true)
  assert.equal(sniDomainsOverlap('*.a.com', 'c.b.a.com'), true)
  assert.equal(sniDomainsOverlap('*.b.a.com', '*.a.com'), true)
  assert.equal(sniDomainsOverlap('a.com', 'b.com'), false)
  assert.equal(sniDomainsOverlap('*.a.com', 'b.other.com'), false)
  assert.equal(sniDomainsOverlap('*.a.com', 'a.com'), true)
})

// ── 保存门同序组合（SNI → 上游 → 端口跟随）──

test('passthroughSaveGateError：合法通过 + 三段顺序与后端 validatePassthroughRule 一致', () => {
  const ok = { domain: 'app.example.com', upstream: '10.0.0.5:10443', listenPort: 443, httpsPort: 443 }
  assert.equal(passthroughSaveGateError(ok), '')
  // 端口跟随（第一期仅 HTTPS 默认口）
  assert.match(passthroughSaveGateError({ ...ok, listenPort: 8443 })!, /必须为部署侧 HTTPS 默认口 443/)
  // 顺序：SNI 错误先于上游错误，上游错误先于端口错误
  const both = passthroughSaveGateError({ domain: '', upstream: 'bad', listenPort: 8443, httpsPort: 443 })
  assert.match(both, /SNI 域名必填/)
  const upstreamFirst = passthroughSaveGateError({ ...ok, upstream: 'bad', listenPort: 8443 })
  assert.match(upstreamFirst, /须为 host:port 形态/)
})

// ── 策略白名单（与后端 validateStrategyForProtocol 的 passthrough 分支同口径）──

test('透传策略卡片=TCP 五策略（cookie/chain_fallback 剔除）', () => {
  const cards = strategyCardsForProtocol('passthrough').map((card) => card.value)
  assert.deepEqual(cards, ['weighted_round_robin', 'least_conn', 'ip_hash', 'random', 'first'])
  assert.deepEqual(strategyValuesForProtocol('passthrough'), cards)
  // HTTP 六/七策略不受影响（分支隔离）
  const http = strategyValuesForProtocol('http')
  assert.ok(http.includes('cookie') && http.includes('chain_fallback'))
  // TCP 白名单不变（cookie/chain_fallback 仍剔除）
  const tcp = strategyValuesForProtocol('tcp')
  assert.ok(!tcp.includes('cookie') && !tcp.includes('chain_fallback') && tcp.length === 5)
})

// ── 跨栈对表：后端门仍在（前端放行、保存 400 不允许的最后防线）──

test('跨栈对表：后端透传保存门与前端行内校验的关键判据同值', () => {
  const go = repoCode('internal/handlers/rule_features.go')
  assert.match(go, /if len\(domain\) > 253 {/, '后端 SNI 长度门 253')
  assert.match(go, /port < 1 \|\| port > 65535/, '后端上游端口域 1-65535')
  assert.match(go, /input\.ListenPort != services\.DefaultHTTPSPort\(\)/, '后端端口跟随门')
  assert.match(go, /input\.EnableTLS \|\| input\.TLSHTTPRedirect/, '后端 TLS 字段互斥门')
  // 冲突双门在 rules.go：同端口同 SNI 只统计启用中规则（与前端行内提示同口径）
  assert.match(repoCode('internal/handlers/rules.go'), /protocol='passthrough' AND enabled=1 AND listen_port/, '后端同端口同 SNI 冲突门只统计启用中规则')
  assert.match(repoCode('internal/handlers/rules.go'), /透传规则的上游由 passthrough_upstream 字段配置，不支持 upstreams 上游列表/, '后端 upstreams 显式携带即 400')
})

// ── Rules.vue 协议分支隔离（透传逻辑只在新分支内）──

test('协议选择器含「TLS 透传」选项；SNI/域名/HTTPS 字段按协议分支隔离', () => {
  assert.match(page, /<el-radio value="passthrough">TLS 透传<\/el-radio>/)
  // SNI 域名字段仅透传渲染；HTTP 域名字段判据不变
  assert.match(page, /label="SNI 域名" required v-if="wizardForm\.protocol === 'passthrough'"/)
  assert.match(page, /label="域名" required v-if="wizardForm\.protocol === 'http'"/)
  // 启用 HTTPS 仍仅 HTTP（透传下证书字段整组不可达）
  assert.match(page, /label="启用 HTTPS" v-if="wizardForm\.protocol === 'http'"/)
})

test('透传时证书字段整组隐藏，且显式提示证书归属与 HTTP/3 限制', () => {
  const basic = section(page, '<div v-show="currentStep === WIZARD_STEP.BASIC"', '<div v-show="currentStep === WIZARD_STEP.TLS"')
  assert.match(basic, /本域名的证书由上游服务器管理，本系统不申请、不续期、不监控有效期/)
  assert.match(basic, /透传域名不支持 HTTP\/3（QUIC），自动降级 HTTP\/2\/1\.1/)
  // TLS 步整体仍由 http+enable_tls 门把守（透传下不可达）
  assert.match(page, /wizardForm\.enable_tls && wizardForm\.protocol === 'http'/)
})

test('透传监听端口只读并标注跟随部署 HTTPS_PORT', () => {
  const portItem = section(page, '<el-form-item label="监听端口" required>', '</el-form-item>')
  assert.match(portItem, /:disabled="wizardForm\.protocol === 'passthrough'"/)
  assert.match(portItem, /跟随部署 HTTPS_PORT/)
})

test('上游步：透传走 passthrough_upstream 单值输入，上游表格整组隐藏', () => {
  const upstreamsStep = section(page, '<div v-show="currentStep === WIZARD_STEP.UPSTREAMS"', '<div v-show="currentStep === WIZARD_STEP.CUSTOM_ROUTES"')
  // 单值输入与后端防脏门文案同源
  assert.match(upstreamsStep, /v-model="wizardForm\.passthrough_upstream"/)
  assert.match(upstreamsStep, /<template v-if="wizardForm\.protocol === 'passthrough'">/)
  // 表格/添加按钮在 else 分支内（透传下不渲染）
  const elseAt = upstreamsStep.indexOf('<template v-else>')
  const tableAt = upstreamsStep.indexOf('上游服务器列表')
  assert.ok(elseAt > 0 && tableAt > elseAt, '上游表格必须在透传分支的 v-else 内')
  // HTTP 路由/NTLM/认证网关块仍由 protocol === 'http' 门把守（不变）
  assert.match(upstreamsStep, /<template v-if="wizardForm\.protocol === 'http'">/)
})

test('透传行内校验接线：SNI/上游字段级错误 + 保存门组合 + 冲突双门', () => {
  assert.match(page, /const passthroughSniFieldError = computed\(/)
  assert.match(page, /const passthroughUpstreamFieldError = computed\(/)
  assert.match(page, /const passthroughGateError = computed\(/)
  assert.match(page, /const passthroughConflictWarning = computed\(/)
  // 冲突双门口径：只统计启用中规则、排除自身、sniDomainsOverlap 判定
  const conflict = section(page, 'const passthroughConflictWarning = computed', 'const usersLoadError = ref(false)')
  assert.match(page, /sniDomainsOverlap\(sni, other\)/)
  assert.match(conflict, /!rule\.enabled/)
  assert.match(conflict, /rule\.caddy_id === excludeId/)
})

test('步进门与提交门镜像透传保存门（跳步保存不得绕过）', () => {
  const basicGate = section(page, 'if (currentStep.value === WIZARD_STEP.BASIC)', 'if (currentStep.value === WIZARD_STEP.TLS)')
  assert.match(basicGate, /passthroughGateError\.value/)
  assert.match(basicGate, /passthroughConflictWarning\.value/)
  const upstreamGate = section(page, 'if (currentStep.value === WIZARD_STEP.UPSTREAMS)', 'if (currentStep.value === WIZARD_STEP.CUSTOM_ROUTES)')
  assert.match(upstreamGate, /if \(wizardForm\.protocol === 'passthrough'\)/)
  const submit = section(page, 'const submitWizard = async', 'const allowedProtocols')
  assert.match(submit, /passthroughGateError\.value/)
  assert.match(submit, /passthroughConflictWarning\.value/)
})

test('载荷：透传上游单值仅透传回传；upstreams 恒空；TLS 字段族按协议收敛', () => {
  const payload = section(page, 'const data: UpdateRuleRequest = {', 'let submitWarnings')
  assert.match(payload, /passthrough_upstream: wizardForm\.protocol === 'passthrough' \? wizardForm\.passthrough_upstream\.trim\(\) : ''/)
  assert.match(payload, /upstreams: wizardForm\.protocol === 'passthrough' \? \[\] : validUpstreams/)
  assert.match(payload, /enable_tls: wizardForm\.protocol === 'passthrough' \? false : wizardForm\.enable_tls/)
  assert.match(payload, /tls_source: wizardForm\.protocol === 'passthrough' \? 'manual' : wizardForm\.tls_source/)
  assert.match(payload, /tcp_proxy_protocol: \(wizardForm\.protocol === 'tcp' \|\| wizardForm\.protocol === 'passthrough'\) && wizardForm\.tcp_proxy_protocol/)
})

test('协议切换 watch：进入透传清理 HTTP-only 字段并清空上游，离开补回默认上游行', () => {
  const watch = section(page, "watch(() => wizardForm.protocol, (newVal, oldVal) => {", "}, { flush: 'sync' })")
  // PROXY V2 保留面扩展透传（TCP 语义不变）
  assert.match(watch, /if \(newVal !== 'tcp' && newVal !== 'passthrough'\) wizardForm\.tcp_proxy_protocol = false/)
  const enter = section(watch, "} else if (newVal === 'passthrough') {", "} else if (newVal === 'http' && oldVal === 'tcp') {")
  assert.match(enter, /wizardForm\.listen_port = defHttps/, '第一期端口必须跟随 HTTPS 默认口')
  assert.match(enter, /wizardForm\.enable_tls = false/)
  assert.match(enter, /wizardForm\.tls_source = 'manual'/, 'TLS/证书字段携带即后端 400，进入透传即复位')
  assert.match(enter, /wizardForm\.upstreams = \[\]/, 'upstreams 显式携带即后端 400')
  assert.match(enter, /proxy_flush_interval = 0/, '代理超时七列非 0 即被后端恒拒')
  assert.match(enter, /wizardForm\.custom_routes_enabled = false/)
  const restore = section(page, 'const restoreAfterPassthrough', 'watch(() => wizardForm.protocol, (newVal, oldVal) => {')
  assert.match(restore, /wizardForm\.upstreams\.push\(upstream\)/, '离开透传必须补回默认上游行（http/tcp ≥1 启用上游门）')
})

test('列表/查看器：passthrough 规则显示「TLS 透传」标签与透传上游', () => {
  // 列表协议列
  const listColumn = section(page, '<el-table-column label="协议" width="80">', '<el-table-column label="负载策略"')
  assert.match(listColumn, /TLS 透传/)
  // 上游列：透传徽标 + 悬停 passthrough_upstream
  const upstreamColumn = section(page, '<el-table-column label="上游" width="64"', '<el-table-column label="TLS"')
  assert.match(upstreamColumn, /row\.protocol === 'passthrough'/)
  assert.match(upstreamColumn, /row\.passthrough_upstream/)
  // 单规则配置查看器
  assert.match(page, /透传上游" v-if="ruleConfig\.protocol === 'passthrough'"/)
})