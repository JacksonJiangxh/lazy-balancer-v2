// 历史 WEB 修复源码钉（A85WA/A85WB/A85WT）：每条对应一个已修发现的回归守卫。
// 形态与 audit82Ui.spec.ts 一致——关键修复点用限段/带边界的断言，避免跨全文空转。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const source = (relative: string): string => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')

test('A85WA-历史问题：自定义规则编辑深拷贝条件行（取消/保存失败不得污染列表行）', () => {
  const text = source('src/views/security/SecurityRules.vue')
  const start = text.indexOf('const openRuleDialog')
  const end = text.indexOf('const saveCustomRule', start)
  const body = text.slice(start, end)
  assert.match(body, /row\.conditions\.map\(\(c\) => \(\{ \.\.\.c \}\)\)/)
  assert.doesNotMatch(body, /\[\.\.\.row\.conditions\]/, '浅拷贝数组会让弹框 v-model 直接改写列表行对象')
})

test('A85WA-历史问题：自动备份 quiet 轮询失败不逐轮弹 toast', () => {
  const text = source('src/views/settings/BasicSettings.vue')
  const start = text.indexOf('const fetchAutoBackup')
  const end = text.indexOf('const onAutoBackupOpened', start)
  const body = text.slice(start, end)
  // quiet（立即备份 2s 轮询）路径必须分流，不得走非 quiet 的报错 toast
  assert.match(body, /if \(!quiet\) \{[\s\S]*?ElMessage\.error/, '非 quiet 失败才允许弹「无法保存」错误')
})

test('A85WA-历史问题：健康轮询接入退避门，不可达 onError 已删除', () => {
  const text = source('src/views/Rules.vue')
  const start = text.indexOf('const healthPolling = usePollingTask')
  const end = text.indexOf('const healthPollingErrorDescription', start)
  const body = text.slice(start, end)
  assert.match(body, /healthPollingError\.canRun\(\)/)
  assert.doesNotMatch(body, /onError/, 'fetchHealthStatus 内部捕获不抛出——onError 是不可达死代码')
})

test('A85WA-历史问题：证书队列拉取接入轮询 AbortSignal', () => {
  const text = source('src/views/settings/TaskMonitor.vue')
  assert.match(text, /const fetchCertQueue = async \(signal\?: AbortSignal\)/)
  assert.match(text, /fetchCertQueue\(signal\)/)
})

test('A85WA-历史问题：任务详情历史与日志加载失败显性化', () => {
  const text = source('src/views/settings/TaskMonitor.vue')
  assert.match(text, /detailHistoryError/)
  assert.match(text, /logsLoadError/)
  const start = text.indexOf('const openDetail')
  const end = text.indexOf('// ===== 日志抽屉', start)
  assert.doesNotMatch(text.slice(start, end), /catch \{ \/\/ 无历史族静默 \}/, '详情历史失败不得静默')
})

test('A85WA-历史问题：规则向导关闭即清空私钥/证书明文', () => {
  const text = source('src/views/Rules.vue')
  const start = text.indexOf('const resetWizard = () =>')
  const end = text.indexOf('const beforeWizardClose', start)
  const body = text.slice(start, end)
  assert.match(body, /wizardForm\.tls_cert = ''/)
  assert.match(body, /wizardForm\.tls_key = ''/)
})

test('A85WA-历史问题：库健康标签加载三态（未加载不得显示「正常」）', () => {
  assert.match(source('src/utils/securityLibraries.ts'), /loaded === false/)
  const page = source('src/views/security/SecurityRules.vue')
  assert.match(page, /loaded: crsInfoLoaded\.value/)
  assert.match(page, /loaded: ip2regionInfoLoaded\.value/)
})

test('A85WA-历史问题：死导出 ADAPTIVE_SAMPLE_TIERS 已移除', () => {
  assert.doesNotMatch(source('src/utils/threatFlowRules.ts'), /ADAPTIVE_SAMPLE_TIERS/)
})

test('A85WA-历史问题：更新者名称四处复用收敛为 utils/updaterName 单源', () => {
  for (const file of [
    'src/views/Rules.vue',
    'src/views/security/SecurityRules.vue',
    'src/views/security/SecurityBlockPages.vue',
    'src/views/security/SecurityPolicies.vue',
  ]) {
    assert.ok(source(file).includes("from '@/utils/updaterName'"), `${file} 必须消费单源`)
  }
})

test('A85WA-历史问题：日志尾轮询五处收敛为 useLogTailPolling', () => {
  for (const file of [
    'src/views/Rules.vue',
    'src/views/settings/CertJobs.vue',
    'src/views/settings/TaskMonitor.vue',
    'src/views/settings/BasicSettings.vue',
    'src/views/settings/CaddyGlobalSettings.vue',
  ]) {
    assert.match(source(file), /useLogTailPolling/, `${file} 必须消费共享 composable`)
  }
  // TaskMonitor 原缺 hidden 暂停——收敛后由 composable 统一保证
  assert.match(source('src/composables/useLogTailPolling.ts'), /document\.hidden/)
})

test('A85WA-历史问题：DNS 掩码测试分支注释标明仅服务非 UI 客户端', () => {
  assert.match(source('src/views/settings/FreeCertificates.vue'), /非 UI 客户端/)
})

test('A85WA-历史问题：管理 TLS 读取失败显性化，开关禁用至加载成功', () => {
  const text = source('src/views/settings/BasicSettings.vue')
  assert.match(text, /adminTlsLoaded/)
  assert.match(text, /:disabled="isReadOnly \|\| !adminTlsLoaded"/)
})

test('A85WB-历史问题：Caddy 全局配置卡接入 configLoaded 双重门控', () => {
  const card = source('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(card, /defineProps<\{ configLoaded: boolean \}>/)
  assert.match(card, /:disabled="isReadOnly \|\| !props\.configLoaded"/)
  const start = card.indexOf('const handleSave = async')
  assert.match(card.slice(start, start + 400), /!props\.configLoaded/)
  const page = source('src/views/Settings.vue')
  assert.match(page, /<CaddyGlobalSettings[\s\S]*?:config-loaded="configLoaded"/)
})

test('A85WB-历史问题：任一 /config 成功读取恢复 configLoaded，失败可重试', () => {
  const text = source('src/views/Settings.vue')
  const start = text.indexOf('const refreshConfigSection')
  const end = text.indexOf('const handleSaveBasic', start)
  assert.match(text.slice(start, end), /configLoaded\.value = true/, '卡片保存后刷新成功必须恢复保存门')
  assert.match(text, /configLoadFailed/)
})

test('A85WB-历史问题：policy_id=0 展示「无策略归属」而非「策略已删除」', () => {
  const text = source('src/components/events/TriggerDetailDialog.vue')
  assert.match(text, /本次事件无策略归属/)
  const start = text.indexOf('const loadAll')
  const elseIdx = text.indexOf('} else {', start)
  const elseEnd = text.indexOf('}', text.indexOf('policyMissing', elseIdx))
  assert.doesNotMatch(text.slice(elseIdx, elseEnd), /policyMissing\.value = true/, 'policy_id<=0 不得归因为策略已删除')
})

test('A85WB-历史问题：威胁地图 canvas 注册/注销 pointerleave 清理悬停态', () => {
  const text = source('src/utils/threatScene.ts')
  assert.match(text, /addEventListener\('pointerleave', onPointerLeave\)/)
  assert.match(text, /removeEventListener\('pointerleave', onPointerLeave\)/)
  const start = text.indexOf('function onPointerLeave')
  assert.match(text.slice(start, start + 300), /hoverName = null/)
})

test('A85WB-历史问题：悬停高亮 Path2D 按 hover+相机键缓存（不再每帧重建）', () => {
  const text = source('src/utils/threatScene.ts')
  assert.match(text, /HoverCache|hoverPathCache/)
  const start = text.indexOf('function drawHoverHighlight')
  const end = text.indexOf('// ---- 主循环 ----', start)
  assert.match(text.slice(start, end), /Cache\.key !== key|cache\.key !== key/i)
})

test('A85WB-历史问题：指标采集失败时规则表空态报「采集失败」', () => {
  const text = source('src/views/Dashboard.vue')
  const start = text.indexOf('const rulesEmptyText')
  const end = text.indexOf('const hasRuleRequests', start)
  assert.match(text.slice(start, end), /caddyMetricsUnavailable/)
})

test('A85WB-历史问题：区域树加载失败保留旧数据并显性提示+重试', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /regionsError/)
  const start = text.indexOf('const fetchRegions')
  const end = text.indexOf('onMounted', start)
  assert.doesNotMatch(text.slice(start, end), /\} catch \{\s*regionTree\.value =/, '失败不得静默清空区域树')
})

test('A85WB-历史问题：事件页刷新按钮联动自动封禁状态', () => {
  const text = source('src/views/security/SecurityEvents.vue')
  const start = text.indexOf('const refreshPage')
  assert.ok(start > 0, '缺 refreshPage')
  assert.match(text.slice(start, start + 300), /fetchAutobanStatus/)
  assert.match(text, /@click="refreshPage"/)
})

test('A85WB-历史问题：信任关联写动作确认前即占位（双击不再叠确认框）', () => {
  const text = source('src/composables/useTrustAssociation.ts')
  const guards = text.match(/if \(creating\.value\) return/g) ?? []
  assert.ok(guards.length >= 2, `ensureListAndJoin/removeFromSideRef 均需入口重入锁，实际 ${guards.length}`)
})

test('A85WB-历史问题：restart 就绪响应落地后 reload 前复查 isDisposed', () => {
  const text = source('src/utils/restart.ts')
  const idx = text.indexOf("await request.get('/caddy/status'")
  assert.ok(idx > 0)
  assert.match(text.slice(idx, idx + 260), /isDisposed\?\.\(\)[\s\S]*?window\.location\.reload/, 'reload 前必须复查卸载门')
})

test('A85WB-历史问题：死代码清理（灰 tone/死 CSS/死字段/解析器单源）', () => {
  assert.doesNotMatch(source('src/components/RuleFlowDialog.vue'), /tl-dot--gray|\| 'gray'/)
  assert.doesNotMatch(source('src/views/security/SecurityEvents.vue'), /autoban-confirm-list|autoban-confirm-text/)
  assert.doesNotMatch(source('src/views/security/SecurityEvents.vue'), /list_referenced: boolean/, '死字段声明应移除')
  assert.doesNotMatch(source('src/views/security/SecurityPolicies.vue'), /\.exclusion-empty \.el-button/)
  // 自定义规则 ID 解析单源化
  const policies = source('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /parseUnknownIds/)
  assert.match(source('src/utils/securityStages.ts'), /export const parseUnknownIds|export function parseUnknownIds/)
})

test('A85WT-历史问题：build 门禁先跑测试与测试类型检查', () => {
  const pkg = JSON.parse(source('package.json')) as { scripts: Record<string, string> }
  assert.ok(
    pkg.scripts.build.startsWith('npm test && npm run typecheck:test &&'),
    `build 必须先执行 npm test 与 typecheck:test，实际: ${pkg.scripts.build}`,
  )
})

test('A85历史问题-C：ACME 证书卡接入 configLoaded 双重门控（与 Basic/Caddy 同契约）', () => {
  const card = source('src/views/settings/FreeCertificates.vue')
  assert.match(card, /defineProps<\{ configLoaded: boolean \}>/)
  assert.match(card, /:disabled="isReadOnly \|\| !props\.configLoaded"/)
  const start = card.indexOf('const handleSave = async ()')
  assert.ok(start >= 0, 'handleSave 未找到')
  assert.match(card.slice(start, start + 400), /!props\.configLoaded/)
  const page = source('src/views/Settings.vue')
  assert.match(page, /<FreeCertificates[\s\S]*?:config-loaded="configLoaded"/)
})
