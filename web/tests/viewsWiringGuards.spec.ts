// 视图/设置/安全页源码接线守卫：每条对应一个已修行为缺陷的回归断言，关键点用
// 限段（section，缺 marker 即抛错）或带边界的断言，避免跨全文空转。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'
import { shouldToastQuietPollError } from '../src/utils/pollErrorToast.ts'
import {
  CERT_QUEUE_VISIBLE_JOBS,
  certQueueHasLive,
  certQueueIsBusy,
  certQueueMoreCount,
  certQueueShownCount,
} from '../src/utils/certQueue.ts'
import { credentialFieldVisible, credentialOptionLabel, defaultCredentialsFor } from '../src/utils/dnsProviderFields.ts'

test('自定义规则编辑深拷贝条件行（取消/保存失败不得污染列表行）', () => {
  const body = section(source('src/views/security/SecurityRules.vue'), 'const openRuleDialog', 'const saveCustomRule')
  assert.match(body, /row\.conditions\.map\(\(c\) => \(\{ \.\.\.c \}\)\)/)
  assert.doesNotMatch(body, /\[\.\.\.row\.conditions\]/, '浅拷贝数组会让弹框 v-model 直接改写列表行对象')
})

test('自动备份 quiet 轮询失败不逐轮弹 toast', () => {
  // 原断言 /if \(!quiet\) \{[\s\S]*?ElMessage\.error/ 从 loading 门
  // 开始惰性匹配，命中的是 **quiet 分支自身**的节流 toast——删掉非 quiet 提示、或
  // 让 quiet 分支每轮无条件弹窗（本条要防的 30 条/60s 刷屏回归）仍然通过。
  // 改为对抽取出的判定做行为断言（单源 src/utils/pollErrorToast.ts）：
  assert.equal(shouldToastQuietPollError(true, 60_000, 0), false, 'quiet 且已加载成功：静默（保存仍可用）')
  assert.equal(shouldToastQuietPollError(false, 100_000, 0), true, 'quiet 且从未加载成功：提示一次')
  assert.equal(shouldToastQuietPollError(false, 100_000 + 29_999, 100_000), false, '窗口内不得重复提示（刷屏回归）')
  assert.equal(shouldToastQuietPollError(false, 100_000 + 30_001, 100_000), true, '窗口过后可再提示一次')
  // 生产接线：两个分支各自独立——quiet 分支先过节流判定，else 分支无条件提示。
  const body = section(source('src/views/settings/BasicSettings.vue'), 'const fetchAutoBackup', 'const onAutoBackupOpened')
  const catchAt = body.indexOf('} catch {')
  assert.ok(catchAt > 0, '缺 catch 分支')
  const catchBody = body.slice(catchAt)
  const elseAt = catchBody.indexOf('} else {')
  assert.ok(elseAt > 0, '缺非 quiet 失败分支')
  const quietBranch = catchBody.slice(0, elseAt)
  const guardAt = quietBranch.indexOf('shouldToastQuietPollError(autoBackupLoaded.value, now, lastAutoBackupErrorToastAt)')
  const quietToastAt = quietBranch.indexOf('ElMessage.error')
  assert.ok(guardAt > 0, 'quiet 分支必须经节流判定')
  assert.ok(quietToastAt > guardAt, 'quiet 分支的 toast 必须在节流判定之后')
  assert.match(catchBody.slice(elseAt), /^} else \{[\s\S]*?ElMessage\.error/, '非 quiet 失败必须无条件提示')
})

test('健康轮询接入退避门，不可达 onError 已删除', () => {
  const body = section(source('src/views/Rules.vue'), 'const healthPolling = usePollingTask', 'const healthPollingErrorDescription')
  assert.match(body, /healthPollingError\.canRun\(\)/)
  assert.doesNotMatch(body, /onError/, 'fetchHealthStatus 内部捕获不抛出——onError 是不可达死代码')
})

test('证书队列拉取接入轮询 AbortSignal', () => {
  const text = source('src/views/settings/TaskMonitor.vue')
  assert.match(text, /const fetchCertQueue = async \(signal\?: AbortSignal\)/)
  assert.match(text, /fetchCertQueue\(signal\)/)
})

test('任务详情历史与日志加载失败显性化', () => {
  const text = source('src/views/settings/TaskMonitor.vue')
  assert.match(text, /detailHistoryError/)
  assert.match(text, /logsLoadError/)
  assert.doesNotMatch(section(text, 'const openDetail', '// ===== 日志抽屉'), /catch \{ \/\/ 无历史族静默 \}/, '详情历史失败不得静默')
})

test('规则向导关闭即清空私钥/证书明文', () => {
  const body = section(source('src/views/Rules.vue'), 'const resetWizard = () =>', 'const beforeWizardClose')
  assert.match(body, /wizardForm\.tls_cert = ''/)
  assert.match(body, /wizardForm\.tls_key = ''/)
})

test('库健康标签加载三态（未加载不得显示「正常」）', () => {
  assert.match(source('src/utils/securityLibraries.ts'), /loaded === false/)
  const page = source('src/views/security/SecurityRules.vue')
  assert.match(page, /loaded: crsInfoLoaded\.value/)
  assert.match(page, /loaded: ip2regionInfoLoaded\.value/)
})

test('死导出 ADAPTIVE_SAMPLE_TIERS 已移除', () => {
  assert.doesNotMatch(source('src/utils/threatFlowRules.ts'), /ADAPTIVE_SAMPLE_TIERS/)
})

test('更新者名称四处复用收敛为 utils/updaterName 单源', () => {
  for (const file of [
    'src/views/Rules.vue',
    'src/views/security/SecurityRules.vue',
    'src/views/security/SecurityBlockPages.vue',
    'src/views/security/SecurityPolicies.vue',
  ]) {
    assert.ok(source(file).includes("from '@/utils/updaterName'"), `${file} 必须消费单源`)
  }
})

test('日志尾轮询五处收敛为 useLogTailPolling', () => {
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

test('DNS 凭证测试按掩码回传分流（***→库中原值 :id/test）', () => {
  // 原断言匹配注释文本「非 UI 客户端」——注释保留而分流逻辑
  // 被删/改向也通过。改为钉分流语义：只有表单凭证含 *** 时打 :id/test（验证库中
  // 存量），用户实际改过凭证（无 ***）走无 id 的 /test。
  const page = source('src/views/settings/FreeCertificates.vue')
  const block = section(page, 'const hasMaskedCred', 'await request.post(url')
  assert.match(block, /v === '\*\*\*'/, '掩码判定必须是凭证值为 ***')
  assert.match(block, /targetId && hasMaskedCred/, '仅在「编辑既有 + 掩码回传」时走库中原值')
  assert.match(block, /`\/certificate-configs\/\$\{targetId\}\/test`/)
  assert.match(block, /:\s*'\/certificate-configs\/test'/)
})

test('管理 TLS 读取失败显性化，开关禁用至加载成功', () => {
  const text = source('src/views/settings/BasicSettings.vue')
  assert.match(text, /adminTlsLoaded/)
  assert.match(text, /:disabled="isReadOnly \|\| !adminTlsLoaded"/)
})

test('Caddy 全局配置卡接入 configLoaded 双重门控', () => {
  const card = source('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(card, /defineProps<\{ configLoaded: boolean \}>/)
  assert.match(card, /:disabled="isReadOnly \|\| !props\.configLoaded"/)
  const save = section(card, 'const handleSave = async', 'if (isReadOnly.value || saving.value) return')
  assert.match(save, /!props\.configLoaded/, 'configLoaded 门必须早于常规写守卫')
  const page = source('src/views/Settings.vue')
  assert.match(page, /<CaddyGlobalSettings[\s\S]*?:config-loaded="configLoaded"/)
})

test('任一 /config 成功读取恢复 configLoaded，失败可重试', () => {
  const text = source('src/views/Settings.vue')
  const block = section(text, 'const refreshConfigSection', 'const handleSaveBasic')
  assert.match(block, /configLoaded\.value = true/, '卡片保存后刷新成功必须恢复保存门')
  assert.match(text, /configLoadFailed/)
})

test('policy_id=0 展示「无策略归属」而非「策略已删除」', () => {
  const text = source('src/components/events/TriggerDetailDialog.vue')
  assert.match(text, /本次事件无策略归属/)
  // 无策略归属态由 policy_id<=0 判定（后端 securityevents.go 返回 (0, "")）
  assert.match(text, /const noPolicyAttribution = computed\(\(\) => \(props\.row\?\.policy_id \?\? 0\) <= 0\)/)
  // 原实现用「首个 } else { + 下一处 policyMissing」推段——
  // 若 policyMissing 首次出现在段外则 indexOf 得 -1、切片为空，断言空转。
  // 改为语义断言：loadAll 内「策略已删除」的每处赋值都必须落在 policy_id>0 分支，
  // 无策略归属分支（} else { 之后）不得出现任何归因赋值。
  const body = section(text, 'const loadAll', '\nconst ')
  const attributionIf = body.indexOf('row.policy_id > 0')
  const attributionElse = body.indexOf('} else {', attributionIf)
  assert.ok(attributionIf > 0 && attributionElse > attributionIf, '缺 policy_id>0 / else 分支')
  const assignments = [...body.matchAll(/policyMissing\.value = true/g)]
  assert.ok(assignments.length >= 1, '策略拉取失败/缺失必须归因（否则「策略已删除」状态失效）')
  for (const assignment of assignments) {
    assert.ok((assignment.index ?? 0) < attributionElse, 'policy_id<=0 分支不得归因为策略已删除')
  }
})

test('威胁地图 canvas 注册/注销 pointerleave 清理悬停态', () => {
  const text = source('src/utils/threatScene.ts')
  assert.match(text, /addEventListener\('pointerleave', onPointerLeave\)/)
  assert.match(text, /removeEventListener\('pointerleave', onPointerLeave\)/)
  assert.match(section(text, 'function onPointerLeave', '\n  }'), /hoverName = null/, '离开画布必须复位悬停名')
})

test('悬停高亮路径按世界坐标缓存（不再随相机逐帧重建）', () => {
  const text = source('src/utils/threatScene.ts')
  const body = section(text, 'function drawHoverHighlight', '// ---- 主循环 ----')
  assert.match(body, /ensureWorldDotPaths\(\)/, '悬停必须复用按国世界路径缓存')
  assert.doesNotMatch(body, /new Path2D\(/, '悬停绘制不得逐帧重建 Path2D')
  const cache = section(text, 'function ensureWorldDotPaths', '// ---- 静态层 ----')
  assert.match(cache, /if \(worldDotPathByKey\) return worldDotPathByKey/, '世界路径必须构建一次后复用')
})

test('指标采集失败时规则表空态报「采集失败」', () => {
  assert.match(section(source('src/views/Dashboard.vue'), 'const rulesEmptyText', 'const hasRuleRequests'), /caddyMetricsUnavailable/)
})

test('区域树加载失败保留旧数据并显性提示+重试', () => {
  const text = source('src/views/security/SecurityPolicies.vue')
  assert.match(text, /regionsError/)
  const fetchRegions = section(text, 'const fetchRegions', 'onMounted')
  assert.doesNotMatch(fetchRegions, /\} catch \{\s*regionTree\.value =/, '失败不得静默清空区域树')
})

test('事件页刷新按钮联动自动封禁状态', () => {
  const text = source('src/views/security/SecurityEvents.vue')
  const start = text.indexOf('const refreshPage')
  assert.ok(start > 0, '缺 refreshPage')
  assert.match(text.slice(start, start + 300), /fetchAutobanStatus/)
  assert.match(text, /@click="refreshPage"/)
})

test('信任关联写动作确认前即占位（双击不再叠确认框）', () => {
  const text = source('src/composables/useTrustAssociation.ts')
  // 原断言只数 `if (creating.value) return` 出现次数 ≥2——
  // 同一函数里写两次也通过，无法证明「两个写入口都有锁」。改为逐函数限段：
  // 每个写入口的入口守卫必须早于占位与确认框。
  const writers = [
    ['const ensureListAndJoin = async', 'const removeFromSideRef = async'],
    ['const removeFromSideRef = async', 'return { busyTrust'],
  ] as const
  for (const [startMarker, endMarker] of writers) {
    const body = section(text, startMarker, endMarker)
    const guard = body.indexOf('if (creating.value) return')
    const occupy = body.indexOf('creating.value = true')
    const confirm = body.indexOf('ElMessageBox.confirm')
    assert.ok(guard > 0, `${startMarker} 缺重入锁`)
    assert.ok(occupy > guard, `${startMarker} 必须先判锁再占位`)
    assert.ok(confirm > guard, `${startMarker} 必须在弹确认框之前判锁（否则双击叠两个框）`)
    assert.ok(confirm > occupy, `${startMarker} 占位必须先于确认框`)
  }
})

test('restart 就绪响应落地后 reload 前复查 isDisposed', () => {
  // 原断言取 260 字符窗口——isDisposed 与 reload 可来自无关语句。
  // 改为函数级限段 + 顺序断言：状态请求成功后的 dispose 复查必须紧邻 reload。
  const body = section(source('src/utils/restart.ts'), 'const reloadAfterRestart = async', 'export interface RestartServiceOptions')
  const statusAt = body.indexOf("await request.get('/caddy/status'")
  assert.ok(statusAt > 0, '缺就绪探测')
  const afterStatus = body.slice(statusAt)
  const reloadAt = afterStatus.indexOf('window.location.reload()')
  assert.ok(reloadAt > 0, '就绪后必须 reload')
  const gateAt = afterStatus.indexOf('if (isDisposed?.()) return false')
  assert.ok(gateAt > 0 && gateAt < reloadAt, 'reload 前必须复查卸载门（在途期间卸载不得刷新页面）')
  // 探测前同样要有卸载门：重启窗口内卸载即停止轮询
  const beforeStatus = body.slice(0, statusAt)
  assert.match(beforeStatus, /if \(isDisposed\?\.\(\)\) return false/)
})

test('死代码清理（灰 tone/死 CSS/死字段/解析器单源）', () => {
  assert.doesNotMatch(source('src/components/RuleFlowDialog.vue'), /tl-dot--gray|\| 'gray'/)
  assert.doesNotMatch(source('src/views/security/SecurityEvents.vue'), /autoban-confirm-list|autoban-confirm-text/)
  assert.doesNotMatch(source('src/views/security/SecurityEvents.vue'), /list_referenced: boolean/, '死字段声明应移除')
  assert.doesNotMatch(source('src/views/security/SecurityPolicies.vue'), /\.exclusion-empty \.el-button/)
  // 自定义规则 ID 解析单源化
  const policies = source('src/views/security/SecurityPolicies.vue')
  assert.match(policies, /parseUnknownIds/)
  assert.match(source('src/utils/securityStages.ts'), /export const parseUnknownIds|export function parseUnknownIds/)
})

test('build 门禁先跑测试与测试类型检查', () => {
  const pkg = JSON.parse(source('package.json')) as { scripts: Record<string, string> }
  assert.ok(
    pkg.scripts.build.startsWith('npm test && npm run typecheck:test &&'),
    `build 必须先执行 npm test 与 typecheck:test，实际: ${pkg.scripts.build}`,
  )
  // tsconfig.test.json extends 根 include（含全部 src/**/*.vue），
  // typecheck:test 已是 src+tests 的超集——再跑 `vue-tsc --noEmit` 只是把全量 SFC
  // 类型检查重复一遍（构建期约 2× 时间）。
  assert.doesNotMatch(pkg.scripts.build, /(^|&& )vue-tsc --noEmit/, `build 不得重复全量类型检查: ${pkg.scripts.build}`)
})

test('证书卡：ACME 证书卡接入 configLoaded 双重门控（与 Basic/Caddy 同契约）', () => {
  const card = source('src/views/settings/FreeCertificates.vue')
  assert.match(card, /defineProps<\{ configLoaded: boolean \}>/)
  assert.match(card, /:disabled="isReadOnly \|\| !props\.configLoaded"/)
  const save = section(card, 'const handleSave = async', 'if (isReadOnly.value) return')
  assert.match(save, /!props\.configLoaded/, 'configLoaded 门必须早于常规写守卫')
  const page = source('src/views/Settings.vue')
  assert.match(page, /<FreeCertificates[\s\S]*?:config-loaded="configLoaded"/)
})

// ===== 设置/安全视图接线（证书队列、任务监控、集群、TLS、DNS 凭证、OIDC） =====

test('证书队列非空判据 = 排队 + 进行中 + 等 CA（任何一项 > 0 都非「空闲」）', () => {
  assert.equal(certQueueIsBusy({ queued: 0, running: 0, waiting: 0 }), false)
  assert.equal(certQueueIsBusy({ queued: 3, running: 0, waiting: 0 }), true, '全部排队时曾被误报空闲')
  assert.equal(certQueueIsBusy({ queued: 0, running: 0, waiting: 2 }), true, '等 CA 也是队列非空')
  assert.equal(certQueueIsBusy({ queued: 0, running: 1, waiting: 0 }), true)
  // 正文空态与「+N」不再依赖首页可见行
  assert.equal(certQueueHasLive({ total: 3 }), true)
  assert.equal(certQueueHasLive({ total: 0 }), false)
  assert.equal(certQueueShownCount({ jobs: [] }), 0)
  assert.equal(certQueueShownCount({ jobs: [{ id: 1 }, { id: 2 }] }), 2)
  assert.equal(CERT_QUEUE_VISIBLE_JOBS, 4)
  const base = { queued: 0, running: 5, waiting: 0 }
  assert.equal(certQueueMoreCount({ ...base, total: 10, jobs: [{ id: 1 }, { id: 2 }, { id: 3 }, { id: 4 }, { id: 5 }] }), 6)
  // 行数不足 4：原实现 total-4 会偏小/错位
  assert.equal(certQueueMoreCount({ ...base, total: 3, jobs: [{ id: 1 }] }), 2)
  assert.equal(certQueueMoreCount({ ...base, total: 0, jobs: [] }), 0)
})

test('证书队列横幅接线与 page_size=6', () => {
  const page = source('src/views/settings/TaskMonitor.vue')
  assert.match(page, /certQueueIsBusy\(certQueue\) \? 'primary' : 'success'/)
  assert.match(page, /v-else-if="certQueueHasLive\(certQueue\)"/)
  assert.match(page, /certQueue\.jobs\.slice\(0, CERT_QUEUE_VISIBLE_JOBS\)/)
  assert.match(page, /certQueueMoreCount\(certQueue\)/)
  assert.match(page, /const CERT_QUEUE_PAGE_SIZE = 6/)
  assert.match(page, /page_size: CERT_QUEUE_PAGE_SIZE/)
})

test('任务监控三份轮询请求缺 data 一律抛 TypeError（进入契约退避）', () => {
  const page = source('src/views/settings/TaskMonitor.vue')
  const tasks = section(page, 'const fetchTasks = async', 'const refreshNow =')
  assert.match(tasks, /if \(!res\.data\) throw new TypeError\('任务列表响应缺少 data'\)/)
  assert.match(tasks, /throw new TypeError\('任务统计响应缺少 data'\)/)
  const queue = section(page, 'const fetchCertQueue = async', '// ===== 概览统计 =====')
  assert.match(queue, /if \(!res\.data\) throw new TypeError\('证书队列响应缺少 data'\)/)
  // 必须在自身 catch 中继续向上抛，否则轮询入口永远看不到契约违约
  assert.match(queue, /if \(error instanceof TypeError\) throw error/)
})

test('任务详情弹框适配窄屏并实时派生（不持打开时快照）', () => {
  const page = source('src/views/settings/TaskMonitor.vue')
  assert.match(page, /<el-dialog v-model="detailVisible" width="min\(720px, 92vw\)"/)
  const block = section(page, 'const detailTask = computed<TaskInfo | null>', 'const history = ref')
  assert.match(block, /tasks\.value\.find\(t => t\.id === id\)/, '详情必须读最新轮询行而非打开时快照')
  assert.match(section(page, 'const openDetail = async', '// ===== 日志抽屉'), /detailTaskId\.value = row\.id/)
})

test('节点审批/拒绝/删除在确认弹框之前取得占位', () => {
  const block = section(source('src/views/settings/ClusterSettings.vue'), 'const confirmAndRunNodeAction = async', 'const approveNode = (node: ClusterNode)')
  const takePlaceholder = block.indexOf('pendingNodeId.value = node.id')
  const confirm = block.indexOf('confirmAction(')
  assert.ok(takePlaceholder >= 0 && confirm > takePlaceholder, '占位必须先于 confirmAction')
  assert.match(block, /pendingNodeId\.value !== null/, '第二请求必须被显式拒绝而非静默丢弃')
  const page = source('src/views/settings/ClusterSettings.vue')
  assert.match(page, /const approveNode = \(node: ClusterNode\): Promise<void> =>\n  confirmAndRunNodeAction\(/)
  assert.match(page, /const removeNode = \(node: ClusterNode\): Promise<void> =>\n  confirmAndRunNodeAction\(/)
})

test('服务控制/同步/同步设置/清钉同样在确认前占位', () => {
  const page = source('src/views/settings/ClusterSettings.vue')
  const service = section(page, 'const executeServiceControl = async', 'const forgetNodePin = async')
  assert.ok(service.indexOf('serviceControlLoading.value = true') < service.indexOf('confirmAction('), '服务控制占位须先于确认')
  const forgetPin = section(page, 'const forgetNodePin = async', 'const registerToken = ref')
  assert.ok(forgetPin.indexOf('nodePinForgetting.value = true') < forgetPin.indexOf('confirmAction('))
  const sync = section(page, 'const syncNow = async', 'const forgetPins = async')
  assert.ok(sync.indexOf('syncing.value = true') < sync.indexOf('confirmAction('))
  const syncField = section(page, 'const updateSyncField = async', 'const updateSyncInterval = async')
  assert.ok(syncField.indexOf('settingsLoading.value = true') < syncField.indexOf('confirmAction('))
  const pins = section(page, 'const forgetPins = async', 'const generateRegisterToken = async')
  assert.ok(pins.indexOf('forgettingPins.value = true') < pins.indexOf('confirmAction('))
})

test('TLS 文件选择器读完即复位（同路径重选可再次触发 change）', () => {
  const block = section(source('src/views/settings/BasicSettings.vue'), 'const onTlsFile = async', 'const notifyTlsRestarting')
  const reset = block.indexOf("input.value = ''")
  const firstUse = block.indexOf('adminTlsForm.value.certFile')
  assert.ok(reset >= 0 && reset < firstUse, 'file input 必须在读取后立即复位')
})

test('/admin-tls 读取失败显性化并提供重试', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  assert.match(page, /const adminTlsLoadFailed = ref\(false\)/)
  const load = section(page, 'const loadAdminTls = async', 'const retryLoadAdminTls')
  assert.match(load, /catch \{\n    adminTlsLoadFailed\.value = true/)
  assert.match(page, /const retryLoadAdminTls = \(\): void => \{ void loadAdminTls\(\) \}/)
  assert.match(page, /v-else-if="adminTlsLoadFailed"[\s\S]{0,400}retryLoadAdminTls/, '开关旁必须有错误文案与重试入口')
})

test('兜底提醒不承诺不会发生的自动跳转', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  assert.doesNotMatch(page, /若未自动跳转/)
  assert.match(page, /ElMessage\.warning\(`请手动访问新地址：\$\{target\}`\)/)
})

test('各写函数入口自带只读/在途守卫（纵深防御）', () => {
  const basic = source('src/views/settings/BasicSettings.vue')
  const checks: Array<[string, string, RegExp]> = [
    ['const saveAutoBackupSettings = async', '\nconst ', /if \(isReadOnly\.value \|\| !autoBackupSectionsValid\.value/],
    ['const restoreAutoBackup = async', '\nconst ', /if \(backupDisabled\.value\) return/],
    ['const deleteAutoBackup = async', '\nconst ', /if \(backupDisabled\.value\) return/],
    ['const confirmImport = async', '\nconst ', /if \(isReadOnly\.value\) return/],
  ]
  for (const [start, end, pattern] of checks) {
    assert.match(section(basic, start, end), pattern, `${start} 缺函数级写守卫`)
  }
  const caddy = source('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(section(caddy, 'const confirmSaveAsList = async', '\nconst '), /if \(isReadOnly\.value \|\| savingList\.value\) return/)
  const free = source('src/views/settings/FreeCertificates.vue')
  assert.match(section(free, 'const saveCAProvider = async', '\nconst '), /if \(isReadOnly\.value \|\| savingCA\.value\) return/)
  assert.match(section(free, 'const saveConfig = async', '\nconst '), /if \(isReadOnly\.value \|\| savingConfig\.value\) return/)
  assert.match(section(free, 'const deleteConfig = async', '\nconst '), /savingConfig\.value/)
  // 两个「测试」端点会真实写 DNS TXT / 申请 EAB（后端非只读豁免）
  assert.match(section(free, 'const testCAProvider = async', '\nconst '), /if \(isReadOnly\.value \|\| isTesting\.value\) return/)
  assert.match(section(free, 'const testConfig = async', '\nconst '), /if \(isReadOnly\.value \|\| isTesting\.value \|\| !config\.id\) return/)
  assert.match(section(basic, 'const openAdminTlsDialog = () => {', '\nconst '), /if \(isReadOnly\.value\) return/)
  const oidc = source('src/views/settings/OIDCSettings.vue')
  assert.match(section(oidc, 'const save = async', '\nconst '), /if \(isReadOnly\.value \|\| saving\.value\) return/)
  assert.match(section(oidc, 'const toggleEnabled = async', '\nconst '), /if \(isReadOnly\.value \|\| saving\.value \|\| loadFailed\.value\) return/)
  assert.match(section(oidc, 'const remove = async', '\nconst '), /if \(isReadOnly\.value \|\| saving\.value \|\| loadFailed\.value\) return/)
})

test('CA 表单不再持有零读取的 credentials 副本', () => {
  const page = source('src/views/settings/FreeCertificates.vue')
  const block = section(page, 'const caForm = reactive', 'const caCreds = reactive')
  assert.doesNotMatch(block, /credentials: '\{\}'/, 'caForm 初始值不得再含零读取的 credentials')
  assert.match(page, /reactive<Omit<CAProvider, 'credentials'>>/)
})

test('DNS 凭证字段可见性按 visible_when 求值，无元数据时恒显示', () => {
  const fields = [
    { name: 'auth_mode', label: '认证方式', type: 'select', required: true, options: ['dnspod', 'tencent_cloud'], option_labels: { dnspod: 'DNSPod API', tencent_cloud: '腾讯云 API' } },
    { name: 'app_id', label: 'App ID', type: 'text', required: false, visible_when: { auth_mode: ['dnspod'] } },
    { name: 'secret_id', label: 'SecretId', type: 'text', required: false, visible_when: { auth_mode: ['tencent_cloud'] } },
    { name: 'future_field', label: '未来字段', type: 'text', required: false },
  ]
  assert.equal(credentialFieldVisible(fields[1], { auth_mode: 'dnspod' }), true)
  assert.equal(credentialFieldVisible(fields[1], { auth_mode: 'tencent_cloud' }), false)
  assert.equal(credentialFieldVisible(fields[2], { auth_mode: 'tencent_cloud' }), true)
  assert.equal(credentialFieldVisible(fields[3], {}), true, '新 provider 无元数据字段不得被隐藏')
  assert.equal(credentialOptionLabel(fields[0], 'dnspod'), 'DNSPod API')
  assert.equal(credentialOptionLabel(fields[0], 'unknown'), 'unknown')
  assert.deepEqual(defaultCredentialsFor(fields), { auth_mode: 'dnspod' })
  assert.deepEqual(defaultCredentialsFor([]), {})
})

test('后端下发 visible_when/option_labels，前端不再硬编码 dnspod 字段名', () => {
  const go = source('../internal/services/dnsproviders/dnspod.go')
  const cf = section(go, 'func (d *DNSPod) CredentialFields()', '\nfunc (d *DNSPod) CredentialFieldOptions')
  assert.match(cf, /VisibleWhen: visibleOnly\("dnspod"\)/)
  assert.match(cf, /VisibleWhen: visibleOnly\("tencent_cloud"\)/)
  assert.match(cf, /OptionLabels: map\[string\]string\{"dnspod": "DNSPod API", "tencent_cloud": "腾讯云 API"\}/)
  const handler = source('../internal/handlers/certificates.go')
  const list = section(handler, 'func (h *Handlers) ListDNSProviders', 'func (h *Handlers) TestCertificateConfig')
  assert.match(list, /field\["visible_when"\] = f\.VisibleWhen/)
  assert.match(list, /field\["option_labels"\] = f\.OptionLabels/)
  const vue = source('src/views/settings/FreeCertificates.vue')
  assert.match(vue, /credentialFieldVisible\(field, form\.value\.dns_credentials\)/)
  assert.match(vue, /:label="credentialOptionLabel\(field, opt\)"/)
  assert.doesNotMatch(vue, /field\.name === 'auth_mode'\) return true/)
  assert.doesNotMatch(vue, /opt === 'dnspod' \? 'DNSPod API' : '腾讯云 API'/)
})

test('OIDC GET 失败清空为未配置态并禁止保存（不得回填上一轮状态）', () => {
  const page = source('src/views/settings/OIDCSettings.vue')
  const load = section(page, 'const load = async', 'let probeInFlight')
  const catchAt = load.indexOf('} catch {')
  assert.ok(catchAt > 0, 'load 缺 catch 分支')
  const catchBlock = load.slice(catchAt)
  for (const cleared of ['enabled.value = false', 'hasSecret.value = false', 'hasFetchedConfig.value = false', "form.issuer = ''", 'loadFailed.value = true']) {
    assert.ok(catchBlock.includes(cleared), `load catch 未复位 ${cleared}——父级会回填陈旧状态`)
  }
  assert.match(page, /v-if="loadFailed" type="error"/)
  assert.match(section(page, 'const save = async', '\nconst '), /if \(loadFailed\.value\)/)
})
