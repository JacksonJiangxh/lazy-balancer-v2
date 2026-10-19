// A86 历史问题 新功能回归守卫：备份四分类（含节点拓扑）/ 威胁大屏全屏布局 /
// 节点站点列——关键逻辑从 SFC 源码抽取后**求值做行为断言**（非纯文本钉）；
// 另含 A86 历史问题 大屏 hidden 修复的组件接线钉（限段、带边界，防空转）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const source = (relative: string): string => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')

const sectionBetween = (text: string, startMarker: string, endMarker: string): string => {
  const start = text.indexOf(startMarker)
  assert.ok(start >= 0, `missing start marker: ${startMarker}`)
  const end = text.indexOf(endMarker, start + startMarker.length)
  assert.ok(end > start, `missing end marker: ${endMarker}`)
  return text.slice(start, end)
}

// ---- 备份四分类：从 BasicSettings.vue 抽取真实声明求值 ----
interface BackupSection { key: string; label: string }
interface BackupSectionsModule {
  BACKUP_SECTIONS: readonly BackupSection[]
  LEGACY_SECTION_ALIASES: Record<string, string>
  normalizeBackupSectionKeys: (keys: string[]) => string[]
}

const loadBackupSections = (): BackupSectionsModule => {
  const page = source('src/views/settings/BasicSettings.vue')
  const block = sectionBetween(page, 'const BACKUP_SECTIONS', 'const exportSections')
  // 剥离 TS  Only 语法后求值（形态变化会显性抛错=守卫生效，非静默漂移）
  const js = block
    .replace(/ as const/g, '')
    .replace(/: Record<string, string>/g, '')
    .replace(/\(keys: string\[\]\): string\[\]/g, '(keys)')
    .replace(/new Set<string>\(\)/g, 'new Set()')
    .replace(/const out: string\[\]/g, 'const out')
  const factory = new Function(`${js}; return { BACKUP_SECTIONS, LEGACY_SECTION_ALIASES, normalizeBackupSectionKeys }`)
  return factory() as BackupSectionsModule
}

test('A86 历史问题：备份分类恰好四键且标签与后端口径一致', () => {
  const { BACKUP_SECTIONS } = loadBackupSections()
  assert.deepEqual(
    BACKUP_SECTIONS.map((s) => [s.key, s.label]),
    [['users', '系统数据'], ['rules', '负载规则'], ['security', '安全防护'], ['cluster', '节点拓扑']],
  )
  // 跨栈一致性：后端 configBackupSections 单源派生键/标签必须同集同序
  const go = source('../internal/handlers/config_backup.go')
  const goBlock = sectionBetween(go, 'var configBackupSections = []struct', '\n}\n')
  const goPairs = [...goBlock.matchAll(/\{Key: "(\w+)", Label: "([^"]+)"/g)].map((m) => [m[1], m[2]])
  assert.deepEqual(BACKUP_SECTIONS.map((s) => [s.key, s.label]), goPairs, '前后端分类键/标签漂移会静默改变导出/还原覆盖面')
})

test('A86 历史问题：legacy 分类键归一行为（映射/去重/保序/未知键透传）', () => {
  const { LEGACY_SECTION_ALIASES, normalizeBackupSectionKeys } = loadBackupSections()
  assert.deepEqual(LEGACY_SECTION_ALIASES, { global_config: 'users', waf_files: 'security' })
  assert.deepEqual(normalizeBackupSectionKeys(['global_config', 'waf_files']), ['users', 'security'], 'legacy 键读出即归一')
  assert.deepEqual(normalizeBackupSectionKeys(['users', 'global_config']), ['users'], '归一后与显式键去重')
  assert.deepEqual(normalizeBackupSectionKeys(['waf_files', 'global_config']), ['security', 'users'], '保序')
  assert.deepEqual(normalizeBackupSectionKeys(['future_key']), ['future_key'], '未知键透传（向前兼容）')
  assert.deepEqual(normalizeBackupSectionKeys([]), [])
})

test('A86 历史问题：导出/自动备份默认全选四分类，恢复路径必经归一', () => {
  const { BACKUP_SECTIONS, normalizeBackupSectionKeys } = loadBackupSections()
  const allKeys = BACKUP_SECTIONS.map((s) => s.key)
  assert.deepEqual(normalizeBackupSectionKeys(allKeys), allKeys)
  const page = source('src/views/settings/BasicSettings.vue')
  // 默认全选两处（导出对话框 + 自动备份表单）
  assert.match(page, /const exportSections = ref<string\[\]>\(BACKUP_SECTIONS\.map\(\(s\) => s\.key\)\)/)
  assert.match(page, /const autoBackupSections = ref<string\[\]>\(BACKUP_SECTIONS\.map\(\(s\) => s\.key\)\)/)
  // 恢复路径两处消费归一：自动备份设置载入 + 历史备份行分类标签
  const loadBlock = sectionBetween(page, 'const loadedSections', 'autoBackupSavedSections.value = [...loadedSections]')
  assert.match(loadBlock, /normalizeBackupSectionKeys\(d\.sections\)/)
  const labelBlock = sectionBetween(page, 'const labels = normalizeBackupSectionKeys', '.map((k) => BACKUP_SECTIONS.find')
  assert.match(labelBlock, /row\.sections \|\| \[\]/)
})

// ---- 威胁大屏全屏布局分支 ----
test('A86 历史问题：大屏全屏分支不进 AppLayout（侧栏顶栏不得渲染）', () => {
  const app = source('src/App.vue')
  const template = sectionBetween(app, '<template>', '</template>')
  const threatIdx = template.indexOf(`<ThreatScreen v-else-if="currentPage === 'threat-screen'" />`)
  assert.ok(threatIdx > 0, '缺大屏全屏分支')
  const layoutIdx = template.indexOf('<AppLayout')
  assert.ok(threatIdx < layoutIdx, '大屏分支必须先于 AppLayout（v-else-if 短路）')
  assert.match(template.slice(layoutIdx), /^<AppLayout v-else>/, 'AppLayout 必须是 v-else——大屏页不得套布局壳')
  assert.ok(!sectionBetween(template, '<AppLayout', '</AppLayout>').includes('ThreatScreen'), '大屏不得在 AppLayout 内部渲染')
  // 页面键唯一事实源含 threat-screen（抽取真实数组求值）
  const auth = source('src/stores/auth.ts')
  const pagesBlock = sectionBetween(auth, 'const pages = [', '] as const').slice('const pages = ['.length)
  const pages = new Function(`return [${pagesBlock}]`)() as string[]
  assert.ok(pages.includes('threat-screen'), 'auth 页面键缺 threat-screen（深链/刷新恢复会失效）')
})

// ---- A86 历史问题 组件接线钉（行为见 visibilityIntervals.spec.ts） ----
test('A86 历史问题：ThreatScreen 经 createVisibilityIntervals 接管 hidden 停摆', () => {
  const page = source('src/views/security/ThreatScreen.vue')
  assert.match(page, /import \{ createVisibilityIntervals \} from '@\/composables\/useVisibilityIntervals'/)
  const loopBlock = sectionBetween(page, 'const screenLoop = createVisibilityIntervals({', '})')
  // 三类间隔全部纳管：时钟(1s, immediate)/弧光冲刷(ARC_FLUSH_MS)/采集租约心跳(immediate)
  assert.match(loopBlock, /\{ tick: tickClock, ms: 1000, immediate: true \}/)
  assert.match(loopBlock, /\{ tick: flushArcs, ms: ARC_FLUSH_MS \}/)
  assert.match(loopBlock, /\{ tick: acquireCollector, ms: COLLECTOR_HEARTBEAT_MS, immediate: true \}/)
  // hidden 回调必须释放租约；visible 回调必须重置流量游标
  const onHidden = sectionBetween(page, 'onHidden: () => {', 'onVisible: () => {')
  assert.match(onHidden, /releaseCollector\(\)/, 'hidden 不释放租约=Caddy 后台空计数')
  const onVisible = sectionBetween(page, 'onVisible: () => {', '\n})')
  assert.match(onVisible, /flowCursorEpoch\+\+/)
  assert.match(onVisible, /applyMapPause\(\)/)
  // SFC 内不得再直挂 visibilitychange（单源在 composable）
  assert.doesNotMatch(page, /document\.(add|remove)EventListener\('visibilitychange'/)
  // 渲染暂停判据=手动暂停 ∨ 页面隐藏
  const pauseBlock = sectionBetween(page, 'function applyMapPause(): void {', '}')
  assert.match(pauseBlock, /setPaused\(paused\.value \|\| screenHidden\)/)
  // 卸载收尾：停 loop + 释放租约
  const unmountBlock = sectionBetween(page, 'onBeforeUnmount(() => {', '})')
  assert.match(unmountBlock, /screenLoop\.stop\(\)/)
  assert.match(unmountBlock, /releaseCollector\(\)/)
})

// ---- 节点站点列（ClusterMasterPanel 只读抽取，不改组件） ----
test('A86 历史问题：站点坐标列渲染/继承标注行为与响应式列隐藏阈值', () => {
  const panel = source('src/views/settings/cluster/ClusterMasterPanel.vue')
  // siteCoordinateLabel 抽取求值（真实行为）
  const fnBlock = sectionBetween(panel, 'const siteCoordinateLabel = ', 'const operationColumnFixed')
  const js = fnBlock.replace(/\(node: ClusterNode\): string/g, '(node)')
  const siteCoordinateLabel = new Function(`${js}; return siteCoordinateLabel`)() as (node: { server_map_lat?: number | null; server_map_lon?: number | null; site_inherited?: boolean }) => string
  assert.equal(siteCoordinateLabel({ server_map_lat: 0, server_map_lon: 0 }), '未配置')
  assert.equal(siteCoordinateLabel({}), '未配置', '缺省坐标按未配置渲染')
  assert.equal(siteCoordinateLabel({ server_map_lat: 35.19, server_map_lon: 108.87, site_inherited: false }), '35.19, 108.87')
  assert.equal(siteCoordinateLabel({ server_map_lat: 35.19, server_map_lon: 108.87, site_inherited: true }), '35.19, 108.87（默认）', '继承主节点坐标必须标注（默认）')
  // 站点列可点编辑且只读禁用
  const column = sectionBetween(panel, '<el-table-column label="站点坐标"', '</el-table-column>')
  assert.match(column, /\$emit\('edit-site', row\)/)
  assert.match(column, /:disabled="readOnly"/)
  // 响应式列隐藏阈值（求值边界两侧）
  for (const [name, marker] of [['showHealthColumn', 'const showHealthColumn'], ['showLastSeenColumn', 'const showLastSeenColumn']] as const) {
    const expr = panel.match(new RegExp(`${marker} = computed\\(\\(\\) => viewportWidth\\.value >= (\\d+)\\)`))
    assert.ok(expr, `缺 ${name} 阈值表达式`)
    const threshold = Number(expr[1])
    const visible = new Function('w', `return w >= ${threshold}`) as (w: number) => boolean
    assert.equal(visible(threshold - 1), false, `${name} 阈值下界应隐藏`)
    assert.equal(visible(threshold), true, `${name} 达阈值应显示`)
  }
})
