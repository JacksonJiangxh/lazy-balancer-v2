// A86 历史问题 新功能回归守卫：备份四分类（含节点拓扑）/ 威胁大屏全屏布局 /
// 节点站点列——关键逻辑从 SFC 源码抽取后**求值做行为断言**（非纯文本钉）；
// 另含 A86 历史问题 大屏 hidden 修复的组件接线钉（限段、带边界，防空转）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

// ---- 备份四分类：从 BasicSettings.vue 抽取真实声明求值 ----
interface BackupSection { key: string; label: string }
interface BackupSectionsModule {
  BACKUP_SECTIONS: readonly BackupSection[]
  LEGACY_SECTION_ALIASES: Record<string, string>
  normalizeBackupSectionKeys: (keys: string[]) => string[]
}

const loadBackupSections = (): BackupSectionsModule => {
  const page = source('src/views/settings/BasicSettings.vue')
  const block = section(page, 'const BACKUP_SECTIONS', 'const exportSections')
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
  const goBlock = section(go, 'var configBackupSections = []struct', '\n}\n')
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
  const loadBlock = section(page, 'const loadedSections', 'autoBackupSavedSections.value = [...loadedSections]')
  assert.match(loadBlock, /normalizeBackupSectionKeys\(d\.sections\)/)
  const labelBlock = section(page, 'const labels = normalizeBackupSectionKeys', '.map((k) => BACKUP_SECTIONS.find')
  assert.match(labelBlock, /row\.sections \|\| \[\]/)
})

// ---- 威胁大屏全屏布局分支 ----
test('A86 历史问题：大屏全屏分支不进 AppLayout（侧栏顶栏不得渲染）', () => {
  const app = source('src/App.vue')
  // 审计 87 WEBT-09②：终点用「顶层 template 收尾 + script 起点」而非首个
  // `</template>`——当前 App.vue 无嵌套 template，但模板一引入嵌套（el-table
  // 插槽等）首标记即截断，断言对象悄悄变短。
  const template = section(app, '<template>', '\n</template>\n\n<script')
  const threatIdx = template.indexOf(`<ThreatScreen v-else-if="currentPage === 'threat-screen'" />`)
  assert.ok(threatIdx > 0, '缺大屏全屏分支')
  const layoutIdx = template.indexOf('<AppLayout')
  assert.ok(threatIdx < layoutIdx, '大屏分支必须先于 AppLayout（v-else-if 短路）')
  assert.match(template.slice(layoutIdx), /^<AppLayout v-else>/, 'AppLayout 必须是 v-else——大屏页不得套布局壳')
  assert.ok(!section(template, '<AppLayout', '</AppLayout>').includes('ThreatScreen'), '大屏不得在 AppLayout 内部渲染')
  // 页面键唯一事实源含 threat-screen（抽取真实数组求值）
  const auth = source('src/stores/auth.ts')
  const pagesBlock = section(auth, 'const pages = [', '] as const').slice('const pages = ['.length)
  const pages = new Function(`return [${pagesBlock}]`)() as string[]
  assert.ok(pages.includes('threat-screen'), 'auth 页面键缺 threat-screen（深链/刷新恢复会失效）')
})

// ---- A86 历史问题 组件接线钉（行为见 visibilityIntervals.spec.ts） ----
test('A86 历史问题：ThreatScreen 经 createVisibilityIntervals 接管 hidden 停摆', () => {
  const page = source('src/views/security/ThreatScreen.vue')
  assert.match(page, /import \{ createVisibilityIntervals \} from '@\/composables\/useVisibilityIntervals'/)
  const loopBlock = section(page, 'const screenLoop = createVisibilityIntervals({', '})')
  // 三类间隔全部纳管：时钟(1s, immediate)/弧光冲刷(ARC_FLUSH_MS)/采集租约心跳(immediate)
  assert.match(loopBlock, /\{ tick: tickClock, ms: 1000, immediate: true \}/)
  assert.match(loopBlock, /\{ tick: flushArcs, ms: ARC_FLUSH_MS \}/)
  assert.match(loopBlock, /\{ tick: acquireCollector, ms: COLLECTOR_HEARTBEAT_MS, immediate: true \}/)
  // hidden 回调必须释放租约；visible 回调必须重置流量游标
  const onHidden = section(page, 'onHidden: () => {', 'onVisible: () => {')
  assert.match(onHidden, /releaseCollector\(\)/, 'hidden 不释放租约=Caddy 后台空计数')
  const onVisible = section(page, 'onVisible: () => {', '\n})')
  assert.match(onVisible, /flowCursorEpoch\+\+/)
  assert.match(onVisible, /applyMapPause\(\)/)
  // SFC 内不得再直挂 visibilitychange（单源在 composable）
  assert.doesNotMatch(page, /document\.(add|remove)EventListener\('visibilitychange'/)
  // 渲染暂停判据=手动暂停 ∨ 页面隐藏
  const pauseBlock = section(page, 'function applyMapPause(): void {', '}')
  assert.match(pauseBlock, /setPaused\(paused\.value \|\| screenHidden\)/)
  // 卸载收尾：停 loop + 释放租约
  const unmountBlock = section(page, 'onBeforeUnmount(() => {', '})')
  assert.match(unmountBlock, /screenLoop\.stop\(\)/)
  assert.match(unmountBlock, /releaseCollector\(\)/)
})

test('W87-11/W87-12：威胁大屏死选择器清理与「被攻击目标」空态文案', () => {
  const page = source('src/views/security/ThreatScreen.vue')
  assert.doesNotMatch(page, /\.ev-icon svg/)
  assert.doesNotMatch(page, /\.scanline/)
  assert.doesNotMatch(page, /\.viewport-grid/)
  assert.match(page, /<div v-else class="empty">暂无目标数据<\/div>/)
})
