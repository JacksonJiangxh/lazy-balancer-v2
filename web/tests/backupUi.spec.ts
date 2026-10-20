import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

// 设置页备份面回归守卫：导入入口/超大文件拒绝、lbbak Blob 直传、还原文案按分类、
// 下次备份调度口径、立即备份的卸载收尾，以及备份四分类前后端单源一致性。
const page = source('src/views/settings/BasicSettings.vue')

test('新文件入口先清旧内容，超大拒绝不可回用旧备份', () => {
  // 终点用「下一个函数声明」而非注释文本——注释终点可能落在本函数内部，
  // 切片会延伸到后续函数（该区间出现 48MB 字样即假红）。
  const body = section(page, 'const handleImportFile', 'const postImportValidation')
  const oversized = body.indexOf('if (file.size > IMPORT_MAX_BYTES)')
  assert.ok(oversized > 0)
  const beforeReject = body.slice(0, oversized)
  for (const reset of [
    "importFileContent.value = ''",
    'importFileIsLbbak.value = false',
    'importSections.value = []',
    'importValidation.value = null',
  ]) {
    assert.ok(beforeReject.includes(reset), `missing pre-reject reset: ${reset}`)
  }
  assert.match(page, /const IMPORT_MAX_BYTES = 128 \* 1024 \* 1024/)
  assert.doesNotMatch(body, /48MB|48 \* 1024/)
})

test('lbbak 以 Blob 直传，不复制成第二个 ArrayBuffer', () => {
  const body = section(page, 'const handleImportFile', 'const postImportValidation')
  assert.match(body, /importFileContent\.value = file\.slice\(bomLen\)/)
  assert.doesNotMatch(body, /file\.slice\(bomLen\)\.arrayBuffer\(\)/)
  assert.match(page, /ref<string \| Blob>\(''\)/)
})

test('还原文案按备份分类，失败行不显示下载', () => {
  const restore = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  assert.match(restore, /autoBackupScopeText\(row\)/)
  assert.match(restore, /覆盖该备份包含的分类/)
  assert.doesNotMatch(restore, /覆盖当前全部配置/)
  assert.match(page, /<el-button v-if="row\.status === 'success'" link type="primary" size="small" @click="downloadAutoBackup\(row\)">下载<\/el-button>/)
})

test('下次备份只消费调度器返回值并标明补跑', () => {
  const label = section(page, 'const autoBackupNextRunLabel', '// 与导出按钮同口径')
  assert.match(label, /autoBackupNextRunAt\.value/)
  assert.match(label, /autoBackupCatchUpDue\.value/)
  assert.match(label, /待补跑/)
  assert.doesNotMatch(label, /autoBackupForm|Intl\.DateTimeFormat/)
  assert.match(page, /next_run_at: string \| null/)
  assert.match(page, /catch_up_due: boolean/)
})

test('立即备份按已保存范围门控，60 秒无结果有提示', () => {
  assert.match(page, /:disabled="!autoBackupCanRunNow" title="按已保存的自动备份设置执行一次备份/)
  const run = section(page, 'const runAutoBackupNow', '// 备份大小')
  assert.match(run, /if \(!autoBackupCanRunNow\.value\)/)
  assert.doesNotMatch(run, /if \(!autoBackupSectionsValid\.value\)/)
  assert.match(run, /else if \(!completed && autoBackupVisible\.value\)/)
  assert.match(run, /60 秒内未检测到本次备份结果/)
  const saved = section(page, 'const saveAutoBackupSettings', '// 「立即备份」')
  assert.match(saved, /autoBackupSavedSections\.value = \[\.\.\.autoBackupSections\.value\]/)
})

// 点「立即备份」后切到其它设置页（组件卸载）：轮询只以弹框可见为门时，
// 卸载后仍每 2s 拉取最多 30 次并在其它页面弹结果 toast。
test('立即备份轮询在组件卸载后终止且不再弹结果', () => {
  const run = section(page, 'const runAutoBackupNow', '// 备份大小')
  assert.match(run, /while \(!disposed && autoBackupVisible\.value && Date\.now\(\) < deadline\)/)
  assert.match(run, /if \(disposed\) break/)
  const afterLoop = section(run, 'if (disposed) return', 'if (completed?.status')
  assert.match(afterLoop, /if \(disposed\) return/)
})

// 取消到 0 个分类时，预览摘要/冲突必须与按钮同门：revalidateImport 早退会让
// 面板继续展示上一次选择的摘要，且确认按钮可点（点了才提示）。
test('0 分类选择隐藏陈旧预览并把确认按钮置灰', () => {
  assert.match(page, /const importPreviewSelected = computed<boolean>\(\(\) => importSections\.value\.length > 0\)/)
  assert.match(page, /<template v-if="importValidation\.valid && importPreviewSelected">/)
  assert.match(page, /v-else-if="importValidation\.valid" class="info-note-bar import-alert"><span class="info-note-desc">未选择导入分类/)
  const button = section(page, ':disabled="!importValidation?.valid', ':loading="importing"')
  assert.match(button, /!importPreviewSelected/)
  assert.match(button, /isReadOnly/)
})

// ---- 备份分类单源：从 BasicSettings.vue 抽取真实声明求值 ----
interface BackupSection { key: string; label: string }
interface BackupSectionsModule {
  BACKUP_SECTIONS: readonly BackupSection[]
  LEGACY_SECTION_ALIASES: Record<string, string>
  normalizeBackupSectionKeys: (keys: string[]) => string[]
}

const loadBackupSections = (): BackupSectionsModule => {
  const page = source('src/views/settings/BasicSettings.vue')
  const block = section(page, 'const BACKUP_SECTIONS', 'const exportSections')
  // 剥离 TS 类型标注后求值（形态变化会显性抛错=守卫生效，非静默漂移）
  const js = block
    .replace(/ as const/g, '')
    .replace(/: Record<string, string>/g, '')
    .replace(/\(keys: string\[\]\): string\[\]/g, '(keys)')
    .replace(/new Set<string>\(\)/g, 'new Set()')
    .replace(/const out: string\[\]/g, 'const out')
  const factory = new Function(`${js}; return { BACKUP_SECTIONS, LEGACY_SECTION_ALIASES, normalizeBackupSectionKeys }`)
  return factory() as BackupSectionsModule
}

test('备份分类恰好四键且标签与后端口径一致', () => {
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

test('legacy 分类键归一行为（映射/去重/保序/未知键透传）', () => {
  const { LEGACY_SECTION_ALIASES, normalizeBackupSectionKeys } = loadBackupSections()
  assert.deepEqual(LEGACY_SECTION_ALIASES, { global_config: 'users', waf_files: 'security' })
  assert.deepEqual(normalizeBackupSectionKeys(['global_config', 'waf_files']), ['users', 'security'], 'legacy 键读出即归一')
  assert.deepEqual(normalizeBackupSectionKeys(['users', 'global_config']), ['users'], '归一后与显式键去重')
  assert.deepEqual(normalizeBackupSectionKeys(['waf_files', 'global_config']), ['security', 'users'], '保序')
  assert.deepEqual(normalizeBackupSectionKeys(['future_key']), ['future_key'], '未知键透传（向前兼容）')
  assert.deepEqual(normalizeBackupSectionKeys([]), [])
})

test('导出/自动备份默认全选四分类，恢复路径必经归一', () => {
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
