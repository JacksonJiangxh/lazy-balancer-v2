import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

const page = source('src/views/settings/BasicSettings.vue')

test('A85历史问题-1：新文件入口先清旧内容，超大拒绝不可回用旧备份', () => {
  // 审计 87 WEBT-09①：终点用「下一个函数声明」而非注释文本——原终点
  // `// 历史问题-02` 落在本函数内部，切片延伸到后续函数（该区间出现 48MB 字样即假红）。
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

test('A85历史问题-1：lbbak 以 Blob 直传，不复制成第二个 ArrayBuffer', () => {
  const body = section(page, 'const handleImportFile', 'const postImportValidation')
  assert.match(body, /importFileContent\.value = file\.slice\(bomLen\)/)
  assert.doesNotMatch(body, /file\.slice\(bomLen\)\.arrayBuffer\(\)/)
  assert.match(page, /ref<string \| Blob>\(''\)/)
})

test('A85历史问题-8/历史问题：还原文案按备份分类，失败行不显示下载', () => {
  const restore = section(page, 'const restoreAutoBackup', 'const deleteAutoBackup')
  assert.match(restore, /autoBackupScopeText\(row\)/)
  assert.match(restore, /覆盖该备份包含的分类/)
  assert.doesNotMatch(restore, /覆盖当前全部配置/)
  assert.match(page, /<el-button v-if="row\.status === 'success'" link type="primary" size="small" @click="downloadAutoBackup\(row\)">下载<\/el-button>/)
})

test('A85历史问题-2：下次备份只消费调度器返回值并标明补跑', () => {
  const label = section(page, 'const autoBackupNextRunLabel', '// 与导出按钮同口径')
  assert.match(label, /autoBackupNextRunAt\.value/)
  assert.match(label, /autoBackupCatchUpDue\.value/)
  assert.match(label, /待补跑/)
  assert.doesNotMatch(label, /autoBackupForm|Intl\.DateTimeFormat/)
  assert.match(page, /next_run_at: string \| null/)
  assert.match(page, /catch_up_due: boolean/)
})

test('A85历史问题-6：立即备份按已保存范围门控，60 秒无结果有提示', () => {
  assert.match(page, /:disabled="!autoBackupCanRunNow" title="按已保存的自动备份设置执行一次备份/)
  const run = section(page, 'const runAutoBackupNow', '// 备份大小')
  assert.match(run, /if \(!autoBackupCanRunNow\.value\)/)
  assert.doesNotMatch(run, /if \(!autoBackupSectionsValid\.value\)/)
  assert.match(run, /else if \(!completed && autoBackupVisible\.value\)/)
  assert.match(run, /60 秒内未检测到本次备份结果/)
  const saved = section(page, 'const saveAutoBackupSettings', '// 「立即备份」')
  assert.match(saved, /autoBackupSavedSections\.value = \[\.\.\.autoBackupSections\.value\]/)
})

// WS-08：点「立即备份」后切到其它设置页（组件卸载）——原轮询只以弹框可见为门，
// 卸载后仍每 2s 拉取最多 30 次并在其它页面弹结果 toast。
test('WS-08：立即备份轮询在组件卸载后终止且不再弹结果', () => {
  const run = section(page, 'const runAutoBackupNow', '// 备份大小')
  assert.match(run, /while \(!disposed && autoBackupVisible\.value && Date\.now\(\) < deadline\)/)
  assert.match(run, /if \(disposed\) break/)
  const afterLoop = run.slice(run.indexOf('if (disposed) return'), run.indexOf('if (completed?.status'))
  assert.match(afterLoop, /if \(disposed\) return/)
})

// WS-10：取消到 0 个分类时，预览摘要/冲突必须与按钮同门——原 revalidateImport
// 早退，面板继续展示上一次选择的摘要，且确认按钮可点（点了才提示）。
test('WS-10：0 分类选择隐藏陈旧预览并把确认按钮置灰', () => {
  assert.match(page, /const importPreviewSelected = computed<boolean>\(\(\) => importSections\.value\.length > 0\)/)
  assert.match(page, /<template v-if="importValidation\.valid && importPreviewSelected">/)
  assert.match(page, /v-else-if="importValidation\.valid" class="info-note-bar import-alert"><span class="info-note-desc">未选择导入分类/)
  const button = section(page, ':disabled="!importValidation?.valid', ':loading="importing"')
  assert.match(button, /!importPreviewSelected/)
  assert.match(button, /isReadOnly/)
})
