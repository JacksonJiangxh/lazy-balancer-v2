import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const page = readFileSync(new URL('../src/views/settings/BasicSettings.vue', import.meta.url), 'utf8')
const section = (startMarker: string, endMarker: string): string => {
  const start = page.indexOf(startMarker)
  assert.ok(start >= 0, `missing start marker ${startMarker}`)
  const end = page.indexOf(endMarker, start + startMarker.length)
  assert.ok(end > start, `missing end marker ${endMarker}`)
  return page.slice(start, end)
}

test('A85历史问题-1：新文件入口先清旧内容，超大拒绝不可回用旧备份', () => {
  const body = section('const handleImportFile', '// 历史问题-02')
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
  const body = section('const handleImportFile', '// 历史问题-02')
  assert.match(body, /importFileContent\.value = file\.slice\(bomLen\)/)
  assert.doesNotMatch(body, /file\.slice\(bomLen\)\.arrayBuffer\(\)/)
  assert.match(page, /ref<string \| Blob>\(''\)/)
})

test('A85历史问题-8/历史问题：还原文案按备份分类，失败行不显示下载', () => {
  const restore = section('const restoreAutoBackup', 'const deleteAutoBackup')
  assert.match(restore, /autoBackupScopeText\(row\)/)
  assert.match(restore, /覆盖该备份包含的分类/)
  assert.doesNotMatch(restore, /覆盖当前全部配置/)
  assert.match(page, /<el-button v-if="row\.status === 'success'" link type="primary" size="small" @click="downloadAutoBackup\(row\)">下载<\/el-button>/)
})

test('A85历史问题-2：下次备份只消费调度器返回值并标明补跑', () => {
  const label = section('const autoBackupNextRunLabel', '// 与导出按钮同口径')
  assert.match(label, /autoBackupNextRunAt\.value/)
  assert.match(label, /autoBackupCatchUpDue\.value/)
  assert.match(label, /待补跑/)
  assert.doesNotMatch(label, /autoBackupForm|Intl\.DateTimeFormat/)
  assert.match(page, /next_run_at: string \| null/)
  assert.match(page, /catch_up_due: boolean/)
})

test('A85历史问题-6：立即备份按已保存范围门控，60 秒无结果有提示', () => {
  assert.match(page, /:disabled="!autoBackupCanRunNow" title="按已保存的自动备份设置执行一次备份/)
  const run = section('const runAutoBackupNow', '// 备份大小')
  assert.match(run, /if \(!autoBackupCanRunNow\.value\)/)
  assert.doesNotMatch(run, /if \(!autoBackupSectionsValid\.value\)/)
  assert.match(run, /else if \(!completed && autoBackupVisible\.value\)/)
  assert.match(run, /60 秒内未检测到本次备份结果/)
  const saved = section('const saveAutoBackupSettings', '// 「立即备份」')
  assert.match(saved, /autoBackupSavedSections\.value = \[\.\.\.autoBackupSections\.value\]/)
})
