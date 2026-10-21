import test from 'node:test'
import assert from 'node:assert/strict'
import { source, section, repoSource } from './_helpers.ts'

// 任务监控=通用任务视图（2026-10-22 用户裁定）：任务列表只呈现通用字段——
// 名称/分类/类型/状态（空闲·运行中·失败）/调度/执行时间/计数/操作。
// 证书生命周期态（已签发/限流中/已禁用…）由免费证书页与规则 TLS 列维护，
// 任务列表的任何列（名称列、状态列、状态词表、兜底）均不得引入业务词表。

const vue = source('src/views/settings/TaskMonitor.vue')
const statusColumn = section(vue, '<el-table-column label="状态"', '</el-table-column>')
const taskColumn = section(vue, '<el-table-column label="任务"', '</el-table-column>')
const svc = repoSource('internal/services/taskmonitor.go')

test('任务名称列只渲染任务名（无业务态子文本/徽标）', () => {
  assert.doesNotMatch(taskColumn, /tm-cert-sub|certJobLabel|certJobRawStatus/, '名称列不得出现证书生命周期态')
  assert.match(taskColumn, /tm-task-name/)
})

test('状态列只由引擎 status 渲染（三态，无业务态覆盖）', () => {
  assert.doesNotMatch(statusColumn, /certJobLabel|certJobToneOf|certJobStatusLabel/, '状态列不得出现证书业务态')
  assert.match(statusColumn, /tm-status/)
  assert.match(statusColumn, /statusLabel\(row\.status\)/)
})

test('statusLabel 兜底不引入证书生命周期词表', () => {
  const fn = section(vue, 'const statusLabels', '// v2.0 四类型')
  assert.doesNotMatch(fn, /certJobStatusLabel/, 'statusLabel 兜底不得把 cert_jobs 状态词表渲染进状态列')
  assert.match(fn, /statusLabels\[s\] \|\| s/, '兜底只回显原值')
})

test('文件内不存在按行渲染证书状态标签的 helper（certJobLabel/certJobRawStatus）', () => {
  assert.doesNotMatch(vue, /const certJobLabel|const certJobRawStatus/, '任务列表不得有证书态标签 helper')
})

test('服务端 TaskStatus 枚举收敛三态（无 queued/disabled 扩展值）', () => {
  const enumBlock = section(svc, 'const (', ')')
  assert.doesNotMatch(enumBlock, /TaskStatusQueued|TaskStatusDisabled/, 'TaskStatus 枚举不得再含 queued/disabled')
  assert.match(svc, /case "issued", "downloaded", "disabled":/)
  assert.match(svc, /ti\.Status = TaskStatusRunning/)
})
