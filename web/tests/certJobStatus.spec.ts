import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  certJobRetryReady,
  certJobStatusLabel,
  certJobStatusTone,
  type CertJobStatus,
} from '../src/utils/certJobStatus.ts'
import { repoSource, section, source } from './_helpers.ts'

const now = Date.parse('2026-10-19T00:00:00Z')
const updatedAt = '2026-10-19T00:00:00Z'

test('重试冷却时长由后端字段驱动，不再由状态常量驱动', () => {
  assert.equal(certJobRetryReady(null, updatedAt, now), false, 'disabled=null 永不可重试')
  assert.equal(certJobRetryReady(0, updatedAt, now), true, '零冷却立即可重试')
  assert.equal(certJobRetryReady(900, updatedAt, now + 14*60*1000 + 59*1000), false)
  assert.equal(certJobRetryReady(900, updatedAt, now + 15*60*1000), true)
  assert.equal(certJobRetryReady(300, updatedAt, now + 4*60*1000), false)
  assert.equal(certJobRetryReady(300, updatedAt, now + 5*60*1000), true)
})

test('缺失或畸形时间戳维持既有 fail-open 边界', () => {
  assert.equal(certJobRetryReady(120, undefined, now), true)
  assert.equal(certJobRetryReady(120, 'not-a-date', now), true)
})

// 证书任务状态 label/tone 全表覆盖后端 db.certJobStatuses（26 态，DB CHECK 单源）。
// 前端枚举漂移会静默落入 unknown 分支（标签显示原始 token、tone 退 info），且无任何
// 运行期用例会失败。穷尽性由生产侧两张表上的 `satisfies Record<CertJobStatus, …>`
// 在编译期锁定（新增状态不补文案即 tsc 报错）；本条在运行期逐态验证「有专属中文
// 标签、tone 合法」，并钉住这两条编译期约束不被悄悄删掉。
test('证书任务状态 label/tone 覆盖后端 db.certJobStatuses 全 26 态', () => {
  const go = repoSource('internal/db/db.go')
  const goBlock = section(go, 'var certJobStatuses = []string{', '\n}\n')
  const backend = [...goBlock.matchAll(/"([a-z_]+)"/g)].map((m) => m[1])
  // 状态联合唯一事实源已迁 types/index.ts（证书任务视图类型族同源处），
  // utils/certJobStatus 只 re-export——枚举漂移检查钉在唯一声明处。
  const sharedTypes = source('src/types/index.ts')
  const tsBlock = section(sharedTypes, 'export type CertJobStatus =', '\n\n')
  const frontend = [...tsBlock.matchAll(/'([a-z_]+)'/g)].map((m) => m[1])
  const ts = source('src/utils/certJobStatus.ts')
  assert.match(ts, /export type \{ CertJobStatus \}/, 'utils/certJobStatus 须保持 CertJobStatus 导入面（re-export）')
  assert.equal(backend.length, 26, '后端枚举应为 26 态（DB CHECK 单源）')
  assert.deepEqual([...frontend].sort(), [...backend].sort(), '证书状态前后端枚举漂移')

  // 编译期穷尽性约束必须存在：删掉 satisfies 后新增状态不再被 typecheck 拦截
  assert.match(ts, /satisfies Record<CertJobStatus, string>/, '标签表必须带 Record<CertJobStatus, string> 约束')
  assert.match(ts, /satisfies Record<CertJobStatus, CertJobStatusTone>/, '色调表必须带 Record<CertJobStatus, CertJobStatusTone> 约束')

  // 运行期逐态：每个状态都有专属中文标签（不落 unknown 分支）
  const tones = ['success', 'danger', 'warning', 'info']
  for (const status of backend) {
    const label = certJobStatusLabel(status as CertJobStatus)
    assert.notEqual(label, '未知', `${status} 未补专属文案（空值兜底分支）`)
    assert.notEqual(label, status, `${status} 落入 unknown 分支（显示原始 token）`)
    assert.ok(label.length > 0)
    assert.ok(tones.includes(certJobStatusTone(status as CertJobStatus)), `${status} tone 非法`)
  }
})

test('重签禁用文案：不可重试且无冷却秒数时不得提示「等待 0 分钟」', () => {
  const page = source('src/views/settings/CertJobs.vue')
  const fn = section(page, 'const retryDisabledReason', '\n}')
  assert.match(fn, /if \(row\.retry_cooldown_seconds === null \|\| row\.retry_cooldown_seconds === undefined\) return '当前状态暂不可重签'/)
  assert.match(fn, /Math\.ceil\(row\.retry_cooldown_seconds \/ 60\)/, '有冷却值时不得再用 ?? 0 兜底物化 0 分钟')
  assert.doesNotMatch(fn, /retry_cooldown_seconds \?\? 0/)
})
