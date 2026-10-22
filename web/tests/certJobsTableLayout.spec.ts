// 证书签发任务表列布局：设置页卡片容器内曾出现水平滚动条（原 12 列合计 1660px）。
// 收敛口径：消息列并入状态标签 tooltip、过期时间与剩余天数合并单列、时间列改配置时区
// 紧凑格式、全部定宽且不再用 min-width 撑宽。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { member, section, source } from './_helpers.ts'
import { createTzFormatter, formatCompactDateParts } from '../src/utils/timeZoneFormat.ts'

const page = source('src/views/settings/CertJobs.vue')

const tableBody = section(page, 'class="cert-jobs-table"', '</el-table>')

const columnTags = (): string[] => [...tableBody.matchAll(/<el-table-column\b[^>]*>/g)].map((m) => m[0])

const startOf = (label: string): number => {
  const at = tableBody.indexOf(`label="${label}"`)
  assert.ok(at >= 0, `缺少列「${label}」`)
  return tableBody.lastIndexOf('<el-table-column', at)
}

/** 列开标签（自闭合列也能取到属性）。 */
const openTagOf = (label: string): string => {
  const start = startOf(label)
  return tableBody.slice(start, tableBody.indexOf('>', start) + 1)
}

/** 列块（含模板体，到 </el-table-column> 为止）。 */
const columnBody = (label: string): string => {
  const start = startOf(label)
  const end = tableBody.indexOf('</el-table-column>', start)
  assert.ok(end > start, `列「${label}」缺少模板体`)
  return tableBody.slice(start, end)
}

test('消息列已删除：message 由状态标签 hover tooltip 承载', () => {
  assert.doesNotMatch(tableBody, /label="消息"/)
  const status = columnBody('状态')
  assert.match(status, /<el-tooltip[^>]*:disabled="!row\.message"/, 'message 为空时不得挂空 tooltip')
  assert.match(status, /:content="row\.message"/)
  assert.match(status, /certJobStatusLabel\(row\.status\)/)
})

test('列定宽收敛：合计 1100px 且不再使用 min-width 撑宽', () => {
  const tags = columnTags()
  assert.equal(tags.length, 10, `列数应为 10，实际 ${tags.length}`)
  assert.doesNotMatch(tableBody, /min-width=/, '必须全部定宽，min-width 会在窄容器内撑出滚动条')
  const expected: Record<string, number> = {
    '规则 ID': 96,
    域名: 170,
    状态: 84,
    颁发者: 96,
    证书有效期: 170,
    自动重签时间: 110,
    更新时间: 110,
    重试次数: 64,
    冷却时间: 104,
    操作: 96,
  }
  for (const [label, width] of Object.entries(expected)) {
    assert.match(openTagOf(label), new RegExp(`\\bwidth="${width}"`), `列「${label}」宽度应为 ${width}px`)
  }
  const total = tags.reduce((sum, tag) => sum + Number(tag.match(/\bwidth="(\d+)"/)?.[1] ?? 0), 0)
  assert.equal(total, 1100, `列宽合计应为 1100px，实际 ${total}px`)
  assert.ok(total <= 1200)
  assert.match(tableBody, /:fit="true"/)
})

test('证书有效期合并单列：日期 + 剩余/已过期天数，精确时间走 tooltip', () => {
  assert.doesNotMatch(tableBody, /label="过期时间"/)
  assert.doesNotMatch(tableBody, /label="剩余天数"/)
  const body = columnBody('证书有效期')
  assert.match(body, /\bwidth="170"/)
  assert.match(body, /formatDateShort\(row\.expires_at\)/)
  assert.ok(body.includes('剩 ${row.days_remaining} 天'), '缺少「剩 N 天」分支')
  assert.ok(body.includes('已过期 ${Math.abs(row.days_remaining)} 天'), '缺少「已过期 N 天」分支')
  assert.match(body, /certificateStatus\(row\) === 'expired'/, '过期判据必须复用 certificateStatus')
  assert.match(body, /<el-tooltip[^>]*:content="formatDate\(row\.expires_at\)"/, '精确过期时间必须进 tooltip')
  assert.match(body, /class="cell-empty"/, '非 issued/缺失必须沿用 cell-empty 占位')
})

test('时间列走配置时区紧凑格式（formatDateCompact），tooltip 承载完整时间', () => {
  assert.match(page, /import \{[^}]*formatDateCompact[^}]*\} from '@\/utils\/date'/)
  for (const [label, body] of [
    ['自动重签时间', columnBody('自动重签时间')],
    ['更新时间', columnBody('更新时间')],
  ] as const) {
    assert.match(body, /\bwidth="110"/, `列「${label}」宽度应为 110px`)
    assert.match(body, /formatDateCompact\(/, `列「${label}」必须消费时区感知紧凑格式`)
    assert.doesNotMatch(body, /toLocaleString|toLocaleDateString|toLocaleTimeString/, `列「${label}」不得绕过配置时区`)
    assert.match(body, /<el-tooltip[^>]*:content="[^"]*formatDate\(/, `列「${label}」tooltip 必须承载完整时间`)
  }
  assert.match(columnBody('更新时间'), /:content="formatDate\(row\.updated_at\)"/)
  assert.doesNotMatch(page, /new Date\(\)\.toLocale/)

  const dateUtils = source('src/utils/date.ts')
  const compact = member(dateUtils, 'export const formatDateCompact')
  assert.match(compact, /tzFormatter\(true\)/, 'formatDateCompact 必须经配置时区格式化器')
  assert.doesNotMatch(compact, /toLocale/)
})

test('紧凑格式 MM-DD HH:mm 时区感知（午夜保持 h23）', () => {
  const formatter = createTzFormatter('Asia/Shanghai', true)
  assert.equal(formatCompactDateParts(new Date('2026-01-01T16:00:00Z'), formatter), '01-02 00:00')
  assert.equal(formatCompactDateParts(new Date('2026-10-22T01:05:00Z'), formatter), '10-22 09:05')
})
