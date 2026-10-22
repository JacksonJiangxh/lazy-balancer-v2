// 配置时区格式化的零依赖单源（utils/timeZoneFormat）行为验收：
// h23 口径、日期/时间两形态、DB 墙钟串 +Z 规范化。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { DEFAULT_TZ, createTzFormatter, formatDateParts, parseDbDateMs } from '../src/utils/timeZoneFormat.ts'

const formatInTz = (d: Date, timeZone: string, withTime = true): string =>
  formatDateParts(d, createTzFormatter(timeZone, withTime), withTime)

test('配置时区格式化显式固定 h23，午夜不得显示 24 点', () => {
  // 2026-01-01T16:00:00Z = 北京 2026-01-02 00:00:00——h24 形态会输出 24:00:00
  const midnight = formatInTz(new Date('2026-01-01T16:00:00Z'), 'Asia/Shanghai')
  assert.equal(midnight, '2026-01-02 00:00:00')
  assert.doesNotMatch(midnight, /24:00:00/)
})

test('仅日期形态不携带时间部分', () => {
  const day = formatInTz(new Date('2026-01-01T16:00:00Z'), 'Asia/Shanghai', false)
  assert.equal(day, '2026-01-02')
})

test('日期段与时间段时间基准一致（00:00:00 与当日日期同属一天）', () => {
  const formatter = createTzFormatter('Asia/Shanghai', true)
  const parts = formatter.formatToParts(new Date('2026-01-01T15:59:59Z'))
  const get = (type: string): string => parts.find((p) => p.type === type)?.value ?? ''
  assert.equal(`${get('year')}-${get('month')}-${get('day')}`, '2026-01-01')
  assert.equal(`${get('hour')}:${get('minute')}:${get('second')}`, '23:59:59')
})

test('默认时区常量与后端 db.go 的 DefaultTimezone 同源（跨栈钉）', () => {
  assert.equal(DEFAULT_TZ, 'Asia/Shanghai')
})

test('DB 墙钟串（空格分隔）按 UTC 解析——裸 new Date 在 Safari 返回 NaN 的守卫', () => {
  assert.equal(parseDbDateMs('2026-08-11 08:23:21'), Date.UTC(2026, 7, 11, 8, 23, 21))
  // 秒可省略
  assert.equal(parseDbDateMs('2026-08-11 08:23'), Date.UTC(2026, 7, 11, 8, 23))
  // 已带时区的 RFC3339 原样解析
  assert.equal(parseDbDateMs('2026-08-11T08:23:21Z'), Date.UTC(2026, 7, 11, 8, 23, 21))
  assert.equal(parseDbDateMs('2026-08-11T16:23:21+08:00'), Date.UTC(2026, 7, 11, 8, 23, 21))
})

test('非法时间串返回 null（不抛、不返回 NaN）', () => {
  for (const value of ['', 'not-a-date', '2026-13-45 99:99:99']) {
    assert.equal(parseDbDateMs(value), null, `${JSON.stringify(value)} 应解析失败`)
  }
  // 仅日期串（"2026-08-11"）由 JS Date 按 UTC 午夜解析——本模块不做 ISO 白名单
  // （白名单在 date.ts 的 parseDateValue，用于区分「DB 墙钟串」与「人读文本」）
  assert.equal(parseDbDateMs('2026-08-11'), Date.UTC(2026, 7, 11))
})
