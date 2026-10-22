// 配置时区格式化行为验收（原源码正则断言改为运行时行为断言）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createTzFormatter, formatDateParts } from '../src/utils/timeZoneFormat.ts'

// 原 src/utils/timeZoneFormat.ts 的 formatDateInTz 仅被本测试消费（生产零消费已退役），
// 行为等价物内联于此继续钉 h23 口径。
const formatDateInTz = (d: Date, timeZone: string, withTime = true): string =>
  formatDateParts(d, createTzFormatter(timeZone, withTime), withTime)

test('配置时区格式化显式固定 h23，午夜不得显示 24 点', () => {
  // 2026-01-01T16:00:00Z = 北京 2026-01-02 00:00:00——h24 形态会输出 24:00:00
  const midnight = formatDateInTz(new Date('2026-01-01T16:00:00Z'), 'Asia/Shanghai')
  assert.equal(midnight, '2026-01-02 00:00:00')
  assert.doesNotMatch(midnight, /24:00:00/)
})

test('仅日期形态不携带时间部分', () => {
  const day = formatDateInTz(new Date('2026-01-01T16:00:00Z'), 'Asia/Shanghai', false)
  assert.equal(day, '2026-01-02')
})

test('日期段与时间段时间基准一致（00:00:00 与当日日期同属一天）', () => {
  const formatter = createTzFormatter('Asia/Shanghai', true)
  const parts = formatter.formatToParts(new Date('2026-01-01T15:59:59Z'))
  const get = (type: string): string => parts.find((p) => p.type === type)?.value ?? ''
  assert.equal(`${get('year')}-${get('month')}-${get('day')}`, '2026-01-01')
  assert.equal(`${get('hour')}:${get('minute')}:${get('second')}`, '23:59:59')
})
