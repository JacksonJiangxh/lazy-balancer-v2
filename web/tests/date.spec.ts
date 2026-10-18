import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('历史问题-18：配置时区格式化显式固定 h23，午夜不得显示 24 点', () => {
  const source = readFileSync(new URL('../src/utils/date.ts', import.meta.url), 'utf8')
  assert.match(source, /hourCycle:\s*'h23'/)

  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  })
  const midnight = formatter.format(new Date('2026-01-01T16:00:00Z'))
  assert.match(midnight, /00:00:00/)
  assert.doesNotMatch(midnight, /24:00:00/)
})
