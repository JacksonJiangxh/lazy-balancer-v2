// 配置值展示口径（审计 81 历史问题-07）：合法小值必须原样展示，仅 0=自动落默认。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { displaySecurityEventsRowCap } from '../src/utils/configValues.ts'

test('行数上限：1..999 等合法小值原样展示，不被夹到 1000/1,000,000', () => {
  for (const value of [1, 2, 500, 999, 1000, 5000, 100000000]) {
    assert.equal(displaySecurityEventsRowCap(value), value)
  }
})

test('行数上限：0/负数/缺省按自动口径展示内置默认 1,000,000', () => {
  assert.equal(displaySecurityEventsRowCap(0), 1_000_000)
  assert.equal(displaySecurityEventsRowCap(-1), 1_000_000)
  assert.equal(displaySecurityEventsRowCap(undefined), 1_000_000)
  assert.equal(displaySecurityEventsRowCap(null), 1_000_000)
})
