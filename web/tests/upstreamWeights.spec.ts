import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeWeights, redistributeWeight } from '../src/utils/upstreamWeights.ts'

test('历史问题-01：重新启用上游至少分配 1，UI 不再显示 0%', () => {
  const rows = [
    { weight: 100, enabled: true },
    { weight: 0, enabled: true },
  ]
  redistributeWeight(rows, 1)
  assert.deepEqual(rows, [
    { weight: 99, enabled: true },
    { weight: 1, enabled: true },
  ])
})

test('历史问题-01：禁用行仍为 0，其余启用行合计 100', () => {
  const rows = [
    { weight: 60, enabled: true },
    { weight: 40, enabled: true },
  ]
  rows[1]!.enabled = false
  redistributeWeight(rows, 1)
  assert.deepEqual(rows, [
    { weight: 100, enabled: true },
    { weight: 0, enabled: false },
  ])
})

test('历史问题-01：全零与单行边界仍归一到 100', () => {
  const rows = [{ weight: 0, enabled: true }, { weight: 0, enabled: true }]
  normalizeWeights(rows)
  assert.equal(rows.reduce((sum, row) => sum + row.weight, 0), 100)
  assert.ok(rows.every((row) => row.weight >= 1))

  const single = [{ weight: 0, enabled: true }]
  redistributeWeight(single, 0)
  assert.equal(single[0]!.weight, 100)
})
