import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeWeights, redistributeWeight, weightPercent } from '../src/utils/upstreamWeights.ts'

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

test('A85WT-历史问题：weightPercent 展示口径（禁用行=0、总和≤0→0、四舍五入）', () => {
  assert.equal(weightPercent(undefined, { weight: 1 }), 0)
  assert.equal(weightPercent([], { weight: 1 }), 0)
  assert.equal(weightPercent([{ weight: 0, enabled: true }], { weight: 0, enabled: true }), 0)
  assert.equal(
    weightPercent([{ weight: 1, enabled: true }, { weight: 2, enabled: true }], { weight: 1, enabled: true }),
    33,
    '1/3 四舍五入为 33'
  )
  assert.equal(
    weightPercent([{ weight: 50, enabled: true }, { weight: 50, enabled: false }], { weight: 50, enabled: true }),
    100,
    '禁用行不计入总和'
  )
  assert.equal(
    weightPercent([{ weight: 50, enabled: true }], { weight: 50, enabled: false }),
    0,
    '禁用行自身恒 0'
  )
})

test('A85WT-历史问题：超出 100 行上限的行权重清零且不参与分配', () => {
  const rows = Array.from({ length: 101 }, () => ({ weight: 1, enabled: true }))
  normalizeWeights(rows)
  assert.equal(rows[100]!.weight, 0, '第 101 行必须被清零')
  assert.equal(rows.slice(0, 100).reduce((sum, row) => sum + row.weight, 0), 100)
})
