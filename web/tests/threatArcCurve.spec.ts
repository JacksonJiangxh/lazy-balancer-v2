import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildSphericalArc } from '../src/utils/threatArcCurve.ts'

function norm(points: Float32Array, i: number): number {
  const x = points[i * 3]
  const y = points[i * 3 + 1]
  const z = points[i * 3 + 2]
  return Math.hypot(x, y, z)
}

test('球面弧端点落在球面、中点高于球面、采样数正确', () => {
  const R = 100
  const points = buildSphericalArc(35.2, 108.9, 51.5, -0.1, R, 48)
  assert.equal(points.length, 48 * 3)
  assert.ok(Math.abs(norm(points, 0) - R) < 1e-3, '起点必须在球面')
  assert.ok(Math.abs(norm(points, 47) - R) < 1e-3, '终点必须在球面')
  assert.ok(norm(points, 24) > R, '大圆中点必须抬升')
  for (const value of points) assert.ok(Number.isFinite(value), '曲线不得出现 NaN')
})

test('重合起终点不产生 NaN（短弧仍抬升，端点仍在球面）', () => {
  const points = buildSphericalArc(35.2, 108.9, 35.2, 108.9, 100, 8)
  for (const value of points) assert.ok(Number.isFinite(value))
  assert.ok(Math.abs(norm(points, 0) - 100) < 1e-3)
  assert.ok(Math.abs(norm(points, 7) - 100) < 1e-3)
  assert.ok(norm(points, 4) > 100)
})
