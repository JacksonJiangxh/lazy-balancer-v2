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

test('坐标轴与 globe.gl 一致：lng=0 在 +z，lng=90 在 +x', () => {
  const points = buildSphericalArc(0, 0, 0, 90, 100, 2)
  assert.ok(Math.abs(points[0]) < 1e-4, '起点 x≈0')
  assert.ok(Math.abs(points[1]) < 1e-4, '起点 y≈0')
  assert.ok(Math.abs(points[2] - 100) < 1e-3, 'lng=0 起点 z≈R')
  assert.ok(Math.abs(points[3] - 100) < 1e-3, 'lng=90 终点 x≈R')
  assert.ok(Math.abs(points[5]) < 1e-4, 'lng=90 终点 z≈0')
})

test('重合起终点不产生 NaN（短弧仍抬升，端点仍在球面）', () => {
  const points = buildSphericalArc(35.2, 108.9, 35.2, 108.9, 100, 8)
  for (const value of points) assert.ok(Number.isFinite(value))
  assert.ok(Math.abs(norm(points, 0) - 100) < 1e-3)
  assert.ok(Math.abs(norm(points, 7) - 100) < 1e-3)
  assert.ok(norm(points, 4) > 100)
})

// 对跖端点：slerp 分母 sin(angle)→0 退化，旧实现把整条弧折叠成起点。
// 修复后构造一条稳定大圆，首末点必须分别是 a、b（方位不唯一，只断言端点/抬升/有限性）。
function unit(lat: number, lng: number): [number, number, number] {
  const phi = (lat * Math.PI) / 180
  const lambda = (lng * Math.PI) / 180
  return [Math.cos(phi) * Math.sin(lambda), Math.sin(phi), Math.cos(phi) * Math.cos(lambda)]
}

function assertEndpointsAreAntipodes(points: Float32Array, count: number, lat: number, lng: number): void {
  const last = count - 1
  const expected = unit(-lat, lng > 0 ? lng - 180 : lng + 180)
  for (let axis = 0; axis < 3; axis++) {
    assert.ok(
      Math.abs(points[last * 3 + axis] / 100 - expected[axis]) < 1e-5,
      `终点必须落在对跖点 b（轴 ${axis}）`,
    )
  }
  for (const value of points) assert.ok(Number.isFinite(value), '对跖弧不得出现 NaN')
}

test('对跖端点：终点落到 b（不折叠回起点），中点抬升', () => {
  const points = buildSphericalArc(0, 0, 0, 180, 100, 8)
  assert.equal(points.length, 8 * 3)
  assert.ok(Math.abs(points[0]) < 1e-4 && Math.abs(points[1]) < 1e-4 && Math.abs(points[2] - 100) < 1e-3, '起点必须是 a')
  assert.ok(Math.abs(points[21]) < 1e-4, '终点 x≈0')
  assert.ok(Math.abs(points[22]) < 1e-4, '终点 y≈0')
  assert.ok(Math.abs(points[23] + 100) < 1e-3, '终点 z≈-R（对跖点，不得折叠回起点 +R）')
  assert.ok(norm(points, 4) > 100, '对跖大圆中点必须抬升')
  for (const value of points) assert.ok(Number.isFinite(value))
})

test('对跖端点：任意纬度/经度的对跖对都落在 b（正交轴选择三形态）', () => {
  // 四组起点覆盖正交参考轴的三条分支，以及「ax≤ay 成立但 ax≤az 不成立」的
  // 短路形态（z 分量最小）——保证正交轴的选取在全部形态下都经过。
  for (const [lat, lng] of [[0, 0], [0, 90], [40, 90], [60, 90]] as const) {
    const points = buildSphericalArc(lat, lng, -lat, lng > 0 ? lng - 180 : lng + 180, 100, 16)
    assertEndpointsAreAntipodes(points, 16, lat, lng)
    assert.ok(norm(points, 8) > 100, `(${lat},${lng}) 对跖弧中点必须抬升`)
  }
})
