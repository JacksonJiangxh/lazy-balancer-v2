// 球面光流曲线采样单源：大圆 slerp + 高程隆起，返回 xyz 平铺数组。
// 只负责几何，不依赖 three/DOM，供地球渲染层每帧零分配投影。
// 坐标约定与 globe.gl 一致：y 轴朝北极，经度绕 y 轴。

const SPHERICAL_ARC_ALTITUDE_SCALE = 0.4
/** 短弧最小抬升：同省/邻省弧在球面上投影过短，容易被站点/扫描带遮住。 */
const SPHERICAL_ARC_MIN_ALTITUDE = 0.12
export const SPHERICAL_ARC_SAMPLES = 48

function toUnit(lat: number, lng: number): [number, number, number] {
  const phi = (lat * Math.PI) / 180
  const lambda = (lng * Math.PI) / 180
  const cosPhi = Math.cos(phi)
  // 与 globe.gl polar2Cartesian 同口径：x=cos(lat)sin(lng)，
  // z=cos(lat)cos(lng)。旧实现 cos/sin 轴互换，弧线整体旋转 90°。
  return [cosPhi * Math.sin(lambda), Math.sin(phi), cosPhi * Math.cos(lambda)]
}

function dot3(a: readonly number[], b: readonly number[]): number {
  return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]
}

/**
 * 生成 start→end 的球面大圆采样点（含端点），按大圆夹角做高程隆起：
 * radius = R * (1 + (angle/2 * 0.4) * sin(πt))。
 * 返回长度 samples*3 的 Float32Array；samples<2 时按 2 处理。
 */
export function buildSphericalArc(
  startLat: number,
  startLng: number,
  endLat: number,
  endLng: number,
  radius: number,
  samples = SPHERICAL_ARC_SAMPLES,
): Float32Array {
  const count = Math.max(2, Math.floor(samples))
  const a = toUnit(startLat, startLng)
  const b = toUnit(endLat, endLng)
  const cosAngle = Math.max(-1, Math.min(1, dot3(a, b)))
  const angle = Math.acos(cosAngle)
  const sinAngle = Math.sin(angle)
  const altitude = Math.max(SPHERICAL_ARC_MIN_ALTITUDE, (angle / 2) * SPHERICAL_ARC_ALTITUDE_SCALE)
  // 退化判定必须分两支：重合（angle≈0）与对跖（angle≈π，sin≈0）都让 slerp 的
  // 1/sin(angle) 失去意义，但后果相反——重合时 b≈a，整条弧塌成一点是对的；
  // 对跖时 b=-a，若同样取 a 则终点永远落回起点，弧不可见。对跖的大圆方位
  // 不唯一，改取与 a 正交的稳定轴构造，保证首末点分别是 a、b。
  const coincident = angle < 1e-9
  const antipodal = !coincident && Math.abs(sinAngle) < 1e-9
  // 正交轴：与 a 的叉乘范数 = sin(a 与该轴夹角)，取 |分量| 最小的坐标轴
  // （夹角最接近 90°）可让叉乘结果范数最大（≥√(2/3)），数值最稳。
  let axisX = 0
  let axisY = 0
  let axisZ = 0
  if (antipodal) {
    const absX = Math.abs(a[0])
    const absY = Math.abs(a[1])
    const absZ = Math.abs(a[2])
    const [refX, refY, refZ] = absX <= absY && absX <= absZ ? [1, 0, 0] : absY <= absZ ? [0, 1, 0] : [0, 0, 1]
    axisX = a[1] * refZ - a[2] * refY
    axisY = a[2] * refX - a[0] * refZ
    axisZ = a[0] * refY - a[1] * refX
    const axisLength = Math.hypot(axisX, axisY, axisZ)
    axisX /= axisLength
    axisY /= axisLength
    axisZ /= axisLength
  }
  const out = new Float32Array(count * 3)
  for (let i = 0; i < count; i++) {
    const t = i / (count - 1)
    let x: number
    let y: number
    let z: number
    if (coincident) {
      x = a[0]
      y = a[1]
      z = a[2]
    } else if (antipodal) {
      // 沿 a→正交轴→-a 的大圆走 π：t=0 得 a，t=1 得 -a=b。
      const theta = Math.PI * t
      const c = Math.cos(theta)
      const s = Math.sin(theta)
      x = a[0] * c + axisX * s
      y = a[1] * c + axisY * s
      z = a[2] * c + axisZ * s
    } else {
      const wa = Math.sin((1 - t) * angle) / sinAngle
      const wb = Math.sin(t * angle) / sinAngle
      x = a[0] * wa + b[0] * wb
      y = a[1] * wa + b[1] * wb
      z = a[2] * wa + b[2] * wb
    }
    const len = Math.hypot(x, y, z) || 1
    const r = radius * (1 + altitude * Math.sin(Math.PI * t))
    out[i * 3] = (x / len) * r
    out[i * 3 + 1] = (y / len) * r
    out[i * 3 + 2] = (z / len) * r
  }
  return out
}
