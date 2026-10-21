// 威胁大屏热路径缓存契约：
//   ① 拾取矩形缓存：pointermove 不再逐帧 getBoundingClientRect（2D canvas 原点 /
//      3D 地球 canvas 矩形），只在 resize/syncSize/点击时刷新。
//   ② hover 高亮路径按世界坐标缓存一次：绘制只 setTransform + 最近副本裁剪，
//      屏幕落点与旧逐点 wrapDeg 公式等价（相机居中副本）。
//   ③ 地球点阵：贴图单例共享（引用计数释放）+ 点集切换原地更新预分配属性
//      （不新建 BufferGeometry，只上传写入区间 + drawRange 收敛）。

import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as THREE from 'three'

import { registerModuleHooks, member, source } from './_helpers.ts'
import {
  WORLD_W,
  WORLD_D,
  latToY,
  wrapDeg,
  wrapLon,
  type Cam2D,
} from '../src/utils/threatProjection.ts'

// threatScene/threatGlobe 内部使用 `@/utils/*` 别名；globe.gl 在 node 无 window
// 会在 import 期抛错——用空模块替身（本用例只消费纯几何/缓冲区实现）。
// 钩子必须先装（静态 import 先于本模块执行），故被测模块只能动态 import
// ——与 tests/admin1Loader.spec.ts 的加载边界同例。
const globeStub = `data:text/javascript,${encodeURIComponent('export default function () {}')}`
registerModuleHooks({ 'globe.gl': () => globeStub })

// 贴图单例需要最小 canvas 宿主（createDotTexture 只建 32×32 画布）。
interface FakeCanvas {
  width: number
  height: number
  getContext: (kind: string) => null
}
let canvasCreations = 0
const fakeDocument = {
  createElement: (tag: string): FakeCanvas => {
    assert.equal(tag, 'canvas', '贴图单例只允许建 canvas')
    canvasCreations += 1
    return { width: 0, height: 0, getContext: () => null }
  },
}
;(globalThis as unknown as { document: unknown }).document = fakeDocument

const { hoverLayerTransform } = await import('../src/utils/threatScene.ts')
const { makeDotGeometry, writeDotPositions, dotTextureState, acquireDotTexture, releaseDotTexture } =
  await import('../src/utils/threatGlobe.ts')

const sceneSrc = source('src/utils/threatScene.ts')
const globeSrc = source('src/utils/threatGlobe.ts')

// ---- ① 拾取矩形缓存 ----

test('地图拾取原点：getBoundingClientRect 只在刷新函数里，pointermove 只读缓存', () => {
  const hits = sceneSrc.match(/\.getBoundingClientRect\(/g) ?? []
  assert.equal(hits.length, 1, `threatScene 只允许一处 getBoundingClientRect，实际 ${hits.length}`)
  const refresh = member(sceneSrc, 'function refreshCanvasOrigin(')
  assert.match(refresh, /\.getBoundingClientRect\(\)/, '唯一的布局读取必须在 refreshCanvasOrigin 里')
  const point = member(sceneSrc, 'function canvasPoint(')
  assert.doesNotMatch(point, /getBoundingClientRect/, 'canvasPoint 必须只读缓存原点（pointermove 逐帧调用）')
  const size = member(sceneSrc, 'const applySize = (): void => {')
  assert.match(size, /refreshCanvasOrigin\(\)/, 'applySize（ResizeObserver/window resize）必须刷新缓存')
  const down = member(sceneSrc, 'function onPointerDown(')
  assert.match(down, /refreshCanvasOrigin\(\)/, '按下手势必须刷新一次，兜住无尺寸变化的布局位移')
})

test('地球拾取矩形：拾取/浮签定位走缓存，syncSize 刷新', () => {
  const hits = globeSrc.match(/\.getBoundingClientRect\(/g) ?? []
  // 仅剩 initW/initH 的构造测量 + canvasRect 内部一处
  assert.equal(hits.length, 3, `threatGlobe 只允许构造期两处 + 缓存读取一处，实际 ${hits.length}`)
  const size = member(globeSrc, 'const syncSize = (): void => {')
  assert.match(size, /canvasRectCache = null/, 'syncSize（RO/resize/轮询）必须失效矩形缓存')
  const pick = member(globeSrc, 'function screenToLatLng(')
  assert.match(pick, /const r = canvasRect\(\)/, '拾取必须读缓存矩形')
  assert.doesNotMatch(pick, /getBoundingClientRect/, 'screenToLatLng 不得读取布局')
  const hover = member(globeSrc, 'function processHover(')
  assert.match(hover, /const r = canvasRect\(\)/, '浮签定位必须读缓存矩形')
  assert.doesNotMatch(hover, /getBoundingClientRect/, 'processHover 不得读取布局')
})

// ---- ② hover 高亮：世界坐标路径 + setTransform 等价落点 ----

test('hover 高亮不再重建 Path2D：复用按国世界路径 + setTransform', () => {
  assert.doesNotMatch(sceneSrc, /hoverCacheKey\s*\(/, '相机键缓存必须退役（camX/camY 每帧变化=每帧重建）')
  assert.doesNotMatch(sceneSrc, /worldHoverCache|drillHoverCache/, '旧屏幕空间 hover 缓存必须删除')
  const world = member(sceneSrc, 'function drawHoverHighlight(')
  assert.match(world, /ensureWorldDotPaths\(\)\.get\(hoverName\)/, '世界 hover 必须复用静态层按国世界路径缓存')
  assert.doesNotMatch(world, /new Path2D\(/, '世界 hover 不得逐帧重建路径')
  assert.match(world, /fillHoverWorldPath\(/, '世界 hover 绘制必须走单源变换')
  const drill = member(sceneSrc, 'function drawDrillHover(')
  assert.match(drill, /ensureDrillHoverPaths\(\)/, '下钻 hover 必须用按省世界路径缓存')
  assert.doesNotMatch(drill, /new Path2D\(/, '下钻 hover 不得逐帧重建路径')
  const fill = member(sceneSrc, 'function fillHoverWorldPath(')
  assert.match(fill, /hoverLayerTransform\(cam\)/, '绘制必须消费单源变换计划')
  assert.match(fill, /ctx\.setTransform\(/, '绘制必须只做 setTransform')
  assert.match(fill, /ctx\.rect\(layer\.clipX, 0, layer\.clipWidth, cam\.height\)/, '必须裁剪到最近副本经度窗')
  assert.doesNotMatch(fill, /dotSubPath|new Path2D/, '绘制不得重放六边形子路径')
})

test('hover 世界路径变换：最近副本落点与旧逐点 wrapDeg 公式等价', () => {
  const cameras: Cam2D[] = [
    { camX: 0, camY: WORLD_D / 2, zoom: 3.58, width: 1600, height: 900 },
    { camX: 170, camY: 100, zoom: 3.58, width: 1600, height: 900 },
    { camX: -179.5, camY: 60, zoom: 8.9, width: 1600, height: 900 },
    { camX: 359.5, camY: 120, zoom: 9, width: 1200, height: 800 },
    { camX: 108.9, camY: 90, zoom: 0.35, width: 900, height: 600 },
  ]
  const lons = [-179.5, -170, -100, -1, 0, 19.5, 108.9, 170, 179.5]
  const lats = [-54.5, 0, 34, 61, 80]
  for (const cam of cameras) {
    const layer = hoverLayerTransform(cam)
    const baseLon = wrapLon(cam.camX)
    for (const lon of lons) {
      for (const lat of lats) {
        // 旧实现（屏幕空间逐点定位）的落点。
        const oldX = cam.width / 2 + wrapDeg(lon - baseLon) * cam.zoom
        const oldY = cam.height / 2 + (latToY(lat) - cam.camY) * cam.zoom
        // 新实现：世界路径经仿射变换 + 三份拷贝，裁剪窗内只应命中一份。
        const pathX = lon + WORLD_W / 2
        const pathY = latToY(lat)
        let hits = 0
        for (const copy of [-layer.worldPx, 0, layer.worldPx]) {
          const x = layer.tx + copy + pathX * layer.scale
          const y = layer.ty + pathY * layer.scale
          // 裁剪窗半开区间（与 wrapDeg 的 +180→-180 选取口径一致），
          // 恰好 ±180° 的点只命中唯一一份拷贝。
          if (x < layer.clipX || x >= layer.clipX + layer.clipWidth) continue
          hits += 1
          assert.ok(Math.abs(x - oldX) < 1e-9, `camX=${cam.camX} zoom=${cam.zoom} lon=${lon}: x=${x} ≠ 旧 ${oldX}`)
          assert.ok(Math.abs(y - oldY) < 1e-9, `camX=${cam.camX} lon=${lon} lat=${lat}: y=${y} ≠ 旧 ${oldY}`)
        }
        assert.equal(hits, 1, `camX=${cam.camX} zoom=${cam.zoom} lon=${lon} 必须恰好命中最近副本一次`)
        // 可见性口径：旧实现按半视口宽（度）过滤，等价于屏幕 x 落在画布内。
        const halfW = cam.width / 2 / cam.zoom
        const onScreen = Math.abs(wrapDeg(lon - baseLon)) <= halfW
        assert.equal(onScreen, oldX >= 0 && oldX <= cam.width, `可见性口径不一致 lon=${lon}`)
      }
    }
  }
})

test('hover 变换与世界层 blit 同源（同一 baseLon 平移公式）', () => {
  const cam: Cam2D = { camX: 250.4, camY: 110, zoom: 6.25, width: 1400, height: 860 }
  const layer = hoverLayerTransform(cam)
  const baseLon = wrapLon(cam.camX)
  assert.ok(Math.abs(layer.tx - (cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom)) < 1e-9)
  assert.ok(Math.abs(layer.ty - (cam.height / 2 - cam.camY * cam.zoom)) < 1e-9)
  assert.ok(Math.abs(layer.worldPx - WORLD_W * cam.zoom) < 1e-9)
  // paintComposite 的静态层拷贝平移为 ±(WORLD_W*zoom)，hover 必须一致
  assert.match(sceneSrc, /for \(const offset of \[-dw, 0, dw\]\)/)
})

// ---- ③ 地球点阵：贴图单例 + 预分配属性原地更新 ----

test('点阵贴图单例：多层共享一次创建，引用归零才销毁', () => {
  canvasCreations = 0
  const first = acquireDotTexture()
  const second = acquireDotTexture()
  const third = acquireDotTexture()
  assert.equal(canvasCreations, 1, '三层点阵只允许建一份贴图 canvas')
  assert.equal(first, second)
  assert.equal(second, third)
  assert.deepEqual(dotTextureState(), { refs: 3, shared: true })
  releaseDotTexture()
  releaseDotTexture()
  assert.deepEqual(dotTextureState(), { refs: 1, shared: true }, '仍有实例持有时不得销毁')
  releaseDotTexture()
  assert.deepEqual(dotTextureState(), { refs: 0, shared: false }, '最后一个引用释放后销毁')
  // 多余释放不得把计数打成负数/误销毁新纹理
  releaseDotTexture()
  assert.deepEqual(dotTextureState(), { refs: 0, shared: false })
})

test('点阵切换原地更新预分配属性：几何身份不变、只上报写入区间', () => {
  const geometry = makeDotGeometry(4)
  const points = new THREE.Points(geometry, new THREE.PointsMaterial())
  const project = (lat: number, lng: number, out: THREE.Vector3): void => {
    out.set(lng, lat, 7)
  }
  const two = [
    { lat: 1, lng: 2 },
    { lat: 3, lng: 4 },
  ]
  assert.equal(writeDotPositions(points, two, project), true)
  assert.equal(points.geometry, geometry, '写入不得替换 BufferGeometry')
  const attr = geometry.getAttribute('position') as THREE.BufferAttribute
  assert.deepEqual(Array.from(attr.array as Float32Array), [2, 1, 7, 4, 3, 7, 0, 0, 0, 0, 0, 0])
  assert.deepEqual(geometry.drawRange, { start: 0, count: 2 }, 'drawRange 必须收敛到实际点集')
  assert.deepEqual(attr.updateRanges, [{ start: 0, count: 6 }], '只上报写入区间（预分配尾部不上传）')
  const versionBefore = attr.version
  assert.ok(versionBefore >= 1, 'needsUpdate 必须递增版本')

  // 切换成更小的点集（悬停另一国家）：前缀覆盖 + drawRange 缩小 + 区间随点集收缩
  assert.equal(writeDotPositions(points, [{ lat: 5, lng: 6 }], project), true)
  assert.equal(points.geometry, geometry)
  assert.deepEqual(Array.from((attr.array as Float32Array).slice(0, 3)), [6, 5, 7])
  assert.deepEqual(geometry.drawRange, { start: 0, count: 1 })
  assert.deepEqual(attr.updateRanges, [{ start: 0, count: 3 }], '旧区间必须清空后重报')
  assert.ok(attr.version > versionBefore)

  // 容量不足：拒绝写入且不改动几何/drawRange（调用方按需扩容）
  const overflow = Array.from({ length: 5 }, (_, i) => ({ lat: i, lng: i }))
  assert.equal(writeDotPositions(points, overflow, project), false)
  assert.equal(points.geometry, geometry)
  assert.deepEqual(geometry.drawRange, { start: 0, count: 1 })
  assert.deepEqual(Array.from((attr.array as Float32Array).slice(0, 3)), [6, 5, 7])
})

test('地球接线：三层共用一个贴图实例，dispose 只按引用释放一次', () => {
  assert.equal((globeSrc.match(/new THREE\.CanvasTexture\(/g) ?? []).length, 1, '贴图构建必须唯一')
  assert.equal((globeSrc.match(/map: dotTex,/g) ?? []).length, 3, '三层材质必须共用 dotTex')
  assert.match(globeSrc, /const dotTex = acquireDotTexture\(\)/)
  const dispose = member(globeSrc, 'dispose(): void {')
  assert.match(dispose, /releaseDotTexture\(\)/, 'dispose 必须释放共享引用')
  assert.doesNotMatch(dispose, /\.map\?\.dispose\(\)/, '共享贴图不得随每个材质销毁')
  const setPoints = member(globeSrc, 'function setPointPositions(')
  assert.match(setPoints, /writeDotPositions\(points, dots, project\)/)
  assert.doesNotMatch(setPoints, /new THREE\.BufferGeometry/, '点集切换不得新建 BufferGeometry')
  assert.match(globeSrc, /makeDotGeometry\(dots\.length\)/, '暗度/hover 层必须预分配容量')
  // 世界点阵是点集上界：hover 只取国家子集、衬底过滤掉下钻国
  assert.match(globeSrc, /worldDots\.filter\(\(d\) => d\.key !== drilledName\)/)
})
