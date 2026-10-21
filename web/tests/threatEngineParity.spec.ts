// 威胁大屏双引擎（2D 地图 / 3D 地球）行为对齐契约。
//
// 两个引擎实现同一 ThreatScene 接口，历史多次出现「一侧修了另一侧没同步」
// （下钻手势、暂停补绘、拾取预筛），差异只在运行时可见。可求值的语义用纯函数
// 断言；引擎接线（DOM/WebGL 依赖，node:test 无法装载）沿用 threatGlobe.spec
// 的源码契约断言先例。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

import { drillClickIntent } from '../src/utils/threatShared.ts'
import { LAT_TOP, LAT_BOTTOM, DOT_LAT_TOP, DOT_LAT_BOTTOM } from '../src/utils/threatProjection.ts'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')
const sceneSrc = readFileSync(join(ROOT, 'src/utils/threatScene.ts'), 'utf8')
const globeSrc = readFileSync(join(ROOT, 'src/utils/threatGlobe.ts'), 'utf8')

/** 截取成员体：按花括号配对（嵌套块不影响边界——固定缩进启发式会在第一个
 *  内层块收尾处截断，产生假绿）。 */
function member(src: string, marker: string): string {
  const start = src.indexOf(marker)
  assert.notEqual(start, -1, `缺少成员 ${marker}`)
  // 函数体起始 = 行尾的 `{`（返回类型里的 `{ name: ... }` 也在 marker 之后，
  // 不能取第一个 `{`）
  const open = src.indexOf('{\n', start)
  assert.notEqual(open, -1, `成员 ${marker} 无函数体`)
  let depth = 0
  for (let i = open; i < src.length; i++) {
    if (src[i] === '{') depth++
    else if (src[i] === '}' && --depth === 0) return src.slice(start, i + 1)
  }
  assert.fail(`成员 ${marker} 花括号不配对`)
}

test('下钻点击手势：命中国=当前下钻国保持、他国切换、空白返回世界、总览态下钻', () => {
  // 下钻态
  assert.equal(drillClickIntent('中国', '中国'), 'stay', '点击当前下钻国自身必须保持（不得重钻回弹）')
  assert.equal(drillClickIntent('美国', '中国'), 'switch', '命中他国必须切换下钻')
  assert.equal(drillClickIntent(null, '中国'), 'world', '下钻态空白必须返回世界')
  // 总览态
  assert.equal(drillClickIntent('中国', null), 'drill')
  assert.equal(drillClickIntent(null, null), 'none')
  // 台湾归一后与选择国同名：归一由调用方完成（normalizeCountryName），此处同串即保持
  assert.equal(drillClickIntent('中国', '中国'), 'stay')
})

test('两个引擎的点击处理都必须走共享手势判定（单源，不得各写一套）', () => {
  const sceneClick = member(sceneSrc, 'function onClick(')
  assert.match(sceneClick, /drillClickIntent\(/, '2D 地图点击必须走共享手势判定')
  assert.match(sceneClick, /intent === 'stay'\)\s*return/, '2D 地图必须对「当前下钻国自身」直接返回（不重钻）')

  const globeClick = member(globeSrc, 'async function handleCanvasClick(')
  assert.match(globeClick, /drillClickIntent\(/, '3D 地球点击必须走共享手势判定')
  // 不得再有「排除选择国后另找一个国家」的平行实现
  assert.doesNotMatch(globeClick, /THREAT_COUNTRIES\.find\(/, '地球点击不得再写平行命中逻辑')
})

test('点阵扫描纬度域由投影常量派生（两引擎单源）', () => {
  assert.equal(DOT_LAT_TOP, LAT_TOP + 1)
  assert.equal(DOT_LAT_BOTTOM, LAT_BOTTOM + 0.5)
  assert.match(sceneSrc, /latToY\(DOT_LAT_TOP\)/)
  assert.match(sceneSrc, /latToY\(DOT_LAT_BOTTOM\)/)
  assert.match(globeSrc, /DOT_LAT_BOTTOM; lat < DOT_LAT_TOP/)
  for (const [src, name] of [[sceneSrc, '地图'], [globeSrc, '地球']] as const) {
    assert.doesNotMatch(src, /latToY\(84\)|let lat = -54\.5|let lat = 84/, `${name}引擎不得再写死点阵纬度域`)
  }
})

test('暂停态数据/坐标 setter 必须补绘一帧（地球与地图同口径）', () => {
  // 地图：三个 setter 均已补绘（既有实现，防回退）
  const sceneStart = sceneSrc.indexOf('return {\n    addArcForLocation')
  const sceneApi = sceneSrc.slice(sceneStart)
  for (const name of ['setCountries', 'setProvinces', 'setServer']) {
    const marker = name === 'setServer' ? `${name}(centroid: Centroid | null): void {` : `${name}(entries: CountryHeat[]): void {`
    const body = member(sceneApi, marker)
    assert.match(body, /if \(paused\) renderOnce\(\)/, `地图 ${name} 暂停态必须补绘`)
  }
  // 地球：三个 setter 同样必须补绘（原实现只有下钻/返回视角补绘）
  const globeStart = globeSrc.indexOf('return {\n    addArcForLocation')
  const globeApi = globeSrc.slice(globeStart)
  for (const name of ['setCountries', 'setProvinces', 'setServer']) {
    const marker = name === 'setServer' ? `${name}(centroid: Centroid | null): void {` : `${name}(entries: CountryHeat[]): void {`
    const body = member(globeApi, marker)
    assert.match(body, /if \(paused\) renderOnce\(\)/, `地球 ${name} 暂停态必须补绘`)
  }
})

test('地球 hover/click 命中必须复用点阵 bbox 预筛，且静止态不再反复拾取', () => {
  const hit = member(globeSrc, 'function countryHit(')
  assert.match(hit, /dotBboxes\[i\]/, '命中测试必须先用 bbox 预筛')
  assert.match(hit, /lng < b\.minLon \|\| lng > b\.maxLon/, '预筛必须同时约束经度')
  const hover = member(globeSrc, 'function processHover(')
  assert.match(hover, /countryHit\(/, 'hover 拾取必须走预筛单源')
  assert.doesNotMatch(hover, /THREAT_COUNTRIES\.find\(/, 'hover 不得再全表逐个射线')
  assert.match(hover, /const autoRotate = globe\.controls\(\)\.autoRotate/, '读自转状态')
  assert.match(hover, /autoRotate && hoverPoint && now - lastHoverPick >= 120/, '仅自转时复测静止指针')
})

test('地球点色更新用单次局部缓存（不得跨 30s 轮询累积）', () => {
  const update = member(globeSrc, 'function updateDotColors(')
  assert.doesNotMatch(globeSrc, /const heatColorCache = new Map/, '全局按计数缓存必须退役（慢泄漏）')
  assert.match(update, /const colorCache = new Map<number, THREE\.Color>\(\)/, '每次更新使用局部缓存')
  assert.match(update, /const colorFor = \(count: number\)/, '颜色复用局部 colorFor')
})

test('地图静态层复用国家 Path2D 后按色批量填充', () => {
  const rebuild = member(sceneSrc, 'function rebuildStaticLayer(')
  assert.match(rebuild, /const byKey = ensureWorldDotPaths\(\)/, '必须复用国家点阵路径缓存')
  assert.match(rebuild, /const byFill = new Map<string, Path2D>\(\)/)
  assert.match(rebuild, /staticCtx\.fill\(path\)/, '必须逐色一次 fill')
  assert.doesNotMatch(rebuild, /dotPath\(/, '逐点 beginPath+fill 必须退役')
  const cache = member(sceneSrc, 'function ensureWorldDotPaths(')
  assert.match(cache, /dotSubPath\(path/, '路径缓存只在首次构建时逐点生成')
  // 弧线渐变同样必须缓存（相机静止时无逐帧 createLinearGradient）
  const arcs = member(sceneSrc, 'function drawArcs(')
  assert.doesNotMatch(arcs, /createLinearGradient\(/, 'drawArcs 不得逐帧逐弧重建渐变')
  assert.match(arcs, /arcGradient\(from, to, color\)/)
})

test('地球光流叠加层复用地图的像素线宽/尾迹/粒子口径', () => {
  const overlay = member(globeSrc, 'function drawFlowOverlay(')
  assert.match(overlay, /flowArcTierWidth\(arc\.tier\)/, '3D 光流线宽必须沿用显式三档')
  assert.match(overlay, /ctx\.globalAlpha = alpha \* \(0\.05 \+ 0\.95 \* ratio\)/, '尾迹必须尾隐头亮（沿弧长分段，避免直线渐变裁剪）')
  assert.match(overlay, /FLOW_PARTICLES/, '必须绘制同地图亮头粒子')
  assert.doesNotMatch(globeSrc, /arcStroke\('strokeW'/, '3D tube 弧线必须退役，避免双套样式')
})

test('地球聚合标签与到站脉冲跟地图同色', () => {
  assert.match(globeSrc, /labelColor\(\(d: object\) => \(\(d as \{ color\?: string \}\)\.color\)/, '标签必须随弧线颜色（不得固定黄）')
  assert.match(globeSrc, /syncArcLabels[\s\S]*color: a\.color/, 'labelsData 必须携带颜色')
  assert.match(globeSrc, /arc\.pulsed = true/, '一个航次只允许触发一次到站脉冲')
  assert.match(globeSrc, /spawnFlowRipple\(arc\.color\)/, '脉冲颜色必须使用弧线颜色')
  assert.match(globeSrc, /ripple\.age \/ 1\.8/, '涟漪寿命必须与地图一致（1.8s）')
})

test('帧率脚手架已删（两档恒等常量与交互时间窗不再伪装成自适应）', () => {
  assert.doesNotMatch(globeSrc, /IDLE_FRAME_INTERVAL|ACTIVE_FRAME_INTERVAL|ACTIVE_WINDOW|lastInteraction/,
    '恒等的两档帧率与交互时间窗是死脚手架')
  assert.match(globeSrc, /const FRAME_INTERVAL = 1000 \/ 60/)
})

test('拦截页回落文案不得断言「默认 403/429」（真实回落取绑定链首个有效页）', () => {
  const stages = readFileSync(join(ROOT, 'src/utils/securityStages.ts'), 'utf8')
  assert.doesNotMatch(stages, /回落默认 403|跟随默认 403|已失效（回落首策略）/,
    '多策略绑定下「默认 403」是错误断言')
  assert.match(stages, /未配置（跟随绑定链首个有效页，无则默认 403）/)
  assert.match(stages, /已失效（回落绑定链首个有效页）/)
})
