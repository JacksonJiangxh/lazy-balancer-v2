// 威胁大屏地球引擎契约守卫。
//
// threatGlobe 依赖 globe.gl/three 的 WebGL 实例与 DOM，node:test 无法装载；
// 其可确定性验证的数学已抽到 threatProjection（sphereSurfacePoint 往返见
// threatScene.spec ⑥/⑥b）。此处沿用 threatScene.spec ⑦ 的源码契约断言先例，
// 钉住「引擎接线」本身——这些修复全是单行接线，缺一行不会有编译错误，只能靠
// 契约断言守住。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const ROOT = join(HERE, '..')
const globeSrc = readFileSync(join(ROOT, 'src/utils/threatGlobe.ts'), 'utf8')

/** 截取成员体：对象方法（4 空格缩进）或闭包内函数（2 空格缩进）。 */
function member(src: string, marker: string): string {
  const start = src.indexOf(marker)
  assert.notEqual(start, -1, `缺少成员 ${marker}`)
  const objEnd = src.indexOf('\n    }', start)
  const fnEnd = src.indexOf('\n  }', start)
  const end = objEnd >= 0 && (fnEnd < 0 || objEnd < fnEnd) ? objEnd : fnEnd
  assert.notEqual(end, -1, `无法截取成员体 ${marker}`)
  return src.slice(start, end)
}

test('复位/返回必须作废在途省界加载（与地图引擎同源）', () => {
  for (const name of ['zoomOut', 'resetView']) {
    const body = member(globeSrc, `${name}(): void {`)
    const seqIdx = body.indexOf('drillSeq += 1')
    const viewIdx = body.indexOf('enterWorldView(')
    assert.ok(seqIdx >= 0, `${name} 必须递增 drillSeq`)
    assert.ok(viewIdx > seqIdx, `${name} 必须先作废在途加载再返回世界视角`)
  }
  // 续体判定必须走共享纯函数（地图/地球同一口径）
  assert.match(globeSrc, /drillCommitAllowed\(seq, drillSeq, disposed\)/)
})

test('暂停态相机变更必须直接落点并补绘一帧', () => {
  assert.match(globeSrc, /paused \? 0 : 700/, '下钻 pointOfView 必须按暂停态取 0 时长')
  const enter = member(globeSrc, 'function enterWorldView(')
  assert.match(enter, /paused \? 0 : duration/, '返回世界视角必须按暂停态取 0 时长')
  assert.match(enter, /if \(paused\) renderOnce\(\)/, '暂停态无自循环，必须手动补绘')
  assert.match(globeSrc, /threeRenderer\.render\(scene, cam\)/, 'renderOnce 必须真正渲染一帧')
})

test('下钻衬底=低透明度世界点阵，hover 他国只提亮点，且不再有 H3 死配置', () => {
  // 与 2D 地图同规则：非下钻国家降透明度点阵，不再使用国家多边形色块。
  assert.match(globeSrc, /worldDots\.filter\(\(d\) => d\.key !== drilledName\)/)
  assert.match(globeSrc, /DRILL_BACKDROP_OPACITY = 0\.22/)
  assert.match(globeSrc, /backdropDotsPoints\.visible = !!drilledName/)
  // alphaTest 若高于 opacity 会把低透明度点全部丢弃（本次不可见根因）。
  assert.match(globeSrc, /alphaTest: 0\.05/)
  assert.match(globeSrc, /size: DRILL_DOT_SIZE,\s+color: DRILL_BACKDROP_COLOR/)
  assert.doesNotMatch(globeSrc, /globe\.polygonsData\(|polygonCapColor\(/,
    '国家多边形衬底已退役，非下钻国家必须走暗度点阵')
  assert.doesNotMatch(globeSrc, /\.hexPolygonsData\(|\.hexPolygonResolution\(|\.hexPolygonMargin\(|\.hexPolygonColor\(/,
    'H3 六边形层从未有图元，死配置必须移除（避免再次误以为衬底走 hex）')
  const hover = member(globeSrc, 'function setHexHover(')
  assert.match(hover, /updateHoverDots\(name\)/, '下钻态 hover 他国必须只提亮该国点阵')
  assert.match(globeSrc, /hoverDotsPoints/, '下钻态 hover 需要独立亮色点阵层')
})

test('首帧双 RAF 无条件应用图层（两帧内下钻不得残留世界点阵）', () => {
  assert.doesNotMatch(globeSrc, /if \(!drilledName\) applyLayer\(\)/)
  const start = globeSrc.indexOf('两个 RAF')
  const end = globeSrc.indexOf('let rafId = requestAnimationFrame(frame)')
  assert.ok(start >= 0 && end > start, '双 RAF 首帧块缺失')
  assert.match(globeSrc.slice(start, end), /^\s*applyLayer\(\)$/m, '双 RAF 回调必须无条件 applyLayer()')
})

test('海外下钻浮签显示「无省级统计」而不是 0', () => {
  assert.match(globeSrc, /hasProvinceStats\(drilledName\)/)
  assert.match(globeSrc, /无省级统计/)
})
test('光流池满时拒绝新弧线，不淘汰已开始动画', () => {
  const spawn = member(globeSrc, 'function spawnArc(')
  assert.match(spawn, /if \(arcs\.length >= MAX_ARCS\) return/, '满池必须拒绝新弧线')
  assert.doesNotMatch(spawn, /arcs\.shift\(\)/, 'spawnArc 不得淘汰已开始弧线')
})

