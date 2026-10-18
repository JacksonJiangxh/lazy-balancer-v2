import {
  LAT_TOP,
  LAT_BOTTOM,
  WORLD_W,
  WORLD_D,
  DRILL_UNIFIED_ZOOM,
  latToY,
  yToLat,
  wrapDeg,
  wrapLon,
  worldToScreen,
  screenToLonLat,
  panBy,
  principalBounds,
  type Cam2D,
} from '@/utils/threatProjection'
import { THREAT_COUNTRIES } from '@/utils/worldBorders'
import { CHINA_PROVINCES } from '@/utils/chinaProvinces'
import { heatCss, heatEntriesEqual, pointInPolys as sharedPointInPolys, adminShortName as sharedShortName, DOT_LAND as SHARED_DOT_LAND, normalizeCountryName, aggregateCountryCounts } from '@/utils/threatShared'
import { COUNTRY_CENTROIDS, FALLBACK_CENTROID, type Centroid } from '@/utils/countryCentroids'
import { loadAdmin1Tables } from '@/utils/admin1Loader'
import { FLOW_ATTACK_COLOR as ATTACK_COLOR, FLOW_NORMAL_COLOR as NORMAL_COLOR, FLOW_FLIGHT_MS, flowArcLabel, flowAttackWidth, flowNormalWidth } from '@/utils/threatTheme'

// 威胁大屏 2D 平面地图引擎（v16 终版：Canvas 2D，参考 Radware/Check Point 平面风格）。
//
// v16 终审裁定弃 3D：等距圆柱平铺、等比缩放永不变形、DPR 原生渲染、线宽恒
// 1 物理像素。分层渲染：静态层（陆地+国家点阵热力）按 zoom/数据缓存离屏 canvas，
// 拖动=blit（360° 环绕三份拼接）；动态层（弧线/涟漪/扫掠/信标/hover/下钻省层）
// 每帧矢量叠绘。对外接口与 3D 版完全一致（ThreatScreen.vue 零改动）。
//
// 热力=绝对标尺（1→1000 命中，log10 归一），砖红三档 #964a3c/#c2553d/#e25454，
// 低命中向底色 #1b2a41 插值；无挤出无悬浮无双层——纯平面。
// 交互：左键拖动平移（横向 360° 无缝环绕、纵向钳制）、**滚轮不参与缩放**（用户
// 裁定 2026-10-17：缩放仅经点击下钻/返回流程控制）、hover=国家提亮+浮签、
// 点击国家下钻省级平面、点击空白返回、ESC 语义在 Vue 层。

const MAX_PIXEL_RATIO = 2
const MAX_ACTIVE_ARCS = 30
const ARC_FLIGHTS = 3
const ARC_FLIGHT_SECONDS = FLOW_FLIGHT_MS / 1000
const ARC_FLIGHT_GAP = 0.22
const ARC_FLIGHT_PARTICLES = 12
const ZOOM_SECONDS = 0.6
const RIPPLE_POOL = 12
// 静态层离屏位图宽度上限（物理像素）。总览 zoom 随视口宽度增长（width×2/360），
// 4K 屏可达 ~14，叠加 DPR 2 后宽度 >1 万物理像素（≈160MB）——超过上限时
// 按上限分配、由 blit 放大（极端屏轻微软化，换取内存有界；历史 历史问题
// 明确要求把 dpr 计入本判定）。
const MAX_STATIC_WIDTH = 4096
// 绝对热力标尺（log10(命中)/3 → 0..1），砖红三档，首段向底色插值

export interface CountryHeat {
  name: string
  count: number
}

export interface ThreatSceneOptions {
  serverCentroid?: Centroid | null
  /** 未配置站点坐标时隐藏本站信标与弹道，避免画出一个假站点。 */
  siteConfigured?: boolean
  /** 允许下钻的国家（缺省不限）；用于禁止无省级数据的海外下钻。 */
  drillCountries?: string[]
  onDrillChange?: (name: string | null) => void
  /** 省界数据按需加载失败（视图层 toast 一次；引擎按「无省层」降级不白屏）。 */
  onProvinceLoadError?: () => void
}

export interface ThreatScene {
  addArc(origin: Centroid): void
  addArcForLocation(ipLocation: string, weight?: number): void
  /** 正常请求光流（固定青色；逐请求事件流消费）。 */
  addNormalArcForLocation(ipLocation: string, weight?: number): void
  setCountries(entries: CountryHeat[]): void
  setProvinces(entries: CountryHeat[]): void
  setTraffic(entries: CountryHeat[]): void
  setServer(centroid: Centroid | null): void
  zoomOut(): void
  /** 复位视角（总览/本站居中，600ms）。 */
  resetView(): void
  /** 程序化启停交互（验证接缝；禁用时点击拾取仍工作）。 */
  setControlsEnabled(enabled: boolean): void
  /** 拾取诊断：屏幕坐标 → 命中国家（null=未命中）。 */
  pickCountryAt(clientX: number, clientY: number): string | null
  /** 相机状态（诊断；cx/cy 为地理坐标中心）。 */
  cameraState(): { zoom: number; cx: number; cy: number; dist: number; pos: [number, number, number] }
  setPaused(paused: boolean): void
  dispose(): void
}

interface Centroid2D {
  x: number
  y: number
}

interface Arc2D {
  from: Centroid
  elapsed: number
  flight: number
  flightT: number
  pulsed: boolean
  normal: boolean
  w: number
  weight: number
  label?: string
}

interface Ripple2D {
  age: number
}



function easeInOutCubic(t: number): number {
  return t < 0.5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2
}

function easeOutCubic(t: number): number {
  return 1 - Math.pow(1 - t, 3)
}

function polysBounds(polys: number[][][]): { minLon: number; maxLon: number; minLat: number; maxLat: number } {
  let minLon = 180
  let maxLon = -180
  let minLat = 90
  let maxLat = -90
  for (const poly of polys) {
    for (const ring of poly) {
      for (let i = 0; i + 1 < ring.length; i += 2) {
        const lon = ring[i]
        const lat = ring[i + 1]
        if (lon < minLon) minLon = lon
        if (lon > maxLon) maxLon = lon
        if (lat < minLat) minLat = lat
        if (lat > maxLat) maxLat = lat
      }
    }
  }
  return { minLon, maxLon, minLat, maxLat }
}


function pointInPolys(lon: number, lat: number, polys: number[][][]): boolean {
  return sharedPointInPolys(lon, lat, polys)
}

function makeLabelElement(text: string, color: string): HTMLDivElement {
  // 悬停浮签（引擎自管 DOM）：样式内联单源——scoped CSS 无法作用于引擎
  // 动态创建的节点（原 `.label-layer div` 选择器零匹配），背景/内边距/圆角
  // 此前完全缺失（深色底图上白字无底衬）。地球版 hoverTip 同视觉。
  const div = document.createElement('div')
  div.className = 'ts-label'
  div.textContent = text
  div.style.cssText = 'position:absolute;z-index:6;pointer-events:none;padding:5px 10px;background:rgba(4,12,32,.92);border:1px solid rgba(80,170,255,.45);border-radius:2px;color:' + color + ';font:12px "Noto Sans SC","PingFang SC",sans-serif;white-space:nowrap'
  return div
}

export function createThreatScene(container: HTMLElement, opts?: ThreatSceneOptions): ThreatScene {
  const onDrillChange = opts?.onDrillChange
  let sawServerConfig = !!opts?.serverCentroid
  let siteConfigured = opts?.siteConfigured ?? sawServerConfig
  let server: Centroid = opts?.serverCentroid ?? [0, (LAT_TOP + LAT_BOTTOM) / 2]

  // ---- 基建 ----
  const canvas = document.createElement('canvas')
  canvas.style.width = '100%'
  canvas.style.height = '100%'
  canvas.style.display = 'block'
  canvas.style.cursor = 'grab'
  container.appendChild(canvas)
  const ctx = canvas.getContext('2d')!

  // 标签层（CSS2D 等价：绝对定位 DOM）
  const labelLayer = document.createElement('div')
  labelLayer.style.position = 'absolute'
  labelLayer.style.inset = '0'
  labelLayer.style.overflow = 'hidden'
  labelLayer.style.pointerEvents = 'none'
  container.appendChild(labelLayer)

  // 静态层（世界：陆地+染色+国界；zoom/数据变化时重建，拖动=blit）
  const staticCanvas = document.createElement('canvas')
  const staticCtx = staticCanvas.getContext('2d')!

  let dpr = Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO)
  let minZoom = 1

  const cam: Cam2D = { camX: 0, camY: 0, zoom: 2, width: 1, height: 1 }
  // v26：总览按宽高双适配（取较小 zoom）——顶栏/底部卡片占位后上下留边，
  // 国家不再贴边无法点选。
  // v2.3.8 三轮放大（用户裁定）：高度满格（留 8px 缓冲）；宽度系数 1.15
  // （360° 环绕冗余可裁）让高度主导——世界高≈面板 98%。
  const overviewZoom = (): number => Math.max(minZoom, Math.min((cam.width * 2) / WORLD_W, (cam.height * 0.9) / WORLD_D))

  // ---- 数据 ----
  let countryCounts = new Map<string, number>()
  let provinceCounts = new Map<string, number>()
  let serverPos: Centroid2D = { x: 0, y: 0 }
  let userInteracted = false

  let drillLayerCountry = ''
  let drillProvinceData: { name: string; polys: number[][][]; centroid?: [number, number] }[] = []
  let hoverName: string | null = null
  let hoverScreen: Centroid2D | null = null
  let pendingHover: Centroid2D | null = null

  // ---- DOM 标签 ----
  const hoverTip = makeLabelElement('', '#e2e8f0')
  hoverTip.style.display = 'none'
  labelLayer.appendChild(hoverTip)

  function shortName(name: string): string {
    return sharedShortName(name)
  }

  // ---- 绘制辅助 ----
  /** 世界坐标（就近副本）→ 屏幕 CSS 像素。 */
  function toScreen(lon: number, lat: number): Centroid2D {
    return worldToScreen(lon, lat, cam)
  }

  /** 多边形 path（按就近副本平移，杜绝跨界撕裂）。 */

  // ---- 点阵网格（v2.3.8：与地球版六边形瓦片同视觉语言；一次栅格化缓存） ----
  /** 六边形瓦片路径（pointy-top，与 globe.gl hexbin 同款——用户裁定
   * 2026-10-17：地图点阵改成地球页面的六边形样式，替代圆点）。 */
  function dotPath(ctx2: CanvasRenderingContext2D, x: number, y: number, r: number): void {
    ctx2.beginPath()
    ctx2.arc(x, y, r, 0, Math.PI * 2)
  }
  function dotSubPath(path: Path2D, x: number, y: number, r: number): void {
    path.moveTo(x + r, y)
    path.arc(x, y, r, 0, Math.PI * 2)
  }
  interface Dot { lon: number; lat: number; key: string }
  function inCountryBbox(i: number, lon: number, lat: number): boolean {
    const b = bboxOf(i)
    if (lat < b.minLat || lat > b.maxLat) return false
    // bbox 跨日界线（如俄/美）时 minLon>maxLon 不可能（当前聚合取原始值），
    // 宽 bbox 只损失预筛收益，不会误杀。
    return lon >= b.minLon && lon <= b.maxLon
  }

  let worldDots: Dot[] | null = null
  /** 经度分桶（12°/桶）：下钻衬底每帧只遍历视口命中桶（原全量 ~1.3 万点/帧）。 */
  let worldDotsByKey: Map<string, Dot[]> | null = null
  let provinceDots: Dot[] | null = null
  // 与地球版同源：0.95° 错列网格、加大点径以匹配地球 5px/10px 的视觉尺寸。
  const DOT_STEP = 0.95
  // Mercator 总览 zoom 约 2.79；半径按原等距投影 zoom4.57 的比例折算，
  // 保持「点径/间距」与原地图一致，避免点互相粘连成色块。
  const DOT_R = 0.18
  const DOT_LAND = SHARED_DOT_LAND
  // 国家 bbox 预筛缓存
  const countryBboxes = THREAT_COUNTRIES.map((c) => ({ name: c.name, minLon: 0, maxLon: 0, minLat: 0, maxLat: 0, polys: c.polys, computed: false }))
  function bboxOf(i: number): { minLon: number; maxLon: number; minLat: number; maxLat: number } {
    const b = countryBboxes[i]
    if (!b.computed) {
      let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
      for (const poly of b.polys) for (const ring of poly) for (let k = 0; k + 1 < ring.length; k += 2) {
        if (ring[k] < minLon) minLon = ring[k]
        if (ring[k] > maxLon) maxLon = ring[k]
        if (ring[k + 1] < minLat) minLat = ring[k + 1]
        if (ring[k + 1] > maxLat) maxLat = ring[k + 1]
      }
      Object.assign(b, { minLon, maxLon, minLat, maxLat, computed: true })
    }
    return b
  }

  function buildWorldDots(): void {
    if (worldDots) return
    const dots: Dot[] = []
    let rowIdx = 0
    // Mercator 下按「投影后 y」等距布点，而不是按纬度等距：等纬度步长
    // 会在高纬被拉稀、低纬挤密（用户实测：上方稀、下方密、南半球显小）。
    const topY = latToY(84)
    const bottomY = latToY(-54.5)
    for (let y = topY; y < bottomY; y += DOT_STEP, rowIdx++) {
      const lat = yToLat(y)
      const lonOffset = rowIdx % 2 === 1 ? DOT_STEP / 2 : 0
      for (let lon = -179.5 + lonOffset; lon < 180; lon += DOT_STEP) {
        for (let ci = 0; ci < THREAT_COUNTRIES.length; ci++) {
          const b = bboxOf(ci)
          if (lon < b.minLon || lon > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
          if (pointInPolys(lon, lat, THREAT_COUNTRIES[ci].polys)) {
            dots.push({ lon, lat, key: normalizeCountryName(THREAT_COUNTRIES[ci].name) })
            break
          }
        }
      }
    }
    worldDots = dots
    const byKey = new Map<string, Dot[]>()
    for (const d of dots) {
      const keyed = byKey.get(d.key)
      if (keyed) keyed.push(d)
      else byKey.set(d.key, [d])
    }
    worldDotsByKey = byKey
  }

  /** 下钻省点阵（进入下钻时重建；省级命中按 short 名染色）。 */
  function buildProvinceDots(): void {
    if (!drillProvinceData.length) { provinceDots = null; return }
    let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
    for (const pv of drillProvinceData) {
      const b = polysBounds(pv.polys)
      minLon = Math.min(minLon, b.minLon); maxLon = Math.max(maxLon, b.maxLon)
      minLat = Math.min(minLat, b.minLat); maxLat = Math.max(maxLat, b.maxLat)
    }
    const dots: Dot[] = []
    let pRow = 0
    // 与世界层同一 Mercator 投影 y 步长/错列，避免下钻后密度随纬度变化。
    const pTopY = latToY(maxLat)
    const pBottomY = latToY(minLat)
    for (let y = pTopY; y <= pBottomY; y += DOT_STEP, pRow++) {
      const lat = yToLat(y)
      const lonOffset = pRow % 2 === 1 ? DOT_STEP / 2 : 0
      for (let lon = minLon + lonOffset; lon <= maxLon; lon += DOT_STEP) {
        for (const pv of drillProvinceData) {
          if (!pointInPolys(lon, lat, pv.polys)) continue
          dots.push({ lon, lat, key: shortName(pv.name) })
          break
        }
      }
    }
    provinceDots = dots
  }

  // ---- 静态层 ----
  let staticDirty = true

  /** 视口可见世界范围（经度 wrap 归一、纬度截断）。 */
  function visibleWorldBox(): { minLon: number; maxLon: number; minLat: number; maxLat: number } {
    const halfW = cam.width / 2 / cam.zoom
    const halfH = cam.height / 2 / cam.zoom
    return {
      minLon: cam.camX - halfW,
      maxLon: cam.camX + halfW,
      minLat: Math.max(LAT_BOTTOM, yToLat(cam.camY + halfH)),
      maxLat: Math.min(LAT_TOP, yToLat(cam.camY - halfH)),
    }
  }

  function rebuildStaticLayer(): void {
    // DPR 计入离屏分配（历史 历史问题）：原按 CSS 像素分配、blit 时放回 CSS
    // 尺寸 → Retina 下静态层被 2× 下采样（点阵发虚/边缘糊）。现按
    // zoom×dpr 分配并以同倍率变换绘制，blit 目标仍是 CSS 尺寸（1:1 物理像素）。
    const scale = Math.min(cam.zoom * dpr, MAX_STATIC_WIDTH / WORLD_W)
    const w = Math.ceil(WORLD_W * scale)
    const h = Math.ceil(WORLD_D * scale)
    // 尺寸不变时不要重写 width/height（会强制重分配后备存储，4K 下每次
    // 数据刷新可产生数十 MB 分配/GC）；仅 clear 后重绘。
    if (staticCanvas.width !== w || staticCanvas.height !== h) {
      staticCanvas.width = w
      staticCanvas.height = h
    }
    staticCtx.setTransform(1, 0, 0, 1, 0, 0)
    staticCtx.clearRect(0, 0, w, h)
    // v27 修复（用户实测「中国画在美洲」根因）：原 transform 平移 (WORLD_W/2)*zoom
    // 与 x=lon+180 叠加 → 整幅地图平移 360°（半世界错位：渲染与拾取相差 180°，
    // hover 中国=视觉美洲）。平移移除，x=lon+180 单独承担。
    staticCtx.setTransform(scale, 0, 0, scale, 0, 0)
    staticCtx.lineJoin = 'round'
    // 陆地衬底退役（用户裁定：单层点阵自表意，海洋即背景）
    // 点阵：普通陆地暗点，命中国家按热力染色（log10 计数标尺与地球版同源）
    buildWorldDots()
    if (worldDots) {
      const heatCache = new Map<string, string>()
      staticCtx.beginPath()
      for (const d of worldDots) {
        let fill = heatCache.get(d.key)
        if (fill === undefined) {
          const cnt = countryCounts.get(d.key) ?? 0
          fill = cnt > 0 ? heatCss(cnt) : DOT_LAND
          heatCache.set(d.key, fill)
        }
        staticCtx.fillStyle = fill
        dotPath(staticCtx, d.lon + WORLD_W / 2, latToY(d.lat), DOT_R * 1.35)
        staticCtx.fill()
      }
    }
    // 国界描边退役（v2.3.8 用户裁定：点阵已表意，无需分隔线）
    staticDirty = false
  }

  /** 静态层重建请求：下钻态使用独立世界坐标层（drillWorldCanvas），
   *  不使用世界静态层。 */
  function requestStaticLayer(): void {
    if (drillLayerCountry) {
      staticDirty = false
      return
    }
    if (staticDirty) rebuildStaticLayer()
  }

  /** 下钻悬浮点高亮（只画命中省的点，数量小，不进入离屏缓存）。 */
  function drawDrillHover(): void {
    if (!hoverName || !provinceDots) return
    const hoverShort = shortName(hoverName)
    const view = visibleWorldBox()
    const halfW = cam.width / 2 / cam.zoom
    const r = DOT_R * 1.35 * cam.zoom
    const path = new Path2D()
    let drew = false
    for (const d of provinceDots) {
      if (d.key !== hoverShort) continue
      if (Math.abs(wrapDeg(d.lon - cam.camX)) > halfW + 1) continue
      if (d.lat < view.minLat - 1 || d.lat > view.maxLat + 1) continue
      dotSubPath(path, cam.width / 2 + wrapDeg(d.lon - cam.camX) * cam.zoom, cam.height / 2 + (latToY(d.lat) - cam.camY) * cam.zoom, r)
      drew = true
    }
    if (!drew) {
      // 下钻态悬停其他国家（暗度衬底）：同样直接提亮该国点阵。
      buildWorldDots()
      for (const d of worldDotsByKey?.get(hoverName) ?? []) {
        if (Math.abs(wrapDeg(d.lon - cam.camX)) > halfW + 1) continue
        if (d.lat < view.minLat - 1 || d.lat > view.maxLat + 1) continue
        dotSubPath(path, cam.width / 2 + wrapDeg(d.lon - cam.camX) * cam.zoom, cam.height / 2 + (latToY(d.lat) - cam.camY) * cam.zoom, r)
        drew = true
      }
    }
    if (drew) {
      ctx.fillStyle = 'rgba(143, 230, 255, 0.55)'
      ctx.globalAlpha = 0.9
      ctx.fill(path)
      ctx.globalAlpha = 1
    }
  }

  // 世界暗度衬底用低分辨率缓存（约 720px 宽）：下钻高分辨率层只叠加省点阵，
  // 避免每次下钻把 1.3 万世界点重新栅格化到 4096px 画布（首帧长任务根因）。
  const dimWorldCanvas = document.createElement('canvas')
  const dimWorldCtx = dimWorldCanvas.getContext('2d')!
  let dimWorldScale = 0
  function ensureDimWorldLayer(): void {
    if (dimWorldScale > 0) return
    buildWorldDots()
    if (!worldDots) return
    const scale = Math.min(2, Math.max(1, dpr))
    dimWorldCanvas.width = Math.ceil(WORLD_W * scale)
    dimWorldCanvas.height = Math.ceil(WORLD_D * scale)
    dimWorldCtx.setTransform(scale, 0, 0, scale, 0, 0)
    dimWorldCtx.clearRect(0, 0, WORLD_W, WORLD_D)
    const path = new Path2D()
    for (const d of worldDots) {
      dotSubPath(path, d.lon + WORLD_W / 2, latToY(d.lat), DOT_R * 1.35)
    }
    dimWorldCtx.globalAlpha = 0.22
    dimWorldCtx.fillStyle = DOT_LAND
    dimWorldCtx.fill(path)
    dimWorldCtx.globalAlpha = 1
    dimWorldScale = scale
  }

  // 下钻世界坐标离屏层：按目标下钻 zoom 只构建一次，动画/拖动期间只做
  // drawImage，不再随相机重建（原屏幕空间缓存 120ms 重建一次仍造成动画卡顿）。
  const drillWorldCanvas = document.createElement('canvas')
  const drillWorldCtx = drillWorldCanvas.getContext('2d')!
  let drillDirty = true
  let drillWorldTargetZoom = DRILL_UNIFIED_ZOOM
  let drillWorldScale = 0
  let cacheDisposed = false
  function rebuildDrillWorldLayer(): void {
    buildWorldDots()
    if (!worldDots || !provinceDots) return
    // 下钻层用于背景衬底，实际显示会再缩放；2048px 宽足以保持点阵连贯，
    // 同时把首次下钻的 Path2D/栅格化成本压到可接受范围。
    const scale = Math.min(Math.max(1, drillWorldTargetZoom * dpr), MAX_STATIC_WIDTH / WORLD_W, 2048 / WORLD_W)
    const w = Math.ceil(WORLD_W * scale)
    const h = Math.ceil(WORLD_D * scale)
    if (drillWorldCanvas.width !== w || drillWorldCanvas.height !== h) {
      drillWorldCanvas.width = w
      drillWorldCanvas.height = h
    }
    ensureDimWorldLayer()
    drillWorldCtx.setTransform(scale, 0, 0, scale, 0, 0)
    drillWorldCtx.clearRect(0, 0, WORLD_W, WORLD_D)
    if (dimWorldScale > 0) drillWorldCtx.drawImage(dimWorldCanvas, 0, 0, WORLD_W, WORLD_D)
    const byColor = new Map<string, Path2D>()
    for (const d of provinceDots) {
      const cnt = provinceCounts.get(d.key) ?? 0
      const color = cnt > 0 ? heatCss(cnt) : DOT_LAND
      let path = byColor.get(color)
      if (!path) {
        path = new Path2D()
        byColor.set(color, path)
      }
      dotSubPath(path, d.lon + WORLD_W / 2, latToY(d.lat), DOT_R * 1.35)
    }
    drillWorldCtx.globalAlpha = 0.9
    for (const [color, path] of byColor) {
      drillWorldCtx.fillStyle = color
      drillWorldCtx.fill(path)
    }
    drillWorldCtx.globalAlpha = 1
    drillWorldScale = scale
    drillDirty = false
  }

  // ---- 交互 ----
  let controlsEnabled = true
  let dragging = false
  let dragMoved = false
  let dragLast: Centroid2D | null = null
  let dragStart: Centroid2D | null = null

  function canvasPoint(event: { clientX: number; clientY: number }): Centroid2D {
    const rect = canvas.getBoundingClientRect()
    return { x: event.clientX - rect.left, y: event.clientY - rect.top }
  }

  function onPointerDown(event: PointerEvent): void {
    if (!controlsEnabled || event.button !== 0) return
    dragging = true
    dragMoved = false
    dragLast = canvasPoint(event)
    dragStart = dragLast
    canvas.style.cursor = 'grabbing'
  }

  function onPointerMove(event: PointerEvent): void {
    const p = canvasPoint(event)
    if (dragging && dragLast && controlsEnabled) {
      const dx = p.x - dragLast.x
      const dy = p.y - dragLast.y
      if (Math.abs(p.x - (dragStart?.x ?? 0)) + Math.abs(p.y - (dragStart?.y ?? 0)) > 4) dragMoved = true
      userInteracted = true
      const next = panBy(cam, dx, dy)
      cam.camX = next.camX
      cam.camY = next.camY
      dragLast = p
      return
    }
    if (!pendingHover || Math.abs(pendingHover.x - p.x) > 2 || Math.abs(pendingHover.y - p.y) > 2) pendingHover = p
  }

  function onPointerUp(): void {
    dragging = false
    dragLast = null
    canvas.style.cursor = 'grab'
  }

  function onClick(event: MouseEvent): void {
    if (!controlsEnabled || dragMoved) {
      dragMoved = false
      return
    }
    const p = canvasPoint(event)
    const geo = screenToLonLat(p.x, p.y, cam)
    for (const country of THREAT_COUNTRIES) {
      if (pointInPolys(geo.lon, geo.lat, country.polys)) {
        void drillToCountry(normalizeCountryName(country.name))
        return
      }
    }
    if (drillLayerCountry) returnToWorld()
  }

  function onWheel(event: WheelEvent): void {
    // v2.3.8（用户裁定 2026-10-17）：滚轮不参与缩放——地图尺寸由总览/下钻
    // 视图固定，缩放仅经点击下钻/返回流程控制。
    if (!controlsEnabled) return
    event.preventDefault()
  }

  canvas.addEventListener('pointerdown', onPointerDown)
  canvas.addEventListener('pointermove', onPointerMove)
  window.addEventListener('pointerup', onPointerUp)
  canvas.addEventListener('click', onClick)
  canvas.addEventListener('wheel', onWheel, { passive: false })

  // ---- 下钻 ----
  function clearProvinceLayer(): void {
    drillProvinceData = []
    provinceDots = null
    drillLayerCountry = ''
    // 进入/退出下钻时清掉上一视图的国家 hover——否则 drawDrillHover 会把
    // 整个中国点阵当「悬停国」再提亮一层，出现整块青色（实测）。
    hoverName = null
    hoverScreen = null
    pendingHover = null
    hoverTip.style.display = 'none'
    drillDirty = true
  }

  // ---- 省界数据按需加载（历史 历史问题） ----
  // admin1Provinces 是 1.9MB 静态表——顶栏首屏不需要它（仅下钻时消费）。
  // 共享加载器动态 import：Vite 切出独立 chunk，总览首屏零下载；加载失败按
  // 「无省层」降级（不白屏、不进下钻），并经 onProvinceLoadError 让视图 toast。
  async function loadProvinceRows(country: string): Promise<{ name: string; polys: number[][][]; centroid?: [number, number] }[] | null> {
    if (country === '中国') {
      return CHINA_PROVINCES.map((pv) => ({ name: pv.name, polys: pv.polys, centroid: [pv.centroid[0], pv.centroid[1]] }))
    }
    const tables = await loadAdmin1Tables()
    if (!tables) {
      opts?.onProvinceLoadError?.()
      return null
    }
    return tables[country] ?? []
  }

  function buildProvinceLayer(country: string, provinces: { name: string; polys: number[][][]; centroid?: [number, number] }[], zoom: number): void {
    clearProvinceLayer()
    drillProvinceData = provinces
    drillLayerCountry = country
    drillWorldTargetZoom = zoom
    drillDirty = true
    buildProvinceDots()
  }

  function returnToWorld(): void {
    drillSeq += 1 // 作废在途省界加载（加载完成后不得再进入下钻）
    clearProvinceLayer()
    flyToOverview()
    if (onDrillChange) onDrillChange(null)
  }

  let drillSeq = 0

  async function drillToCountry(country: string): Promise<void> {
    country = normalizeCountryName(country)
    const c = THREAT_COUNTRIES.find((x) => x.name === country)
    if (!c) return
    const seq = ++drillSeq
    const b = principalBounds(c.polys)
    const clon0 = (b.minLon + b.maxLon) / 2
    const clon = clon0 > 180 ? clon0 - 360 : clon0
    const clat = (b.minLat + b.maxLat) / 2
    // v2.3.8（用户裁定）：下钻统一放大倍率——按国家 bbox 自适应曾对美/俄
    // 等超幅员国家产生过高 zoom（显示不全/跳动）；统一倍率+拖动自由探索。
    const zoom = DRILL_UNIFIED_ZOOM
    // 目标 camY 预钳制（俄罗斯质心 61°N 越上界——动画落点被 tick 钳制 snap
    // 上跳，与「复位下坠」同款根因）
    const visH = cam.height / zoom
    const targetY = visH >= WORLD_D
      ? WORLD_D / 2
      : Math.min(WORLD_D - visH / 2, Math.max(visH / 2, latToY(clat)))
    // 中国走内置高精度表（无需异步）；其余国家按需加载省界 chunk。
    const provinces = await loadProvinceRows(country)
    if (seq !== drillSeq) return // 加载期间又点击了别国/返回 → 丢弃
    // 无省层数据（含加载失败）：不进入下钻、不切换提示/返回按钮——
    // 原实现先 flyTo+onDrillChange 再发现无数据，画面成「被选国家空洞」。
    if (!provinces || provinces.length === 0) return
    buildProvinceLayer(country, provinces, zoom)
    flyTo(clon, targetY, zoom)
    if (onDrillChange) onDrillChange(country)
  }

  // ---- 相机动画 ----
  interface CamAnim {
    from: { camX: number; camY: number; zoom: number }
    to: { camX: number; camY: number; zoom: number }
    elapsed: number
  }
  let camAnim: CamAnim | null = null

  /** 相机落点归一（tick 末尾同口径）：camX wrap、camY 按可视高钳制。 */
  function applyCamTarget(camX: number, camY: number, zoom: number): void {
    cam.camX = wrapDeg(camX)
    cam.zoom = zoom
    const visH = cam.height / zoom
    cam.camY = visH >= WORLD_D
      ? WORLD_D / 2
      : Math.min(WORLD_D - visH / 2, Math.max(visH / 2, camY))
    staticDirty = true
    serverPos = toScreen(server[0], server[1])
  }

  function flyTo(camX: number, camY: number, zoom: number): void {
    const fromX = cam.camX
    const toX = fromX + wrapDeg(camX - fromX)
    // 暂停态无动画帧驱动（rafId=0）：直接落点并补绘一帧，否则「复位视角/返回
    // 世界/下钻」在暂停中静默无反应（历史 历史问题）。
    if (paused) {
      applyCamTarget(toX, camY, zoom)
      renderOnce()
      return
    }
    camAnim = {
      from: { camX: fromX, camY: cam.camY, zoom: cam.zoom },
      to: { camX: toX, camY, zoom },
      elapsed: 0,
    }
  }

  function flyToOverview(): void {
    // v2.3.8 修复「复位后地图整体向下」：目标 camY 先按总览 zoom 的可视高
    // 钳制——原目标=本站纬度（动画中 camY 合法），tick 末尾归一钳制再把它
    // 拉回 WORLD_D 中心，观感即动画结束后整幅下坠。
    const z = overviewZoom()
    const visH = cam.height / z
    const targetY = visH >= WORLD_D
      ? WORLD_D / 2
      : Math.min(WORLD_D - visH / 2, Math.max(visH / 2, latToY(server[1])))
    flyTo(server[0], targetY, z)
  }

  // ---- 特效 ----
  const arcs: Arc2D[] = []
  const ripples: Ripple2D[] = []
  let sweepAngle = 0

  function spawnArc(origin: Centroid, normal: boolean, weight = 1): void {
    if (!siteConfigured) return
    if (arcs.length >= MAX_ACTIVE_ARCS) arcs.shift()
    // 同源聚合权重 → 弧宽（log 标尺上限钳 4：百次/秒下视觉可控）
    const w = Math.min(4, 0.6 + Math.log10(Math.max(1, weight)))
    // 同一地区/秒 >10 条才带聚合标签；≤10 逐条无标签。
    const label = flowArcLabel(weight)
    arcs.push({ from: origin, elapsed: 0, flight: 0, flightT: 0, pulsed: false, normal, w, weight, label })
  }

  function spawnRipple(): void {
    if (ripples.length >= RIPPLE_POOL) ripples.shift()
    ripples.push({ age: 0 })
  }

  function bezierPoint(p0: Centroid2D, p1: Centroid2D, p2: Centroid2D, t: number): Centroid2D {
    const u = 1 - t
    return {
      x: u * u * p0.x + 2 * u * t * p1.x + t * t * p2.x,
      y: u * u * p0.y + 2 * u * t * p1.y + t * t * p2.y,
    }
  }

  function drawArcs(delta: number): void {
    for (let i = arcs.length - 1; i >= 0; i--) {
      const arc = arcs[i]
      arc.elapsed += delta
      arc.flightT += delta
      const life = arc.normal
        ? ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP
        : ARC_FLIGHTS * (ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP)
      if (arc.flightT >= ARC_FLIGHT_SECONDS) {
        if (!arc.pulsed) {
          arc.pulsed = true
          if (!arc.normal) spawnRipple()
        }
        if (arc.flightT >= ARC_FLIGHT_SECONDS + ARC_FLIGHT_GAP) {
          if (arc.normal || arc.flight + 1 >= ARC_FLIGHTS) {
            arcs.splice(i, 1)
            continue
          }
          arc.flight += 1
          arc.flightT = 0
          arc.pulsed = false
        }
      }
      // 屏幕空间二次贝塞尔（质心→本站，控制点居中抬高）
      const from = toScreen(arc.from[0], arc.from[1])
      const to = { x: serverPos.x, y: serverPos.y }
      const dist = Math.hypot(to.x - from.x, to.y - from.y)
      if (dist < 2 || dist > Math.max(cam.width, cam.height) * 1.2) continue
      const ctrl = { x: (from.x + to.x) / 2, y: (from.y + to.y) / 2 - dist * 0.28 }
      const head = easeOutCubic(Math.min(1, arc.flightT / ARC_FLIGHT_SECONDS))
      const color = arc.normal ? NORMAL_COLOR : ATTACK_COLOR
      const segments = 64
      ctx.beginPath()
      let last: Centroid2D | null = null
      for (let s = 0; s <= segments * head; s++) {
        const pt = bezierPoint(from, ctrl, to, s / segments)
        if (!last) ctx.moveTo(pt.x, pt.y)
        else ctx.lineTo(pt.x, pt.y)
        last = pt
      }
      // 渐变发光描边（头亮尾隐）
      if (last) {
        const gradient = ctx.createLinearGradient(from.x, from.y, to.x, to.y)
        gradient.addColorStop(0, 'rgba(0,0,0,0)')
        gradient.addColorStop(1, color)
        ctx.strokeStyle = gradient
        ctx.lineWidth = arc.normal ? flowNormalWidth(arc.weight) : flowAttackWidth(arc.weight)
        ctx.globalAlpha = arc.normal ? 0.5 : Math.min(1, Math.max(0.05, (life - arc.elapsed) / 0.4))
        ctx.stroke()
        ctx.globalAlpha = 1
        if (arc.label) {
          ctx.font = '11px ui-monospace, monospace'
          ctx.fillStyle = arc.normal ? NORMAL_COLOR : ATTACK_COLOR
          ctx.textBaseline = 'middle'
          ctx.fillText(arc.label, from.x + 8, from.y - 8)
        }
      }
      // 亮头粒子拖尾
      if (head < 1 || !arc.normal) {
        for (let p = 0; p < ARC_FLIGHT_PARTICLES; p++) {
          const t = Math.max(0, head - p * (0.16 / ARC_FLIGHT_PARTICLES))
          const pt = bezierPoint(from, ctrl, to, t)
          const r = arc.normal ? 1.1 : 2 - p * 0.12
          ctx.beginPath()
          ctx.arc(pt.x, pt.y, Math.max(0.4, r), 0, Math.PI * 2)
          ctx.fillStyle = color
          ctx.globalAlpha = (arc.normal ? 0.5 : 0.9) * (1 - p / ARC_FLIGHT_PARTICLES)
          ctx.fill()
        }
        ctx.globalAlpha = 1
      }
    }
  }

  function drawRipples(delta: number): void {
    for (let i = ripples.length - 1; i >= 0; i--) {
      const ripple = ripples[i]
      ripple.age += delta
      const t = ripple.age / 1.8
      if (t >= 1) {
        ripples.splice(i, 1)
        continue
      }
      const r = 3 + t * 26
      ctx.beginPath()
      ctx.arc(serverPos.x, serverPos.y, r, 0, Math.PI * 2)
      ctx.strokeStyle = ATTACK_COLOR
      ctx.lineWidth = 1.5
      ctx.globalAlpha = 0.85 * (1 - t)
      ctx.stroke()
      ctx.globalAlpha = 1
    }
  }

  function drawSiteMarker(): void {
    if (!siteConfigured) return
    // 十字标
    ctx.strokeStyle = '#e2e8f0'
    ctx.lineWidth = 1.4
    ctx.globalAlpha = 0.95
    ctx.beginPath()
    ctx.moveTo(serverPos.x - 7, serverPos.y)
    ctx.lineTo(serverPos.x - 2.5, serverPos.y)
    ctx.moveTo(serverPos.x + 2.5, serverPos.y)
    ctx.lineTo(serverPos.x + 7, serverPos.y)
    ctx.moveTo(serverPos.x, serverPos.y - 7)
    ctx.lineTo(serverPos.x, serverPos.y - 2.5)
    ctx.moveTo(serverPos.x, serverPos.y + 2.5)
    ctx.lineTo(serverPos.x, serverPos.y + 7)
    ctx.stroke()
    // 外圈
    ctx.beginPath()
    ctx.arc(serverPos.x, serverPos.y, 5, 0, Math.PI * 2)
    ctx.stroke()
    // 本站文字（画布内绘制，图标右侧 14px 垂直居中）
    ctx.font = '11px "Noto Sans SC", "PingFang SC", sans-serif'
    ctx.fillStyle = '#8ea7d6'
    ctx.textBaseline = 'middle'
    ctx.fillText('本站', serverPos.x + 14, serverPos.y)
    // 顶部光点
    ctx.beginPath()
    ctx.arc(serverPos.x, serverPos.y - 11, 2.4, 0, Math.PI * 2)
    ctx.fillStyle = '#e2e8f0'
    ctx.fill()
    ctx.globalAlpha = 1
  }

  // v27 恢复（用户裁定加回）：本站雷达扫掠光线——旋转扇形光束，低透明度
  // 不与热力色块/弧线打架（旧 conic 大扇退役原因），扫过全屏半径以内。
  let sweepGrad: CanvasGradient | null = null
  let sweepGradAngle = -1
  let sweepGradX = -1
  let sweepGradY = -1
  function drawSiteSweep(): void {
    if (!siteConfigured) return
    // 角度由 tick 统一推进（每帧 delta*0.9 rad/s）；此处只消费不复位/不自增
    const r = Math.hypot(cam.width, cam.height) / 2 + 40
    // createConicGradient 是下钻/放大态的高开销调用：角度变化 <0.05rad 或
    // 站点未移动时复用上一帧渐变（约 20Hz 更新，视觉足够平滑）。
    if (!sweepGrad || Math.abs(sweepAngle - sweepGradAngle) > 0.05 ||
      Math.abs(serverPos.x - sweepGradX) > 0.5 || Math.abs(serverPos.y - sweepGradY) > 0.5) {
      sweepGrad = ctx.createConicGradient ? ctx.createConicGradient(sweepAngle, serverPos.x, serverPos.y) : null
      sweepGradAngle = sweepAngle
      sweepGradX = serverPos.x
      sweepGradY = serverPos.y
    }
    const grad = sweepGrad
    if (!grad) return
    // 前缘亮、尾缘淡的单束扫掠（0~0.9rad 扇区）
    grad.addColorStop(0, 'rgba(120,190,255,0.22)')
    grad.addColorStop(0.14, 'rgba(120,190,255,0.05)')
    grad.addColorStop(1, 'rgba(120,190,255,0)')
    ctx.save()
    ctx.beginPath()
    ctx.moveTo(serverPos.x, serverPos.y)
    ctx.arc(serverPos.x, serverPos.y, r, sweepAngle, sweepAngle + 0.9)
    ctx.closePath()
    ctx.fillStyle = grad
    ctx.fill()
    ctx.restore()
  }

  function drawHoverHighlight(): void {
    if (!hoverName) return
    // 与地球模式统一：不铺半透明多边形，直接把命中该国的点阵提亮（地球是
    // 直接改 hex 颜色）。worldDotsByKey 预索引，悬停国通常数百点。
    buildWorldDots()
    const dots = worldDotsByKey?.get(hoverName)
    if (!dots) return
    const view = visibleWorldBox()
    const halfW = cam.width / 2 / cam.zoom
    const path = new Path2D()
    let n = 0
    for (const d of dots) {
      if (Math.abs(wrapDeg(d.lon - cam.camX)) > halfW + 1) continue
      if (d.lat < view.minLat - 1 || d.lat > view.maxLat + 1) continue
      dotSubPath(path, cam.width / 2 + wrapDeg(d.lon - cam.camX) * cam.zoom, cam.height / 2 + (latToY(d.lat) - cam.camY) * cam.zoom, DOT_R * 1.35 * cam.zoom)
      n++
    }
    if (n > 0) {
      ctx.fillStyle = '#8fe6ff'
      ctx.globalAlpha = 0.9
      ctx.fill(path)
      ctx.globalAlpha = 1
    }
  }

  // ---- 主循环 ----
  let rafId = 0
  let paused = false
  let lastTime = performance.now()

  function updateHoverTip(): void {
    if (hoverName && hoverScreen) {
      hoverTip.style.display = 'block'
      hoverTip.style.transform = `translate(${(hoverScreen.x + 14).toFixed(1)}px, ${(hoverScreen.y - 8).toFixed(1)}px)`
    } else {
      hoverTip.style.display = 'none'
    }
  }

  /** 单帧合成（tick 与暂停补绘共用，历史 历史问题）：静态层 + hover +
   *  下钻省层 + 全部动态层（弧线/涟漪/信标/扫掠/浮签）。暂停帧传 delta=0：
   *  画面元素在位但动画不推进——原 renderOnce 只画静态层+浮签，暂停后弧线/
   *  信标/扫掠整层消失。 */
  function paintComposite(delta: number): void {
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    ctx.clearRect(0, 0, cam.width, cam.height)
    const dw = WORLD_W * cam.zoom
    const dh = WORLD_D * cam.zoom
    if (drillLayerCountry) {
      // 下钻世界坐标层：动画与稳定态都只 blit；相机变化不再触发点阵重建。
      if (drillDirty || drillWorldScale === 0) rebuildDrillWorldLayer()
      const baseLon = wrapLon(cam.camX)
      const sx = cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom
      const sy = cam.height / 2 - cam.camY * cam.zoom
      for (const offset of [-dw, 0, dw]) {
        if (sx + offset > cam.width || sx + offset + dw < 0) continue
        ctx.drawImage(drillWorldCanvas, sx + offset, sy, dw, dh)
      }
      drawDrillHover()
    } else {
      const baseLon = wrapLon(cam.camX)
      const sx = cam.width / 2 - (baseLon + WORLD_W / 2) * cam.zoom
      const sy = cam.height / 2 - cam.camY * cam.zoom
      for (const offset of [-dw, 0, dw]) {
        if (sx + offset > cam.width || sx + offset + dw < 0) continue
        ctx.drawImage(staticCanvas, sx + offset, sy, dw, dh)
      }
    }
    // 世界 hover 提亮；下钻态 hover 由 drawDrillHover 只画命中省。
    if (!drillLayerCountry) drawHoverHighlight()
    drawArcs(delta)
    drawRipples(delta)
    drawSiteMarker()
    drawSiteSweep()
    updateHoverTip()
  }

  const tick = (): void => {
    rafId = requestAnimationFrame(tick)
    const now = performance.now()
    const delta = Math.min(0.1, (now - lastTime) / 1000)
    lastTime = now
    sweepAngle += delta * 0.9
    serverPos = toScreen(server[0], server[1])

    // 相机飞行
    if (camAnim) {
      camAnim.elapsed += delta
      const t = Math.min(1, camAnim.elapsed / ZOOM_SECONDS)
      const e = easeInOutCubic(t)
      cam.camX = camAnim.from.camX + (camAnim.to.camX - camAnim.from.camX) * e
      cam.camY = camAnim.from.camY + (camAnim.to.camY - camAnim.from.camY) * e
      cam.zoom = camAnim.from.zoom + (camAnim.to.zoom - camAnim.from.zoom) * e
      // 动画期间不重建静态层（原每帧 staticDirty=true → 每帧重分配整幅离屏
      // 画布并逐点重绘，0.6s 动画≈36 次全量栅格化）。blit 本身已按当前 zoom
      // 缩放旧位图（短暂软化可接受）；动画结束补一次重建保证清晰度。
      if (t >= 1) {
        camAnim = null
        staticDirty = true
      }
    }

    // hover 拾取（帧内一次）
    if (pendingHover) {
      hoverScreen = pendingHover
      const geo = screenToLonLat(pendingHover.x, pendingHover.y, cam)
      hoverName = null
      if (drillLayerCountry) {
        // 下钻态：先测省（选中国家内），未命中再测其他国家（暗度衬底同样
        // 可 hover——用户裁定 2026-10-17）
        for (const pv of drillProvinceData) {
          if (pointInPolys(geo.lon, geo.lat, pv.polys)) {
            hoverName = pv.name
            hoverTip.textContent = `${shortName(pv.name)} ${provinceCounts.get(shortName(pv.name)) ?? provinceCounts.get(pv.name) ?? 0}`
            break
          }
        }
        if (!hoverName) {
          for (let ci = 0; ci < THREAT_COUNTRIES.length; ci++) {
            const country = THREAT_COUNTRIES[ci]
            const normalized = normalizeCountryName(country.name)
            if (normalized === drillLayerCountry) continue
            if (inCountryBbox(ci, geo.lon, geo.lat) && pointInPolys(geo.lon, geo.lat, country.polys)) {
              hoverName = normalized
              hoverTip.textContent = `${hoverName} ${countryCounts.get(hoverName) ?? 0}`
              break
            }
          }
        }
      } else {
        for (let ci = 0; ci < THREAT_COUNTRIES.length; ci++) {
          const country = THREAT_COUNTRIES[ci]
          if (inCountryBbox(ci, geo.lon, geo.lat) && pointInPolys(geo.lon, geo.lat, country.polys)) {
            hoverName = normalizeCountryName(country.name)
            hoverTip.textContent = `${hoverName} ${countryCounts.get(hoverName) ?? 0}`
            break
          }
        }
      }
      canvas.style.cursor = hoverName ? 'pointer' : 'grab'
      pendingHover = null
    }

    requestStaticLayer()
    paintComposite(delta)

    // v27 终修（tick 末尾）：camX 每帧归一 + camY 钳制——必须放在 camAnim 插值
    // 之后：动画目标未 wrap 时每帧插值会把 camX 写脏（用户实测 cx=684.4），
    // 开头归一无效。末尾归一保证下一帧渲染/拾取/信标全体消费端一致。
    cam.camX = wrapDeg(cam.camX)
    const visHFrame = cam.height / cam.zoom
    if (visHFrame >= WORLD_D) cam.camY = WORLD_D / 2
    else cam.camY = Math.min(WORLD_D - visHFrame / 2, Math.max(visHFrame / 2, cam.camY))
  }

  const startLoop = (): void => {
    if (!rafId && !paused) {
      lastTime = performance.now()
      rafId = requestAnimationFrame(tick)
    }
  }

  /** 暂停态单帧补绘（尺寸变化/复位/暂停切换共用；与 tick 同合成路径）。 */
  const renderOnce = (): void => {
    if (rafId || !paused) return
    serverPos = toScreen(server[0], server[1])
    requestStaticLayer()
    paintComposite(0)
  }

  // ---- 尺寸 ----
  const applySize = (): void => {
    const w = container.clientWidth || 1
    const h = container.clientHeight || 1
    dpr = Math.min(window.devicePixelRatio || 1, MAX_PIXEL_RATIO)
    canvas.width = Math.round(w * dpr)
    canvas.height = Math.round(h * dpr)
    cam.width = w
    cam.height = h
    // v26 修复：minZoom 固定 0.35——原 Math.max(h/WORLD_D, 0.35) 强制地图高≥视口，
    // 总览缩小（宽高双适配留边）从未生效，顶/底国家恒贴边不可选（用户实测实锤）。
    minZoom = 0.35
    staticDirty = true
    // v27 修复（初始地图偏高）：ResizeObserver 在布局落定后二次触发 applySize，
    // 但 zoom 仍是旧尺寸算的总览值——用户未交互且未下钻时随尺寸刷新总览。
    if (!userInteracted && !drillLayerCountry && !camAnim) cam.zoom = overviewZoom()
    // 暂停态无 tick 驱动：尺寸变化后必须补绘一帧，否则画布是新尺寸的空白
    // （历史 历史问题）。
    if (paused) renderOnce()
  }
  const resizeObserver = typeof ResizeObserver !== 'undefined' ? new ResizeObserver(applySize) : null
  resizeObserver?.observe(container)
  window.addEventListener('resize', applySize)
  applySize()
  cam.camX = server[0]
  cam.camY = latToY(server[1])
  cam.zoom = overviewZoom()
  startLoop()

  // 预热世界暗度衬底（约 1.3 万点 Path2D）——放到空闲期，避免用户第一次
  // 点击下钻时同步构建造成 300–500ms 首帧长任务。
  const warmDrillCaches = (): void => {
    if (cacheDisposed) return
    buildWorldDots()
    ensureDimWorldLayer()
  }
  if (typeof window.requestIdleCallback === 'function') {
    window.requestIdleCallback(warmDrillCaches, { timeout: 2000 })
  } else {
    window.setTimeout(warmDrillCaches, 50)
  }

  return {
    addArc(origin: Centroid): void {
      spawnArc(origin, false)
      startLoop()
    },
    addArcForLocation(ipLocation: string, weight = 1): void {
      if (!ipLocation) return
      const [country, province] = ipLocation.split('·')
      if (!country) return
      if (country === '中国') {
        const pv = province ? CHINA_PROVINCES.find((x) => x.short === province || x.name === province) : undefined
        const c: Centroid = pv ? [pv.centroid[0], pv.centroid[1]] : COUNTRY_CENTROIDS['中国']
        spawnArc(c, false, weight)
        startLoop()
        return
      }
      spawnArc(COUNTRY_CENTROIDS[country] ?? FALLBACK_CENTROID, false, weight)
      startLoop()
    },
    addNormalArcForLocation(ipLocation: string, weight = 1): void {
      if (!ipLocation) return
      const [country, province] = ipLocation.split('·')
      if (!country) return
      if (country === '中国') {
        const pv = province ? CHINA_PROVINCES.find((x) => x.short === province || x.name === province) : undefined
        spawnArc(pv ? [pv.centroid[0], pv.centroid[1]] : COUNTRY_CENTROIDS['中国'], true, weight)
      } else {
        spawnArc(COUNTRY_CENTROIDS[country] ?? FALLBACK_CENTROID, true, weight)
      }
      startLoop()
    },
    setCountries(entries: CountryHeat[]): void {
      // 30s 轮询同数据不得触发整幅静态层重建（历史 历史问题）：长度+逐键
      // 浅比较，无变化直接返回（原恒 staticDirty=true → 每轮全量栅格化）。
      const nextCounts = aggregateCountryCounts(entries)
      if (heatEntriesEqual(countryCounts, [...nextCounts].map(([name, count]) => ({ name, count })))) return
      countryCounts = nextCounts
      staticDirty = true
      if (!drillLayerCountry) drillDirty = true
      // 暂停态无 tick 驱动：数据到达即补绘（否则热力染色停在上一次暂停帧）
      if (paused) renderOnce()
    },
    setProvinces(entries: CountryHeat[]): void {
      if (heatEntriesEqual(provinceCounts, entries)) return
      provinceCounts = new Map(entries.map((e) => [e.name, e.count]))
      drillDirty = true
      if (paused) renderOnce()
    },
    setTraffic(entries: CountryHeat[]): void {
      // 正常请求同样按地区聚合：weight=采样窗口计数，>10 带 ×N 标签。
      for (const entry of entries) {
        if (entry.count <= 0) continue
        spawnArc(COUNTRY_CENTROIDS[entry.name] ?? FALLBACK_CENTROID, true, entry.count)
      }
      startLoop()
    },
    setServer(centroid: Centroid | null): void {
      if (centroid && !sawServerConfig) {
        sawServerConfig = true
        siteConfigured = true
        server = [centroid[0], centroid[1]]
        cam.camX = server[0]
        cam.camY = latToY(server[1])
        startLoop()
      }
    },
    zoomOut(): void {
      drillSeq += 1
      clearProvinceLayer()
      flyToOverview()
      startLoop()
    },
    resetView(): void {
      drillSeq += 1
      clearProvinceLayer()
      flyToOverview()
    },
    setControlsEnabled(enabled: boolean): void {
      controlsEnabled = enabled
      if (!enabled) {
        dragging = false
        dragLast = null
      }
    },
    pickCountryAt(clientX: number, clientY: number): string | null {
      const rect = canvas.getBoundingClientRect()
      const geo = screenToLonLat(clientX - rect.left, clientY - rect.top, cam)
      for (const country of THREAT_COUNTRIES) {
        if (pointInPolys(geo.lon, geo.lat, country.polys)) return country.name
      }
      return null
    },
    cameraState(): { zoom: number; cx: number; cy: number; dist: number; pos: [number, number, number] } {
      return {
        zoom: Number(cam.zoom.toFixed(2)),
        cx: Number(wrapLon(cam.camX).toFixed(1)),
        cy: Number(yToLat(cam.camY).toFixed(1)),
        dist: Number((1000 / cam.zoom).toFixed(0)),
        pos: [Number(wrapLon(cam.camX).toFixed(1)), Number(cam.zoom.toFixed(2)), Number(cam.camY.toFixed(1))],
      }
    },
    setPaused(value: boolean): void {
      if (paused === value) return
      paused = value
      if (value) {
        cancelAnimationFrame(rafId)
        rafId = 0
        renderOnce()
      } else {
        startLoop()
      }
    },
    dispose(): void {
      cacheDisposed = true
      cancelAnimationFrame(rafId)
      rafId = 0
      resizeObserver?.disconnect()
      window.removeEventListener('resize', applySize)
      window.removeEventListener('pointerup', onPointerUp)
      canvas.removeEventListener('pointerdown', onPointerDown)
      canvas.removeEventListener('pointermove', onPointerMove)
      canvas.removeEventListener('click', onClick)
      canvas.removeEventListener('wheel', onWheel)
      hoverTip.remove()
      // 提前释放离屏位图后备存储（GC 前即可归还内存）
      staticCanvas.width = 0
      staticCanvas.height = 0
      drillWorldCanvas.width = 0
      drillWorldCanvas.height = 0
      dimWorldCanvas.width = 0
      dimWorldCanvas.height = 0
      canvas.remove()
      labelLayer.remove()
    },
  }
}
