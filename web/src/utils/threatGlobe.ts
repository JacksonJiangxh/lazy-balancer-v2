// 威胁大屏「地球模式」引擎（v2.3.8）：globe.gl(three.js) 旋转地球 + 垂直扫描
// 特效。与 threatScene.ts（360°地图+雷达扫掠）实现同一 ThreatScene 接口——
// ThreatScreen.vue 按设置 threat_screen_mode 二选一装载，数据管线/UI 完全复用。
// 渲染：世界态=点阵国家热力（可点击下钻，不着色陆地）；下钻态=该国一级行政区
// 点阵（中国=chinaProvinces 34 省高精度；其余=admin1Provinces）+ 他国暗度点阵
// 衬底（与地图版下钻同视觉）；攻击弧线/本站涟漪/扫描光带。扫描 shader 移植自
// 参考实现（threat-wall，用户友人制作，授权改造）。
import Globe from 'globe.gl'
import type { GlobeInstance } from 'globe.gl'
import * as THREE from 'three'
import type { Centroid } from '@/utils/countryCentroids'
import { COUNTRY_CENTROIDS, FALLBACK_CENTROID } from '@/utils/countryCentroids'
import { THREAT_COUNTRIES } from '@/utils/worldBorders'
import { CHINA_PROVINCES } from '@/utils/chinaProvinces'
import { loadAdmin1Tables, loadedAdmin1Tables } from '@/utils/admin1Loader'
import { heatCss, heatEntriesEqual, pointInPolys as sharedPointInPolys, arcEndpoints, adminShortName, normalizeCountryName, aggregateCountryCounts, drillCountryAllowed, DOT_LAND, arcOriginForLocation, hasProvinceStats, drillCommitAllowed, drillClickIntent } from '@/utils/threatShared'
import type { ThreatScene, ThreatSceneOptions, CountryHeat } from '@/utils/threatScene'
import { FLOW_ATTACK_COLOR, FLOW_NORMAL_COLOR, FLOW_FLIGHT_MS, flowArcLabel, flowArcWidth } from '@/utils/threatTheme'
import { planFlowArcs } from '@/utils/threatFlowRules'
import { sphereSurfacePoint, DOT_LAT_TOP, DOT_LAT_BOTTOM } from '@/utils/threatProjection'
import { buildSphericalArc, SPHERICAL_ARC_SAMPLES } from '@/utils/threatArcCurve'

interface ArcDatum {
  startLat: number
  startLng: number
  endLat: number
  endLng: number
  color: string
  weight: number
  label?: string
  born: number
  /** 球面大圆采样点 xyz 平铺；spawn 时生成一次，帧内只投影不重建。 */
  curve: Float32Array
}

// 世界总览相机高度：2.4 实测球体偏小；1.8 放大约 1/3。
const WORLD_ALTITUDE = 1.63
const MAX_ARCS = 60
// 地图书写口径：3 个航次（3 × (0.95s + 0.22s) ≈ 3.51s）后移除；地球叠加层
// 使用同一寿命，确保两页光流残留时长一致。
const ARC_TTL = 3550

/** 垂直扫描 shader（参考实现移植）：纬度带自北极向南极往返扫掠。 */
const FRESNEL_VS = `
varying vec3 vN; varying vec3 vV; varying vec3 vP;
void main(){
  vN = normalize(normalMatrix * normal);
  vec4 mv = modelViewMatrix * vec4(position, 1.0);
  vV = normalize(-mv.xyz);
  vP = position;
  gl_Position = projectionMatrix * mv;
}`
const SCAN_FS = `
uniform vec3 uColor; uniform float uTime, uR;
varying vec3 vN; varying vec3 vV; varying vec3 vP;
void main(){
  float y = vP.y / uR;
  float c = sin(uTime * 0.32) * 1.05;
  float band = 1.0 - smoothstep(0.0, 0.035, abs(y - c));
  float tail = (1.0 - smoothstep(0.0, 0.28, abs(y - c))) * 0.18;
  float facing = max(dot(vN, vV), 0.0);
  gl_FragColor = vec4(uColor, (band * 0.32 + tail * 0.7) * (0.3 + 0.7 * facing));
}`

/** 国家板块跨度（度）→ 相机高度：大国产远、小国产近，钳制 0.55-2.2。 */
function flyAltitudeFor(name: string): number {
  const c = THREAT_COUNTRIES.find((x) => x.name === name)
  if (!c) return 1.4
  let minLat = 90, maxLat = -90, minLon = 180, maxLon = -180
  for (const poly of c.polys) {
    for (const flat of poly) {
      for (let i = 0; i + 1 < flat.length; i += 2) {
        if (flat[i] < minLon) minLon = flat[i]
        if (flat[i] > maxLon) maxLon = flat[i]
        if (flat[i + 1] < minLat) minLat = flat[i + 1]
        if (flat[i + 1] > maxLat) maxLat = flat[i + 1]
      }
    }
  }
  const span = Math.max(maxLat - minLat, Math.min(maxLon - minLon, 180)) / 2
  return Math.min(2.2, Math.max(0.55, span / 45 + 0.35))
}

export function createThreatGlobe(container: HTMLElement, opts?: ThreatSceneOptions): ThreatScene {
  // 历史 历史问题：本站坐标是可变状态——构造期常量会让 setServer 只改
  // 环/点，弧线终点与返回视角仍指向旧坐标（本变量由 setServer/返回视角消费）。
  let server: Centroid = opts?.serverCentroid ?? COUNTRY_CENTROIDS['中国'] ?? [104, 35]
  let siteConfigured = opts?.siteConfigured ?? !!opts?.serverCentroid

  let countryCounts = new Map<string, number>()
  let provinceCounts = new Map<string, number>()
  let drilledName: string | null = null
  // 首帧先出球体/尺寸正确，再在第二帧后构建世界点阵；否则构造期
  // 同步点阵/H3 会挡住 renderer 尺寸更新，canvas 按 window 尺寸停留，
  // 球心偏右 → 「从右侧飘入」。
  let layerReady = false
  // 世界点阵与地图版同源错列网格 + 点内多边形判定；球面步长独立校准。
  // 用单个 THREE.Points 承载，一次 draw call；不再走 H3（res3 首屏 4.4s
  // 主线程长任务，res2 点阵又明显稀疏——两条路都不可接受）。
  // 点阵间距 0.9°：世界/下钻同源错列网格，在观感接近更密网格的同时
  // 保留 60fps 余量，点径与地图版按各自投影分别校准。
  const DOT_STEP = 0.9
  // 与地图共用同一基色（threatShared 单源）。
  const DOT_BASE = DOT_LAND
  // 地图点阵半径随 cam.zoom 放大；球面点径固定屏幕像素会让下钻显得稀。
  // 点阵与 hover 拾取共用 DOT_ALTITUDE 壳层；0.005 的微小抬高避免
  // z-fighting，同时控制球缘视差，不让高亮偏离目标国家。
  const DOT_ALTITUDE = 0.005
  const WORLD_DOT_SIZE = 3.2
  const DRILL_DOT_SIZE = 6.2
  const DRILL_BACKDROP_OPACITY = 0.22
  const DRILL_BACKDROP_COLOR = DOT_LAND
  const DRILL_HOVER_COLOR = '#8fe6ff'
  interface WorldDot { lat: number; lng: number; key: string }
  let worldDots: WorldDot[] | null = null
  let worldDotsByKey = new Map<string, WorldDot[]>()
  let worldDotPositions: Float32Array | null = null
  let activeDots: WorldDot[] | null = null
  let activeCounts = new Map<string, number>()
  const provinceDotCache = new Map<string, { dots: WorldDot[]; positions: Float32Array }>()
  const dotLayerGroup = new THREE.Group()
  let dotsPoints: THREE.Points | null = null
  let backdropDotsPoints: THREE.Points | null = null
  let hoverDotsPoints: THREE.Points | null = null
  let hoveredDotCountry: string | null = null
  // 国家级 bbox 预筛（构造期算一次）：点阵构建 + hover/click 命中测试共用
  // （countryHit）。历史：只给 buildWorldDots 消费，hover/click 对 177 国全量
  // 射线，下钻态每 120ms 复测仍付全表成本。
  const dotBboxes = THREAT_COUNTRIES.map((c) => {
    let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
    for (const poly of c.polys) for (const ring of poly) for (let k = 0; k + 1 < ring.length; k += 2) {
      if (ring[k] < minLon) minLon = ring[k]
      if (ring[k] > maxLon) maxLon = ring[k]
      if (ring[k + 1] < minLat) minLat = ring[k + 1]
      if (ring[k + 1] > maxLat) maxLat = ring[k + 1]
    }
    return { minLon, maxLon, minLat, maxLat }
  })
  const arcs: ArcDatum[] = []
  let disposed = false
  let paused = false
  const onDrillChange = opts?.onDrillChange

  // 构造（v2.3.8）：width/height 默认窗口尺寸（地球右偏）——事后同步容器
  // 实测尺寸（渲染器+相机 aspect 均更新）。库内 hexPolygon 射线拾取在本
  // 组合下不可用（多轮实证：hover/click 永不触发且无错误），交互改为引擎
  // 自研：canvas click → 相机射线 ∩ 球面 → 经纬度（three-globe 球面约定）
  // → 点内多边形判定（ray-casting），数学确定、零依赖库内事件。
  // 两段式构造（v2.3.8 定稿）：自研射线交互不依赖库内拾取，两段式无副作用；
  // animateIn:false 必须经配置传入（new 形态 props 不透传——「右下角飘入」
  // 在 new 形态下持续存在的根因）；width/height 同步容器实测尺寸。
  const initW = Math.max(1, container.clientWidth || Math.floor(container.getBoundingClientRect().width) || 0)
  const initH = Math.max(1, container.clientHeight || Math.floor(container.getBoundingClientRect().height) || 0)
  const globe = (Globe as unknown as (config: Record<string, unknown>) => (el: HTMLElement) => GlobeInstance)({
    rendererConfig: { antialias: true, alpha: true },
    animateIn: false,
  })(container)
  // 构造 config 的 width/height 在此库版本下不可靠（实测首帧仍按 window
  // 1600×1000 建 canvas → 球心偏右，随后 syncSize 才缩回 → 视觉「从右侧
  // 飘入」）。构造后立即显式定尺寸，且 path 层 rendererSize 同源，避免
  // 弧线按窗口尺寸投影。
  globe.width(initW).height(initH)
  ;(globe as unknown as { rendererSize?: (v: unknown) => void }).rendererSize?.(
    new THREE.Vector2(initW, initH),
  )
  // Kapsule 的 width 更新会批到动画帧；H3 构建若在同帧同步发生，canvas
  // 会继续以构造默认 window 尺寸显示一帧以上。这里直接同步 renderer 与
  // scene-container，保证第一帧就是容器尺寸。
  const renderer = (globe as unknown as { renderer?: () => THREE.WebGLRenderer }).renderer?.()
  const threeRenderer: THREE.WebGLRenderer | null = renderer ?? null
  if (renderer) {
    // 客户端 DPR=2 时 canvas 实际 1808×1402，透明度+深度测试点阵 60fps
    // 会让 CPU/GPU 占用明显偏高；上限 1.5 保留清晰度并显著降载。
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5))
    renderer.setSize(initW, initH)
    const sceneEl = container.querySelector('.scene-container') as HTMLElement | null
    if (sceneEl) {
      sceneEl.style.width = `${initW}px`
      sceneEl.style.height = `${initH}px`
    }
    const cam = (globe as unknown as { camera?: () => THREE.PerspectiveCamera }).camera?.()
    if (cam) {
      cam.aspect = initW / initH
      cam.updateProjectionMatrix()
    }
  }


  // ---- 60fps 渲染节流（v2.3.8 用户反馈） ----
  // globe.gl 内部固定用 requestAnimationFrame 自循环，无 FPS 配置项。这里只
  // 拦截其 _animationCycle 回调，保留累计时间预算以便后续降档；其它 RAF
  // （Vue/自研帧循环/hover）原样放行。
  const originalRAF = window.requestAnimationFrame
  const nativeRAF = originalRAF.bind(window)
  // 本实例补丁状态：重叠实例后装者覆盖前装者时，dispose 只在自己仍是栈顶
  // 时恢复；否则标记 inactive，由后续栈顶恢复后经本补丁转发到 prev
  //（历史 历史问题-6，原实现会让补丁永久残留）。
  const rafPatch = { active: true, prev: originalRAF }
  const globeCycle = (globe as unknown as { _animationCycle?: FrameRequestCallback })._animationCycle
  // 60fps 节流：globe.gl 自循环没有 FPS 选项，这里按累计时间预算把它的
  // _animationCycle 限到 60fps（其它 RAF 原样转发）。历史上此处有两档常量
  // （IDLE/ACTIVE 恒等 60fps）与交互时间窗，两档从未分叉——纯脚手架，已删。
  const FRAME_INTERVAL = 1000 / 60
  let lastGlobeFrame = 0
  let frameCredit = 0
  const throttledRAF = (cb: FrameRequestCallback): number => {
    if (!rafPatch.active) return rafPatch.prev(cb)
    if (cb !== globeCycle) return nativeRAF(cb)
    const run = (t: number): void => {
      if (disposed || paused) return
      if (lastGlobeFrame === 0) lastGlobeFrame = t
      const delta = Math.min(100, t - lastGlobeFrame)
      lastGlobeFrame = t
      frameCredit += delta
      if (frameCredit >= FRAME_INTERVAL) {
        frameCredit = Math.min(FRAME_INTERVAL, frameCredit - FRAME_INTERVAL)
        cb(t)
      } else {
        nativeRAF(run)
      }
    }
    return nativeRAF(run)
  }
  window.requestAnimationFrame = throttledRAF

  // 世界/下钻点阵承载层（自定义单 Group，不参与 H3）
  globe
    .customLayerData([])
    .customThreeObject(() => dotLayerGroup)
    .customThreeObjectUpdate(() => { /* 颜色由 updateDotColors 原地更新 */ })

  // 海洋球面基色与地图背景同色（#030a1c），并用 Basic 材质去掉光照加成：
  // 地图点阵透明度/基色是用户认可的口径，球面必须同样让 #1b2a41 点可见。
  const oceanMat = new THREE.MeshBasicMaterial({ color: '#030a1c' })
  globe.globeMaterial(oceanMat)
  globe
    .backgroundColor('rgba(0,0,0,0)')
    .showAtmosphere(true)
    .atmosphereColor('#3ad1ff')
    .atmosphereAltitude(0.16)
    .ringsData(siteConfigured ? [{ lat: server[1], lng: server[0] }] : [])
    .ringLat('lat')
    .ringLng('lng')
    .ringColor(() => (t: number) => `rgba(226,232,240,${Math.max(0, 1 - t)})`)
    .ringMaxRadius(3)
    .ringPropagationSpeed(1.1)
    .ringRepeatPeriod(900)
    .arcsData([])
    // 聚合光流计数标签（世界/下钻共用；无标签时数据为空）
    .labelsData([])
    .labelLat('lat')
    .labelLng('lng')
    .labelText('text')
    .labelSize(0.65)
    .labelColor(() => '#ffd166')
    .labelDotRadius(0)
    .pointsData(siteConfigured ? [{ lat: server[1], lng: server[0], size: 0.45 }] : [])
    .pointLat('lat')
    .pointLng('lng')
    .pointColor((d: object) => ((d as { color?: string }).color) ?? '#e2e8f0')
    .pointAltitude(0.012)
    .pointRadius('size')
    .pointsTransitionDuration(0)

  globe.controls().autoRotate = true
  globe.controls().autoRotateSpeed = 0.45
  // 滚轮不参与缩放（用户裁定：两页面交互一致，缩放仅经下钻/返回）
  globe.controls().enableZoom = false
  globe.pointOfView({ lat: server[1], lng: server[0], altitude: WORLD_ALTITUDE }, 0)

  // ---- 自研拾取：屏幕点 → 相机射线 ∩ 球面 → 经纬度 → 国家/省份 ----
  function screenToLatLng(px: number, py: number): { lat: number; lng: number } | null {
    const cam = globe.camera() as THREE.PerspectiveCamera
    // 用 canvas 自身矩形（而非外层 container）：canvas 是实际渲染/指针目标，
    // 容器若有 padding/偏移会让 hover/点击整体平移。
    const cv = container.querySelector('canvas')
    const r = (cv ?? container).getBoundingClientRect()
    const ndcX = ((px - r.left) / r.width) * 2 - 1
    const ndcY = -(((py - r.top) / r.height) * 2 - 1)
    cam.updateMatrixWorld()
    const dir = cam.getWorldDirection(new THREE.Vector3())
    const right = new THREE.Vector3().crossVectors(dir, cam.up).normalize()
    const up = new THREE.Vector3().crossVectors(right, dir).normalize()
    const origin = new THREE.Vector3().setFromMatrixPosition(cam.matrixWorld)
    // 逆投影纯数学单源（threatProjection.sphereSurfacePoint，WT87-09）：
    // 与点阵同一壳层求交（不是球面），消除高纬/球缘的视差。
    return sphereSurfacePoint(
      {
        origin: [origin.x, origin.y, origin.z],
        dir: [dir.x, dir.y, dir.z],
        right: [right.x, right.y, right.z],
        up: [up.x, up.y, up.z],
        fovHalf: (cam.fov * Math.PI) / 360,
        aspect: cam.aspect,
      },
      ndcX,
      ndcY,
      globe.getGlobeRadius() * (1 + DOT_ALTITUDE),
    )
  }

  
  /**
   * 单帧补绘（WT87-04）：暂停态 `globe.pauseAnimation()` 停掉库自循环后，
   * 同步的相机/图层变更无人渲染。globe.gl 无 manual-render API，这里直接用
   * 已捕获的 renderer 画一帧（与地图引擎 renderOnce 同语义）。
   */
  function renderOnce(): void {
    if (!threeRenderer || disposed) return
    const scene = globe.scene()
    const cam = globe.camera()
    if (scene && cam) threeRenderer.render(scene, cam)
  }

  /** 共享点内判定的批量包装（国家/省多边形组命中）。 */
  function pointInEntries(lon: number, lat: number, entries: { polys: number[][][] }[]): boolean {
    return entries.some((e) => sharedPointInPolys(lon, lat, e.polys))
  }

  let provincePolysCache: { polys: number[][][] }[] = []

  /** 下钻省数据源（中国走内置高精度表；其余取按需加载表，未加载=空）。 */
  function provinceSource(country: string): { name: string; polys: number[][][]; short?: string }[] {
    if (country === '中国') return CHINA_PROVINCES
    return loadedAdmin1Tables()?.[country] ?? []
  }

  let drillSeq = 0

  /** 下钻某国（历史 历史问题：下钻态点击他国与地图版一致=切换下钻）。
   *  无省层数据（含 admin1 chunk 加载失败）时不进入下钻——原实现直接
   *  drilledName+flyTo，省板为空（被选国家成空洞）。 */
  async function drillCountry(name: string): Promise<void> {
    name = normalizeCountryName(name)
    if (!drillCountryAllowed(opts?.drillCountries, name)) return
    const seq = ++drillSeq
    if (name !== '中国') {
      const tables = await loadAdmin1Tables()
      // 历史问题-F5：chunk 加载期间用户退出大屏/复位/返回 → 丢弃结果（判定单源，
      // 与地图引擎共用）。原地球 zoomOut/resetView 不递增 drillSeq，迟到续体
      // 会把用户刚做的复位覆盖成下钻（WT87-03）。
      if (!drillCommitAllowed(seq, drillSeq, disposed)) return
      if (!tables) {
        if (!disposed) opts?.onProvinceLoadError?.()
        return
      }
      if (!tables[name]?.length) return
    }
    drilledName = name
    const c2 = COUNTRY_CENTROIDS[name] ?? FALLBACK_CENTROID
    // 暂停态无动画帧驱动：直接落点并补绘一帧（与地图版 历史问题 同语义）。
    globe.pointOfView({ lat: c2[1], lng: c2[0], altitude: flyAltitudeFor(name) }, paused ? 0 : 700)
    globe.controls().autoRotate = false
    applyLayer()
    if (paused) renderOnce()
    onDrillChange?.(name)
  }

  /** 返回世界视角（空白点击/zoomOut/resetView 共用；暂停态直接落点+补绘）。 */
  function enterWorldView(duration: number): void {
    drilledName = null
    globe.controls().autoRotate = !paused
    globe.pointOfView({ lat: server[1], lng: server[0], altitude: WORLD_ALTITUDE }, paused ? 0 : duration)
    applyLayer()
    if (paused) renderOnce()
  }

  async function handleCanvasClick(ev: MouseEvent): Promise<void> {
    const geo = screenToLatLng(ev.clientX, ev.clientY)
    if (!geo) return
    if (drilledName) {
      // 本省（选中国家内）：保持
      if (pointInEntries(geo.lng, geo.lat, provincePolysCache)) return
    }
    // 命中判定的手势语义与地图版单源（drillClickIntent）：下钻态命中他国=切换
    // （台湾归一后与选择国同名，不得当「其他国家」重复下钻）、空白=返回世界。
    const hit = countryHit(geo.lng, geo.lat, drilledName ?? undefined)
    const intent = drillClickIntent(hit?.name ?? null, drilledName)
    if (intent === 'drill' || intent === 'switch') {
      if (hit) await drillCountry(hit.name)
      return
    }
    if (intent === 'world') {
      drillSeq += 1
      enterWorldView(700)
      onDrillChange?.(null)
    }
  }

  // ---- hover：国家/省 hex 标记重着色 + 悬浮名（与地图版同构：pointermove 只
  // 记坐标，帧内拾取一次——原实现每个 pointermove 事件全量扫描 177 国多边形，
  // 快速移动时同帧多次射线拾取，hover 明显滞后（历史 历史问题）。 ----
  const hoverTipEl = document.createElement('div')
  hoverTipEl.style.cssText = 'position:absolute;z-index:6;pointer-events:none;display:none;padding:5px 10px;background:rgba(4,12,32,.92);border:1px solid rgba(80,170,255,.45);color:#e2ecff;font:12px "Noto Sans SC","PingFang SC",sans-serif;white-space:nowrap;border-radius:2px'
  container.appendChild(hoverTipEl)
  let hoverKeyCache: string | null = null
  let pendingMove: { x: number; y: number } | null = null
  // 自转时指针可能不动而国家从光标下滑过：保留最后指针位置并低频复测，
  // 否则高亮/浮签停在旧国家，视觉上就是「hover 位置错位」。
  let hoverPoint: { x: number; y: number } | null = null
  let lastHoverPick = 0

  /**
   * 国家命中测试（单源，hover/click 共用）：先用点阵构建期的 bbox 预筛，
   * 再对候选国做多边形射线。原实现对 177 国逐个全量射线（俄/美多环最重），
   * 且 bbox 已算好却只给 buildWorldDots 用——下钻态每 120ms 复测都在付全表成本。
   */
  function countryHit(lng: number, lat: number, exclude?: string): { name: string; index: number } | null {
    for (let i = 0; i < THREAT_COUNTRIES.length; i++) {
      const b = dotBboxes[i]
      if (lng < b.minLon || lng > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
      const name = normalizeCountryName(THREAT_COUNTRIES[i].name)
      if (exclude && name === exclude) continue
      if (sharedPointInPolys(lng, lat, THREAT_COUNTRIES[i].polys)) return { name, index: i }
    }
    return null
  }

  function setHexHover(name: string | null): void {
    // 世界态：hover 只改点色（同一 Points 层）。下钻态：省 hover 改省点色，
    // 他国 hover 用独立亮色点阵层；不再绘制/提亮国家多边形色块。
    hoveredDotCountry = name
    updateDotColors()
    updateHoverDots(name)
  }

  /** 帧内 hover 拾取（每帧最多一次）。 */
  function processHover(): void {
    const now = performance.now()
    // 指针不动的复测只为「自转时国家从光标下滑过」服务：下钻/暂停自转后
    // 画面静止，复测不会再改变结果，只会每 120ms 付一次全表拾取成本。
    const autoRotate = globe.controls().autoRotate
    const move = pendingMove ?? (autoRotate && hoverPoint && now - lastHoverPick >= 120 ? hoverPoint : null)
    if (!move) return
    lastHoverPick = now
    pendingMove = null
    const geo = screenToLatLng(move.x, move.y)
    if (!geo) {
      if (hoverKeyCache !== null) {
        hoverKeyCache = null
        hoverTipEl.style.display = 'none'
        setHexHover(null)
      }
      return
    }
    let name: string | null = null
    let count = 0
    let provinceHover = false
    if (drilledName) {
      for (const pv of provinceSource(drilledName)) {
        if (pointInEntries(geo.lng, geo.lat, [{ polys: pv.polys }])) {
          name = 'short' in pv && pv.short ? String(pv.short) : String(pv.name)
          count = provinceCounts.get(name) ?? 0
          provinceHover = true
          break
        }
      }
      if (!name) {
        const other = countryHit(geo.lng, geo.lat, drilledName)
        if (other) { name = other.name; count = countryCounts.get(name) ?? 0 }
      }
    } else {
      const hit = countryHit(geo.lng, geo.lat)
      if (hit) { name = hit.name; count = countryCounts.get(name) ?? 0 }
    }
    if (name !== hoverKeyCache) {
      hoverKeyCache = name
      setHexHover(name)
    }
    if (name) {
      const cv = container.querySelector('canvas')
      const r = (cv ?? container).getBoundingClientRect()
      hoverTipEl.style.display = 'block'
      // WT87-11：省级统计只覆盖中国，海外下钻不得显示「该省 0 次攻击」。
      hoverTipEl.textContent = provinceHover && drilledName && !hasProvinceStats(drilledName)
        ? `${name} 无省级统计`
        : `${name} ${count}`
      hoverTipEl.style.left = `${move.x - r.left + 14}px`
      hoverTipEl.style.top = `${move.y - r.top - 6}px`
    } else {
      hoverTipEl.style.display = 'none'
    }
  }

  function onCanvasMove(ev: PointerEvent): void {
    hoverPoint = { x: ev.clientX, y: ev.clientY }
    pendingMove = { ...hoverPoint }
  }

  function onPointerLeave(): void {
    pendingMove = null
    hoverPoint = null
    hoverKeyCache = null
    hoverTipEl.style.display = 'none'
    setHexHover(null)
  }

  function dotTexture(): THREE.CanvasTexture {
    const canvas = document.createElement('canvas')
    canvas.width = canvas.height = 32
    const ctx = canvas.getContext('2d')
    if (ctx) {
      ctx.fillStyle = '#ffffff'
      ctx.beginPath()
      ctx.arc(16, 16, 14, 0, Math.PI * 2)
      ctx.fill()
    }
    const tex = new THREE.CanvasTexture(canvas)
    tex.needsUpdate = true
    return tex
  }

  const HOVER_DOT_COLOR = new THREE.Color(0.56, 0.9, 1)

  function updateDotColors(): void {
    if (!dotsPoints || !activeDots) return
    const colorAttr = dotsPoints.geometry.getAttribute('color') as THREE.BufferAttribute | undefined
    if (!colorAttr) return
    // 局部缓存：每次计数刷新最多 239 个颜色，函数结束即可回收；旧实现按
    // count 永久缓存 THREE.Color，长时间 30s 轮询会无界增长（慢泄漏）。
    const colorCache = new Map<number, THREE.Color>()
    const colorFor = (count: number): THREE.Color => {
      const cached = colorCache.get(count)
      if (cached) return cached
      const color = new THREE.Color()
      color.setStyle(count > 0 ? heatCss(count) : DOT_BASE)
      colorCache.set(count, color)
      return color
    }
    const arr = colorAttr.array as Float32Array
    for (let i = 0; i < activeDots.length; i++) {
      const d = activeDots[i]
      const c = hoveredDotCountry && d.key === hoveredDotCountry ? HOVER_DOT_COLOR : colorFor(activeCounts.get(d.key) ?? 0)
      arr[i * 3] = c.r
      arr[i * 3 + 1] = c.g
      arr[i * 3 + 2] = c.b
    }
    colorAttr.needsUpdate = true
  }

  function dotPositions(dots: WorldDot[]): Float32Array {
    const positions = new Float32Array(dots.length * 3)
    const v = new THREE.Vector3()
    for (let i = 0; i < dots.length; i++) {
      // 以 DOT_ALTITUDE 微小抬高，避免与球面 z-fighting，又不产生悬浮感。
      v.copy((globe as unknown as { getCoords: (lat: number, lng: number, alt: number) => THREE.Vector3 }).getCoords(dots[i].lat, dots[i].lng, DOT_ALTITUDE))
      positions[i * 3] = v.x
      positions[i * 3 + 1] = v.y
      positions[i * 3 + 2] = v.z
    }
    return positions
  }

  /** 切换当前点阵（世界国家 / 下钻省）：同一 Points 对象换 geometry 属性。 */
  function setActiveDots(dots: WorldDot[], positions: Float32Array, counts: Map<string, number>): void {
    activeDots = dots
    activeCounts = counts
    if (!dotsPoints) return
    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(positions, 3))
    geometry.setAttribute('color', new THREE.BufferAttribute(new Float32Array(dots.length * 3), 3))
    const old = dotsPoints.geometry
    dotsPoints.geometry = geometry
    old.dispose()
    dotsPoints.visible = true
    const pm = dotsPoints.material as THREE.PointsMaterial
    pm.size = drilledName ? DRILL_DOT_SIZE : WORLD_DOT_SIZE
    updateDotColors()
  }

  /** 复用世界点阵几何生成暗度/ hover 层（单次 BufferGeometry，不重建整颗球）。 */
  function setPointPositions(points: THREE.Points, dots: WorldDot[]): void {
    const geometry = new THREE.BufferGeometry()
    geometry.setAttribute('position', new THREE.BufferAttribute(dotPositions(dots), 3))
    const old = points.geometry
    points.geometry = geometry
    old.dispose()
  }

  /** 下钻衬底：非下钻国家显示为 22% 透明度世界点阵（与 2D 地图一致）。 */
  function buildDrillBackdrop(): void {
    if (!backdropDotsPoints || !worldDots) return
    const dots = worldDots.filter((d) => d.key !== drilledName)
    setPointPositions(backdropDotsPoints, dots)
    backdropDotsPoints.visible = !!drilledName && dots.length > 0
  }

  /** 下钻 hover 非下钻国家：只提亮该国点阵，不绘制整块多边形。 */
  function updateHoverDots(name: string | null): void {
    if (!hoverDotsPoints) return
    if (!drilledName || !name || name === drilledName) {
      hoverDotsPoints.visible = false
      return
    }
    const dots = worldDotsByKey.get(name) ?? []
    if (dots.length === 0) {
      hoverDotsPoints.visible = false
      return
    }
    setPointPositions(hoverDotsPoints, dots)
    hoverDotsPoints.visible = true
  }

  /** 世界点阵：与地图版同源错列网格/国家多边形（球面步长独立校准）。 */
  function buildWorldDots(): void {
    if (worldDots) return
    const dots: WorldDot[] = []
    let row = 0
    // 扫描纬度域与地图共用派生常量（DOT_LAT_TOP/BOTTOM），不再各自写死
    // 84/-54.5——改投影域时两引擎点阵覆盖必须同步。
    for (let lat = DOT_LAT_BOTTOM; lat < DOT_LAT_TOP; lat += DOT_STEP, row++) {
      const offset = row % 2 === 1 ? DOT_STEP / 2 : 0
      for (let lon = -179.5 + offset; lon < 180; lon += DOT_STEP) {
        for (let ci = 0; ci < THREAT_COUNTRIES.length; ci++) {
          const b = dotBboxes[ci]
          if (lon < b.minLon || lon > b.maxLon || lat < b.minLat || lat > b.maxLat) continue
          if (!sharedPointInPolys(lon, lat, THREAT_COUNTRIES[ci].polys)) continue
          dots.push({ lat, lng: lon, key: normalizeCountryName(THREAT_COUNTRIES[ci].name) })
          break
        }
      }
    }
    worldDots = dots
    worldDotPositions = dotPositions(dots)
    worldDotsByKey = new Map()
    for (const dot of dots) {
      const list = worldDotsByKey.get(dot.key)
      if (list) list.push(dot)
      else worldDotsByKey.set(dot.key, [dot])
    }
    // 无贴图、非透明、开启深度写入：PointsMaterial 的最轻路径。
    // 圆形/六边形都需要纹理采样 + alphaTest + 透明混合；在 1.3 万点、
    // 60fps 旋转球体上这部分是持续的每帧成本。方形点视觉上仍是点阵，
    // 但 CPU/GPU 明显更低。
    const material = new THREE.PointsMaterial({
      size: WORLD_DOT_SIZE,
      vertexColors: true,
      // 圆形观感：贴图只提供 alpha 轮廓；alphaTest 丢弃轮廓外像素，
      // 保持不透明管线（不做透明混合），成本低于 transparent 圆点。
      map: dotTexture(),
      alphaTest: 0.5,
      transparent: false,
      depthWrite: true,
      sizeAttenuation: false,
    })
    dotsPoints = new THREE.Points(new THREE.BufferGeometry(), material)
    dotsPoints.frustumCulled = false
    dotsPoints.renderOrder = 2
    dotLayerGroup.add(dotsPoints)

    // 下钻衬底：世界点阵降透明度显示；hover 层只含当前悬停国家。
    const backdropMat = new THREE.PointsMaterial({
      size: DRILL_DOT_SIZE,
      color: DRILL_BACKDROP_COLOR,
      transparent: true,
      opacity: DRILL_BACKDROP_OPACITY,
      map: dotTexture(),
      // 低透明度材质不能沿用 0.5 alphaTest：alphaTest 在 opacity 之后判定，
      // 会把 opacity<0.5 的全部点丢弃（本次“非下钻国家不可见”的根因）。
      alphaTest: 0.05,
      depthWrite: false,
      sizeAttenuation: false,
    })
    backdropDotsPoints = new THREE.Points(new THREE.BufferGeometry(), backdropMat)
    backdropDotsPoints.frustumCulled = false
    backdropDotsPoints.renderOrder = 1
    backdropDotsPoints.visible = false
    dotLayerGroup.add(backdropDotsPoints)

    const hoverMat = new THREE.PointsMaterial({
      size: DRILL_DOT_SIZE,
      color: DRILL_HOVER_COLOR,
      transparent: true,
      opacity: 0.9,
      map: dotTexture(),
      alphaTest: 0.5,
      depthWrite: false,
      sizeAttenuation: false,
    })
    hoverDotsPoints = new THREE.Points(new THREE.BufferGeometry(), hoverMat)
    hoverDotsPoints.frustumCulled = false
    hoverDotsPoints.renderOrder = 3
    hoverDotsPoints.visible = false
    dotLayerGroup.add(hoverDotsPoints)

    globe.customLayerData([{ kind: 'world-dots' }])
    setActiveDots(dots, worldDotPositions, countryCounts)
  }

  /** 下钻省点阵：与世界层同错列网格，按 admin 短名染色。 */
  const PROVINCE_DOT_CACHE_MAX = 8
  function ensureProvinceDotSet(country: string): { dots: WorldDot[]; positions: Float32Array } {
    const cached = provinceDotCache.get(country)
    if (cached) {
      // LRU：命中刷新到队尾，避免反复下钻热门国家被淘汰。
      provinceDotCache.delete(country)
      provinceDotCache.set(country, cached)
      return cached
    }
    const source = provinceSource(country)
    let minLon = 180, maxLon = -180, minLat = 90, maxLat = -90
    for (const pv of source) {
      for (const poly of pv.polys) for (const ring of poly) for (let k = 0; k + 1 < ring.length; k += 2) {
        if (ring[k] < minLon) minLon = ring[k]
        if (ring[k] > maxLon) maxLon = ring[k]
        if (ring[k + 1] < minLat) minLat = ring[k + 1]
        if (ring[k + 1] > maxLat) maxLat = ring[k + 1]
      }
    }
    const dots: WorldDot[] = []
    let row = 0
    for (let lat = minLat; lat <= maxLat; lat += DOT_STEP, row++) {
      const offset = row % 2 === 1 ? DOT_STEP / 2 : 0
      for (let lon = minLon + offset; lon <= maxLon; lon += DOT_STEP) {
        for (const pv of source) {
          if (!sharedPointInPolys(lon, lat, pv.polys)) continue
          dots.push({ lat, lng: lon, key: adminShortName(pv.name) })
          break
        }
      }
    }
    const result = { dots, positions: dotPositions(dots) }
    provinceDotCache.set(country, result)
    while (provinceDotCache.size > PROVINCE_DOT_CACHE_MAX) {
      const oldest = provinceDotCache.keys().next().value
      if (oldest === undefined) break
      provinceDotCache.delete(oldest)
    }
    return result
  }

  /** 板块层重建：世界=国家点阵（热力，无陆地着色）；下钻=省点阵 + 他国暗度
   *  点阵衬底（与地图版下钻同视觉）。衬底复用世界点阵几何，不进 H3。 */
  function applyLayer(): void {
    if (!layerReady) return
    if (drilledName) {
      const set = ensureProvinceDotSet(drilledName)
      setActiveDots(set.dots, set.positions, provinceCounts)
      provincePolysCache = provinceSource(drilledName).map((p) => ({ polys: p.polys }))
      buildDrillBackdrop()
    } else {
      if (!worldDots || !worldDotPositions) return
      setActiveDots(worldDots, worldDotPositions, countryCounts)
      provincePolysCache = []
      if (backdropDotsPoints) backdropDotsPoints.visible = false
      if (hoverDotsPoints) hoverDotsPoints.visible = false
    }
    updateHoverDots(hoveredDotCountry)
  }

  // click 处理为 async（按需加载省界）——命名包装器承担 add/removeEventListener
  // 同一引用；void 丢弃 Promise 是刻意的（内部处理全部失败分支）。
  const onCanvasClick = (ev: MouseEvent): void => {
    void handleCanvasClick(ev)
  }
  const cv = container.querySelector('canvas')
  if (cv) {
    cv.addEventListener('click', onCanvasClick)
    cv.addEventListener('pointermove', onCanvasMove)
    cv.addEventListener('pointerleave', onPointerLeave)
  }

  // ---- 光流叠加层（球面曲线 + 地图同款样式） ----
  // 曲线在 spawn 时按球面大圆预计算（buildSphericalArc）；每帧只做零分配
  // 投影并复用一块屏幕坐标标量，不创建逐段对象。3D tube/dash 已退役。
  const FLOW_PARTICLES = 12
  const FLOW_TRAIL_SECONDS = FLOW_FLIGHT_MS / 1000
  const FLOW_GAP_SECONDS = 0.22
  const FLOW_CYCLE_SECONDS = FLOW_TRAIL_SECONDS + FLOW_GAP_SECONDS
  const FLOW_LIFE_SECONDS = 3 * FLOW_CYCLE_SECONDS
  const flowCanvas = document.createElement('canvas')
  flowCanvas.style.cssText =
    'position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:1;'
  container.appendChild(flowCanvas)
  const flowCtx = flowCanvas.getContext('2d')
  let flowW = 0
  let flowH = 0
  let flowDpr = 1
  const flowProjectVec = new THREE.Vector3()
  const flowProjected = { x: 0, y: 0 }
  const flowScreen = new Float32Array(SPHERICAL_ARC_SAMPLES * 2)
  const flowFront = new Uint8Array(SPHERICAL_ARC_SAMPLES)

  const syncFlowSize = (): void => {
    const w = Math.max(1, container.clientWidth || 1)
    const h = Math.max(1, container.clientHeight || 1)
    const dpr = Math.min(window.devicePixelRatio || 1, 2)
    if (w === flowW && h === flowH && dpr === flowDpr) return
    flowW = w
    flowH = h
    flowDpr = dpr
    flowCanvas.width = Math.round(w * dpr)
    flowCanvas.height = Math.round(h * dpr)
  }
  syncFlowSize()

  function easeOutCubic(t: number): number {
    return 1 - Math.pow(1 - Math.min(1, Math.max(0, t)), 3)
  }

  /** xyz 世界坐标 → 屏幕坐标；返回是否在可见半球。
   *  背面点也会写入 flowProjected（供背面淡色弧段使用），调用方按返回值区分。 */
  function projectFlowXyz(x: number, y: number, z: number, cam: THREE.Camera): boolean {
    const len = Math.hypot(x, y, z) || 1
    const nx = x / len
    const ny = y / len
    const nz = z / len
    const front = nx * (cam.position.x - x) + ny * (cam.position.y - y) + nz * (cam.position.z - z) > 0.01
    flowProjectVec.set(x, y, z).project(cam)
    flowProjected.x = ((flowProjectVec.x + 1) * flowW) / 2
    flowProjected.y = ((1 - flowProjectVec.y) * flowH) / 2
    return front
  }

  /** 经纬度 → 屏幕坐标；背面点返回 null。 */
  function projectFlow(lat: number, lng: number): { x: number; y: number } | null {
    const cam = globe.camera()
    const raw = (globe as unknown as { getCoords?: (lat: number, lng: number, alt?: number) => { x: number; y: number; z: number } }).getCoords?.(
      lat,
      lng,
      0.005,
    )
    if (!cam || !raw || !projectFlowXyz(raw.x, raw.y, raw.z, cam)) return null
    return { x: flowProjected.x, y: flowProjected.y }
  }

  function drawFlowOverlay(now: number): void {
    if (!flowCtx) return
    syncFlowSize()
    const ctx = flowCtx
    ctx.setTransform(flowDpr, 0, 0, flowDpr, 0, 0)
    ctx.clearRect(0, 0, flowW, flowH)
    if (!siteConfigured) return
    // 站点转到球背面时不再整层跳过：仍绘制弧线落在可见半球的部分，
    // 否则地球自转几十秒后光流会长期“消失”（地图页不受此影响）。
    const site = projectFlow(server[1], server[0])
    const cam = globe.camera()
    cam.updateMatrixWorld()
    for (const arc of arcs) {
      const elapsed = (now - arc.born) / 1000
      if (elapsed > FLOW_LIFE_SECONDS) continue
      const local = elapsed % FLOW_CYCLE_SECONDS
      if (local >= FLOW_TRAIL_SECONDS) continue
      const curve = arc.curve
      const samples = curve.length / 3
      if (samples < 2) continue
      const head = easeOutCubic(local / FLOW_TRAIL_SECONDS)
      const headIndex = Math.max(1, Math.min(samples - 1, Math.ceil(head * (samples - 1))))
      const alpha = Math.min(1, Math.max(0.05, (FLOW_LIFE_SECONDS - elapsed) / 0.4))
      let firstIndex = -1
      let visibleCount = 0
      let backCount = 0
      const maxSamples = flowScreen.length / 2
      const count = Math.min(headIndex, maxSamples - 1)
      for (let i = 0; i <= count; i++) {
        const o = i * 3
        const front = projectFlowXyz(curve[o], curve[o + 1], curve[o + 2], cam)
        flowFront[i] = front ? 1 : 0
        flowScreen[i * 2] = flowProjected.x
        flowScreen[i * 2 + 1] = flowProjected.y
        if (front) {
          visibleCount++
          if (firstIndex < 0) firstIndex = i
        } else {
          backCount++
        }
      }
      if (visibleCount < 2 && backCount < 2) continue
      if (site && firstIndex >= 0) {
        const dist = Math.hypot(site.x - flowScreen[firstIndex * 2], site.y - flowScreen[firstIndex * 2 + 1])
        if (dist < 2 || dist > Math.max(flowW, flowH) * 1.2) continue
      }
      // 背面淡色弧段：地球自转/来源位于球背面时仍能看到流向；真实 3D 深度
      // 遮挡由低透明度表达，避免光流在背半球完全消失。
      if (backCount >= 2) {
        ctx.beginPath()
        let drawing = false
        for (let i = 0; i <= count; i++) {
          if (flowFront[i]) {
            drawing = false
            continue
          }
          const x = flowScreen[i * 2]
          const y = flowScreen[i * 2 + 1]
          if (drawing) ctx.lineTo(x, y)
          else ctx.moveTo(x, y)
          drawing = true
        }
        ctx.lineWidth = Math.max(1, flowArcWidth(arc.weight) * 0.8)
        ctx.strokeStyle = arc.color
        ctx.globalAlpha = alpha * 0.28
        ctx.stroke()
      }
      ctx.globalAlpha = 1
      // 曲线不能使用「起点→站点」单一线性渐变：球面弧在屏幕上的弯曲会落到
      // 渐变轴起点之外，被 Canvas 钳成透明（历史实测 300ms 后整条消失）。
      // 改为沿弧长分段绘制，段尾透明度按进度递增：尾隐头亮且覆盖全曲线。
      const chunks = Math.min(12, count)
      ctx.lineWidth = flowArcWidth(arc.weight)
      ctx.strokeStyle = arc.color
      for (let c = 0; c < chunks; c++) {
        const fromIdx = Math.floor((count * c) / chunks)
        const toIdx = c === chunks - 1 ? count : Math.floor((count * (c + 1)) / chunks)
        const ratio = toIdx / Math.max(1, count)
        ctx.beginPath()
        let drawing = false
        for (let i = fromIdx; i <= toIdx; i++) {
          if (!flowFront[i]) {
            drawing = false
            continue
          }
          const x = flowScreen[i * 2]
          const y = flowScreen[i * 2 + 1]
          if (drawing) ctx.lineTo(x, y)
          else ctx.moveTo(x, y)
          drawing = true
        }
        ctx.globalAlpha = alpha * (0.05 + 0.95 * ratio)
        ctx.stroke()
      }
      ctx.globalAlpha = 1
      if (arc.label && firstIndex >= 0) {
        ctx.font = '11px ui-monospace, monospace'
        ctx.fillStyle = arc.color
        ctx.textBaseline = 'middle'
        ctx.fillText(arc.label, flowScreen[firstIndex * 2] + 8, flowScreen[firstIndex * 2 + 1] - 8)
      }

      if (head < 1) {
        for (let p = 0; p < FLOW_PARTICLES; p++) {
          const t = Math.max(0, head - p * (0.16 / FLOW_PARTICLES))
          const pos = t * (samples - 1)
          const i0 = Math.min(samples - 1, Math.floor(pos))
          const i1 = Math.min(samples - 1, i0 + 1)
          const frac = pos - i0
          const a0 = i0 * 3
          const a1 = i1 * 3
          const x = curve[a0] + (curve[a1] - curve[a0]) * frac
          const y = curve[a0 + 1] + (curve[a1 + 1] - curve[a0 + 1]) * frac
          const z = curve[a0 + 2] + (curve[a1 + 2] - curve[a0 + 2]) * frac
          if (!projectFlowXyz(x, y, z, cam)) continue
          ctx.beginPath()
          ctx.arc(flowProjected.x, flowProjected.y, 1.8, 0, Math.PI * 2)
          ctx.fillStyle = arc.color
          ctx.globalAlpha = 0.85 * (1 - p / FLOW_PARTICLES)
          ctx.fill()
        }
        ctx.globalAlpha = 1
      }
    }
  }

  // 尺寸重试同步（构造竞态：容器 0×0 时双 RAF 单次尝试会静默失败）
  const syncSize = (): void => {
    const w = container.clientWidth
    const h = container.clientHeight
    if (w > 0 && h > 0 && (globe.width() !== w || globe.height() !== h)) globe.width(w).height(h)
    syncFlowSize()
  }
  let syncTries = 0
  const syncTimer = window.setInterval(() => {
    syncSize()
    syncTries++
    const done = globe.width() === container.clientWidth && container.clientWidth > 0
    if (done || syncTries > 60) clearInterval(syncTimer)
  }, 250)
  window.addEventListener('resize', syncSize)
  // 容器尺寸可能晚于构造稳定（面板/字体/滚动条）；只靠 250ms 轮询且
  // 首次相等即停会漏掉后续回缩，导致 canvas 长期宽于容器、球心偏右。
  const ro = new ResizeObserver(() => syncSize())
  ro.observe(container)

  // 垂直扫描带（移植 shader）+ 帧驱动
  let scanMat: THREE.ShaderMaterial | null = null
  let scanGeo: THREE.SphereGeometry | null = null
  const clock = { t: 0 }
  globe.onGlobeReady(() => {
    if (disposed) return
    const scene = globe.scene()
    if (!scene) return
    const R = 100
    scanMat = new THREE.ShaderMaterial({
      transparent: true,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      uniforms: { uColor: { value: new THREE.Color('#5fe1ff') }, uTime: { value: 0 }, uR: { value: R * 1.012 } },
      vertexShader: FRESNEL_VS,
      fragmentShader: SCAN_FS,
    })
    scanGeo = new THREE.SphereGeometry(R * 1.012, 96, 64)
    const scan = new THREE.Mesh(scanGeo, scanMat)
    // 扫描壳包在板块层之外，必须退出射线检测——否则吞掉国家点击
    scan.raycast = () => {}
    scan.scale.setScalar(globe.getGlobeRadius() / R)
    scene.add(scan)
  })

  // 调试句柄（与地图版 __threatScene 同位约定；无功能依赖）
  ;(window as unknown as Record<string, unknown>).__threatGlobe = globe

  let last = performance.now()
  const frame = (): void => {
    if (disposed) return
    rafId = requestAnimationFrame(frame)
    const now = performance.now()
    const dt = now - last
    last = now
    // hover 拾取每帧最多一次（pointermove 只记坐标——历史 历史问题）
    processHover()
    drawFlowOverlay(now)
    if (!paused) {
      clock.t += dt / 1000
      if (scanMat) scanMat.uniforms.uTime.value = clock.t
      // 弧线老化淘汰（队首=最旧；保持其余对象次序稳定，动画相位不重排）
      if (arcs.length > 0 && now - arcs[0].born > ARC_TTL) {
        arcs.shift()
        syncArcLabels()
      }
    }
  }
  // 两个 RAF：第一个让首帧（球体 + 正确尺寸）真正上屏，第二个再建点阵。
  requestAnimationFrame(() => requestAnimationFrame(() => {
    if (disposed) return
    layerReady = true
    buildWorldDots()
    applyHotspots()
    // 无条件应用：两帧内已下钻（中国路径同步完成，drillCountry 不 await）时
    // applyLayer 此前因 !layerReady 早退，而 setCountries/setProvinces 只走
    // 「activeDots 已存在」重着色分支 → 省点阵永不应用（WT87-10）。
    applyLayer()
  }))
  let rafId = requestAnimationFrame(frame)

  /** 仅保留本站点；命中国家不再叠加红色光球——国家热力由点阵染色表达。 */
  function applyHotspots(): void {
    globe.pointsData(siteConfigured ? [{ lat: server[1], lng: server[0], size: 0.45, color: '#e2e8f0' }] : [])
  }

  function syncArcLabels(): void {
    globe.labelsData(
      arcs
        .filter((a) => a.label)
        .map((a) => ({ lat: a.startLat, lng: a.startLng, text: a.label })),
    )
  }

  function spawnArc(from: Centroid, normal: boolean, weight = 1): void {
    if (!siteConfigured) return
    // 正常/攻击共用容量：满池时拒绝新弧线，已开始的动画按 TTL 完整播完。
    if (arcs.length >= MAX_ARCS) return
    arcs.push({
      ...arcEndpoints(server, from),
      color: normal ? FLOW_NORMAL_COLOR : FLOW_ATTACK_COLOR,
      weight,
      label: flowArcLabel(weight),
      born: performance.now(),
      curve: buildSphericalArc(from[1], from[0], server[1], server[0], globe.getGlobeRadius(), SPHERICAL_ARC_SAMPLES),
    })
    syncArcLabels()
  }

  return {
    addArcForLocation(ipLocation: string, weight = 1): void {
      if (!ipLocation) return
      spawnArc(arcOriginForLocation(ipLocation), false, weight)
    },
    addNormalArcForLocation(ipLocation: string, weight = 1): void {
      if (!ipLocation) return
      spawnArc(arcOriginForLocation(ipLocation), true, weight)
    },
    setCountries(entries: CountryHeat[]): void {
      const nextCounts = aggregateCountryCounts(entries)
      if (heatEntriesEqual(countryCounts, [...nextCounts].map(([name, count]) => ({ name, count })))) return
      countryCounts = nextCounts
      applyHotspots()
      if (!drilledName) {
        // 计数变化不改点集/位置：已建层只重算颜色，避免 30s 轮询重建
        // 1.3 万点 geometry（历史 历史问题-2）。首帧仍需建层。
        if (!activeDots) {
          applyLayer()
        } else {
          activeCounts = countryCounts
          updateDotColors()
        }
      }
      // 暂停态库自循环已停：数据到达必须补绘一帧，否则点色停在暂停帧
      // （与地图引擎 setCountries 同口径）。
      if (paused) renderOnce()
    },
    setProvinces(entries: CountryHeat[]): void {
      if (heatEntriesEqual(provinceCounts, entries)) return
      provinceCounts = new Map(entries.map((e) => [e.name, e.count]))
      if (drilledName) {
        activeCounts = provinceCounts
        updateDotColors()
      }
      if (paused) renderOnce()
    },
    setTraffic(entries: CountryHeat[]): void {
      // 正常/攻击共用出弧计划：>10 聚合、≤10 逐条、单轮预算一致。
      const plan = planFlowArcs(entries.filter((e) => e.count > 0).map((e) => ({ key: e.name, count: e.count })))
      for (const item of plan) {
        spawnArc(COUNTRY_CENTROIDS[item.key] ?? FALLBACK_CENTROID, true, item.count)
      }
    },
    setServer(centroid: Centroid | null): void {
      if (!centroid) return
      // 历史 历史问题：状态化本站坐标——热光点、弧线终点（spawnArc 每次
      // 读 server）、返回世界视角（zoomOut/resetView）随之更新；原实现只改
      // 环/点数据，server 常量让后续弧线仍飞向旧坐标。
      server = [centroid[0], centroid[1]]
      siteConfigured = true
      globe.ringsData([{ lat: server[1], lng: server[0] }])
      applyHotspots()
      // 本站坐标到达即定位：不播放 600ms 相机动画——/config 晚于 4s 兜底
      // 装载时，动画会让自动旋转中的地球明显「往回转一下」。
      if (!drilledName) globe.pointOfView({ lat: server[1], lng: server[0], altitude: WORLD_ALTITUDE }, 0)
      // 暂停态无自循环：信标/环数据变更同样要补绘（首帧 paused 装载时
      // 否则一直看不到本站信标）。
      if (paused) renderOnce()
    },
    zoomOut(): void {
      // WT87-03：与地图版同源——复位/返回必须作废在途省界加载，否则迟到的
      // chunk 续体会把用户刚做的复位覆盖成下钻。
      drillSeq += 1
      enterWorldView(600)
    },
    resetView(): void {
      drillSeq += 1
      enterWorldView(600)
    },
    cameraState(): { zoom: number; cx: number; cy: number; dist: number; pos: [number, number, number] } {
      const pov = globe.pointOfView()
      return { zoom: 1, cx: pov.lng, cy: pov.lat, dist: pov.altitude, pos: [pov.lng, 1, pov.lat] }
    },
    setPaused(p: boolean): void {
      paused = p
      globe.controls().autoRotate = !p && !drilledName
      if (p) {
        // 真暂停：停掉库渲染循环与自有 rAF，后台页/暂停键不再烧 GPU。
        cancelAnimationFrame(rafId)
        rafId = 0
        globe.pauseAnimation()
      } else if (!disposed && rafId === 0) {
        last = performance.now()
        lastGlobeFrame = 0
        frameCredit = 0
        rafId = requestAnimationFrame(frame)
        globe.resumeAnimation()
      }
    },
    dispose(): void {
      disposed = true
      // 历史问题-F5：作废在途省界加载（下钻续体在 await 后检查 disposed，双保险）
      drillSeq += 1
      rafPatch.active = false
      if (window.requestAnimationFrame === throttledRAF) window.requestAnimationFrame = rafPatch.prev
      window.removeEventListener('resize', syncSize)
      ro.disconnect()
      clearInterval(syncTimer)
      const cvd = container.querySelector('canvas')
      if (cvd) {
        cvd.removeEventListener('click', onCanvasClick)
        cvd.removeEventListener('pointermove', onCanvasMove)
        cvd.removeEventListener('pointerleave', onPointerLeave)
      }
      flowCanvas.remove()
      cancelAnimationFrame(rafId)
      globe.pauseAnimation()
      globe.arcsData([])
      globe.labelsData([])
      globe.ringsData([])
      globe.pointsData([])
      for (const points of [dotsPoints, backdropDotsPoints, hoverDotsPoints]) {
        if (!points) continue
        points.geometry.dispose()
        const pointsMaterial = points.material as THREE.PointsMaterial
        // 历史问题-F6：Material.dispose() 不释放贴图——dotTexture 的 CanvasTexture
        // 必须显式释放，否则反复进出大屏累积 Canvas/GPU 资源。
        pointsMaterial.map?.dispose()
        pointsMaterial.dispose()
      }
      dotsPoints = null
      backdropDotsPoints = null
      hoverDotsPoints = null
      dotLayerGroup.clear()
      // 历史问题-F6：海面材质（globe.globeMaterial）随实例销毁释放
      oceanMat.dispose()
      if (scanMat) {
        scanMat.dispose()
        scanMat = null
      }
      if (scanGeo) {
        scanGeo.dispose()
        scanGeo = null
      }
      // WebGL/three 资源释放（历史 历史问题）：原仅清数据 + innerHTML，
      // renderer/几何/纹理驻留 → 反复进出大屏堆内存与 WebGL 上下文持续增长。
      const destructible = globe as unknown as { _destructor?: () => void; renderer?: () => THREE.WebGLRenderer }
      try {
        destructible.renderer?.().dispose()
        destructible.renderer?.().forceContextLoss()
        destructible._destructor?.()
      } catch (error) {
        console.warn('threat globe teardown failed', error)
      }
      delete (window as unknown as Record<string, unknown>).__threatGlobe
      container.innerHTML = ''
    },
  }
}
