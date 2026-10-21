// 安全规则库展示单源（历史问题）：SecurityRules 与 SecurityOverview 此前各自
// 实现「状态标签/色调 + 多源聚合」，且已漂移（同为空 source 列表，规则集页
// 落 idle 显示「已最新」，总览页返回 '' 不显示标签）。本模块统一：
// - libraryStatusLabel / libraryStatusTagType：状态 → 文案/色调
// - summarizeLibrarySources：威胁情报库/爬虫地址库多源聚合（版本取最近、
//   条目求和、状态=更新中>失败>成功>未更新）
// - libraryHealthTag / librarySourceHealthTag：卡头健康标签
// 状态词表：missing=文件缺失（danger）、not-installed=库未安装（info）、
// never=从未更新（info）、cancelled=已取消（info）、failed/running/checking/
// downloading/installing/reloading/success/idle 与后端 update_status 同词。
import { compareVersion } from './securityStages.ts'

export type LibraryTagType = 'success' | 'warning' | 'danger' | 'info'

const STATUS_LABELS: Record<string, string> = {
  missing: '缺失',
  'not-installed': '未安装',
  never: '未更新',
  failed: '更新失败',
  running: '更新中',
  checking: '检查中',
  downloading: '下载中',
  installing: '安装中',
  reloading: '重载中',
  success: '已最新',
  idle: '已最新',
  cancelled: '已取消',
  disabled: '已关闭',
}

export const libraryStatusLabel = (status: string): string =>
  STATUS_LABELS[status] ?? status ?? ''

export const libraryStatusTagType = (status: string): LibraryTagType => {
  if (!status) return 'info'
  if (status === 'missing' || status === 'failed' || status.includes('失败') || status.includes('错误')) return 'danger'
  if (status === 'not-installed' || status === 'never' || status === 'disabled') return 'info'
  // 历史问题-01 同族收敛：cancelled 是后端的持久状态（四类库均会写），原词表漏映射
  // 会让状态列直接显示英文原词——中立 info，不冒充失败/成功。
  if (status === 'cancelled') return 'info'
  if (status === 'checking' || status === 'downloading' || status === 'installing' || status === 'reloading' || status === 'running') return 'warning'
  if (status === 'success' || status === 'idle' || status.includes('最新')) return 'success'
  if (status.includes('中')) return 'warning'
  return 'info'
}

export interface LibrarySourceRow {
  readonly version?: string
  readonly update_status?: string
  readonly update_enabled?: boolean
  readonly entry_count?: number
  readonly last_checked?: string
  readonly next_update?: string
}

export interface LibrarySummary {
  readonly latestVersion: string
  readonly totalEntries: number
  readonly status: 'running' | 'failed' | 'success' | 'never' | 'disabled'
  readonly lastChecked: string
  readonly nextUpdate: string
}

/**
 * 多源规则库聚合（威胁情报库/爬虫地址库共用）：
 * - latestVersion = 各源 version 最大值（compareVersion，日期/semver 通用）；
 * - totalEntries = 各源 entry_count 之和；
 * - status = 任一更新中 > 任一失败 > 有版本=success > never（空源/无版本）。
 *   「从未更新」独立成 never，不折叠为 idle/「已最新」——原两页对空列表的
 *   结论互相矛盾（历史问题）。
 * formatDate 注入（缺省原样）避免本模块依赖 auth store，供 node 测试直测。
 */
export const summarizeLibrarySources = (
  sources: readonly LibrarySourceRow[],
  formatDate: (value?: string) => string = (value) => value || '',
): LibrarySummary => {
  // 已关闭源不参与任务状态聚合：关闭前的 failed 是历史态，继续计入会让
  // 库头持续显示「N 源更新失败」，而该源实际已不在任何更新任务内。
  const active = sources.filter((s) => s.update_enabled !== false)
  const anyRunning = active.some((s) => s.update_status === 'running')
  const anyFailed = !anyRunning && active.some((s) => s.update_status === 'failed')
  const latestVersion = sources.map((s) => s.version).filter((v): v is string => !!v).sort(compareVersion).pop() || ''
  const totalEntries = sources.reduce((sum, s) => sum + (s.entry_count || 0), 0)
  // 上次更新取最晚、下次更新取最早（空源 → '—'）；下次排程只看启用源。
  const lastChecked = sources.map((s) => formatDate(s.last_checked)).filter(Boolean).sort().pop() || '—'
  const nextUpdate = active.map((s) => formatDate(s.next_update)).filter(Boolean).sort().shift() || '—'
  return {
    latestVersion,
    totalEntries,
    status: active.length === 0 && sources.length > 0
      ? 'disabled'
      : anyRunning ? 'running' : anyFailed ? 'failed' : latestVersion ? 'success' : 'never',
    lastChecked,
    nextUpdate,
  }
}

export interface LibraryHealthTag {
  readonly label: string
  readonly type: LibraryTagType
}

/**
 * 单库（CRS/IP 地理库）健康标签：加载失败/文件缺失 → danger；库未安装
 * （版本未知/空）→ warning，不得再显示「正常」（历史问题 自相矛盾态）。
 * loaded=false（首次响应未落地）→ 「加载中」（历史修复：初值 available:true
 * 不得冒充正常态）；缺省 true，既有调用方口径不变。
 */
export const libraryHealthTag = (
  name: string,
  state: { loadError: boolean; available?: boolean; status?: string; loaded?: boolean },
): LibraryHealthTag => {
  if (state.loaded === false) return { label: `${name} · 加载中`, type: 'info' }
  if (state.loadError) return { label: `${name} · 加载失败`, type: 'danger' }
  if (state.available === false) return { label: `${name} · 缺失`, type: 'danger' }
  if (state.status === 'not-installed') return { label: `${name} · 未安装`, type: 'warning' }
  if (state.status === 'never') return { label: `${name} · 未更新`, type: 'warning' }
  // 历史问题-01：持久 update_status 的失败/进行中/关闭态必须显性——该列可为
  // failed（更新失败落库），活动期还会 overlay checking/downloading/installing/
  // reloading/running。此前一律落「正常」，与同卡状态列（libraryStatusTagType）
  // 的「更新失败/更新中」自相矛盾（历史问题 同族）。词表复用状态列单源。
  const status = state.status ?? ''
  if (status !== '' && status !== 'success' && status !== 'idle') {
    return { label: `${name} · ${libraryStatusLabel(status)}`, type: libraryStatusTagType(status) }
  }
  return { label: `${name} · 正常`, type: 'success' }
}

/** 多源库（威胁情报库/爬虫地址库）健康标签：更新中/部分失败为 warning；
 *  loaded=false（首次响应未落地）→ 「加载中」（历史修复，缺省 true）。 */
export const librarySourceHealthTag = (
  name: string,
  sources: readonly LibrarySourceRow[],
  loadError: boolean,
  loaded = true,
): LibraryHealthTag => {
  if (!loaded) return { label: `${name} · 加载中`, type: 'info' }
  if (loadError) return { label: `${name} · 加载失败`, type: 'danger' }
  if (sources.length === 0) return { label: `${name} · 未配置`, type: 'warning' }
  const active = sources.filter((s) => s.update_enabled !== false)
  if (active.length === 0) return { label: `${name} · 已关闭`, type: 'info' }
  if (active.some((s) => s.update_status === 'running')) return { label: `${name} · 更新中`, type: 'warning' }
  const failed = active.filter((s) => s.update_status === 'failed').length
  if (failed > 0) return { label: `${name} · ${failed} 源更新失败`, type: 'warning' }
  return { label: `${name} · 正常`, type: 'success' }
}

/**
 * CRS 规则库「数量」列文案（历史修复）：后端 `rule_count` 是 SecRule
 * 指令条数（internal/services/crsrelease.go countSecRules 只数 SecRule 行）——
 * 写「条规则」而不是「个文件」，否则 832 条规则会被读成 832 个文件。
 * 读取失败由调用方先行置 '—'；0/缺省同样 '—'（0 条不等于「库已就绪」）。
 */
export const crsRuleCountLabel = (ruleCount: number | undefined): string =>
  ruleCount && ruleCount > 0 ? `${ruleCount.toLocaleString()} 条规则` : '—'

/**
 * 规则库「定时更新」保存前校验（历史问题）：返回错误文案，合法时 null。
 * 时间被清空时原实现静默回落 04:00——输入框显示空、落库却是 04:00，用户看不到
 * 差异。改为显式拒绝保存（不代填），由组件以 warning 呈现。
 */
export const libraryScheduleError = (days: readonly number[], time: string | null | undefined): string | null => {
  if (days.length === 0) return '至少选择一天'
  if (!time) return '请选择时间'
  return null
}
