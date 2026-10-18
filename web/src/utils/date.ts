import { useAuthStore } from '@/stores/auth'
// 与后端 COALESCE 默认一致的兜底时区与格式化器单源（历史问题-F11）：抽到无依赖
// 模块供 node 行为测试直测 h23 口径；本文件保留缓存/回退策略。
import { DEFAULT_TZ, createTzFormatter, formatDateParts } from '@/utils/timeZoneFormat'

let warnedInvalidTz = false

const configTz = (): string => {
  try {
    return useAuthStore().timezone || DEFAULT_TZ
  } catch {
    return DEFAULT_TZ
  }
}

// 时间筛选口径：el-date-picker 以 value-format="YYYY-MM-DD HH:mm:ss" 产出的墙钟字符串按
// 「浏览器本地时区」生成（element-plus 无 timezone 配置项），后端按「配置时区」解析
// （auditlog.go / security.go 的 parseBoundary → ParseInLocation(configTz) 转 UTC 比较）。
// 仅当浏览器时区 == 配置时区（典型同机房部署）时与展示侧 formatInConfigTz 口径一致；
// 管理员跨时区访问时筛选边界存在系统性偏移（已知限制），根治需改为 RFC3339 传参并同步后端解析契约。

const isIsoLike = (value: string): boolean => value.includes('T') || value.endsWith('Z') || /[+-]\d{2}:?\d{2}$/.test(value)

// 模块级 formatter 缓存（S-01）：Dashboard 每轮询对 60 点 × 2 图表调用 tzFormatter，
// 每 5s 约构造 120 个 Intl.DateTimeFormat（Intl 构造带 locale 数据解析，纯函数重复计算）。
// key = `${tz}|${withTime}`；只缓存成功构造的实例，非法 tz 回退路径不受影响（回退后同样走缓存）。
const tzFormatterCache = new Map<string, Intl.DateTimeFormat>()

// 共享的受保护格式化器（D-1）：非法配置时区使 Intl 构造抛 RangeError 时回退 DEFAULT_TZ，
// warnedInvalidTz 防止 warn 刷屏。所有 tz 格式化调用点必须经此入口，不得直接 new Intl.DateTimeFormat。
const tzFormatter = (withTime: boolean): Intl.DateTimeFormat => {
  const tz = configTz()
  const cacheKey = `${tz}|${withTime}`
  const cached = tzFormatterCache.get(cacheKey)
  if (cached) return cached
  try {
    const formatter = createTzFormatter(tz, withTime)
    tzFormatterCache.set(cacheKey, formatter)
    return formatter
  } catch {
    if (!warnedInvalidTz) {
      warnedInvalidTz = true
      console.warn(`[date] 无效的配置时区「${tz}」，已回退为「${DEFAULT_TZ}」`)
    }
    // 回退后同样走缓存：避免每次调用都重建 DEFAULT_TZ 实例（S-01）
    const fallbackKey = `${DEFAULT_TZ}|${withTime}`
    const fallback = tzFormatterCache.get(fallbackKey) ?? createTzFormatter(DEFAULT_TZ, withTime)
    tzFormatterCache.set(fallbackKey, fallback)
    // 非法键同样缓存回退实例（D-3）：后续调用命中缓存，不再重复构造/抛 RangeError
    tzFormatterCache.set(cacheKey, fallback)
    return fallback
  }
}

const formatInConfigTz = (d: Date, withTime: boolean): string =>
  formatDateParts(d, tzFormatter(withTime), withTime)

const isRecord = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null

const parseDateValue = (date: unknown): Date | null => {
  if (!date) return null
  // 后端契约统一为 *string / JSONNullTime（RFC3339 字符串或 null），无 sql.Null* 包装对象；
  // 对未知对象形状保持宽容防御，一律按空处理（历史问题 S-1）
  if (isRecord(date) || typeof date !== 'string') return null
  // DB datetimes ("2026-08-11 08:23:21") are stored in UTC; normalize to explicit UTC ISO
  const normalized = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(date) ? date.replace(' ', 'T') + 'Z' : date
  if (!isIsoLike(normalized)) return null
  const d = new Date(normalized)
  return isNaN(d.getTime()) ? null : d
}

export const formatDate = (date: unknown): string => {
  const d = parseDateValue(date)
  if (d) return formatInConfigTz(d, true)
  if (typeof date === 'string' && date) return date
  return ''
}

export const formatDateShort = (date: unknown): string => {
  const d = parseDateValue(date)
  if (d) return formatInConfigTz(d, false)
  if (typeof date === 'string' && date) return date
  return ''
}

// FE-70-5（历史）：DB 墙钟串（"YYYY-MM-DD HH:mm:ss"，UTC 存储）→ epoch ms。
// 必须经 parseDateValue 的 +Z 规范化——裸 new Date 对空格分隔格式在 Safari 返回
// NaN（排序比较恒为 0 退化）；解析失败返回 null，调用方自行兜底。
export const parseDbTimeMs = (date: unknown): number | null => {
  const d = parseDateValue(date)
  return d ? d.getTime() : null
}

// Dashboard 图表轴标签（HH:mm:ss），经 tzFormatter 受保护入口（BUG-01）：
// 非法配置时区回退 DEFAULT_TZ，不再在 ECharts computed 中抛 RangeError。
export const formatChartTimeInConfigTz = (ms: number): string => {
  const parts = tzFormatter(true).formatToParts(new Date(ms))
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? ''
  return `${get('hour')}:${get('minute')}:${get('second')}`
}
