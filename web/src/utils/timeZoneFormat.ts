// 配置时区格式化的无依赖单源：date.ts 的 tzFormat/formatInConfigTz
// 内联实现抽出，供页面渲染与 node --test 行为断言共用——date.ts 依赖 auth store
// （走 @ 别名），测试无法加载；本模块零依赖，测试可直接构造格式化器验证 h23 口径。
export const DEFAULT_TZ = 'Asia/Shanghai'

export const createTzFormatter = (timeZone: string, withTime: boolean): Intl.DateTimeFormat =>
  new Intl.DateTimeFormat('en-US', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    // h23：午夜显示 00 点而非 24 点
    ...(withTime ? { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' as const } : {}),
  })

export const formatDateParts = (d: Date, formatter: Intl.DateTimeFormat, withTime: boolean): string => {
  const parts = formatter.formatToParts(d)
  const get = (type: string): string => parts.find((p) => p.type === type)?.value ?? ''
  const date = `${get('year')}-${get('month')}-${get('day')}`
  if (!withTime) return date
  return `${date} ${get('hour')}:${get('minute')}:${get('second')}`
}

// DB 墙钟串（"YYYY-MM-DD HH:mm:ss"，UTC 存储）→ epoch ms。
// 空格分隔格式在 Safari 裸 new Date 返回 NaN——统一替换为显式 UTC ISO 再解析；
// 解析失败返回 null，调用方自行兜底。
//
// 本模块是「DB 墙钟 → epoch」的**唯一内核**：utils/date.ts 的 parseDbTimeMs
// 在它之上叠 ISO 白名单（区分「DB 墙钟串」与「人读文本」），threatFlowRules 的
// flowTimestamp 把 null 映射为 NaN。三者接受集合的差异只有白名单这一层，规范化
// 与解析不得各写一份（历史上三份实现已漂移）。

/** DB 墙钟串 → 显式 UTC 的 ISO 串（其余形态原样返回）。 */
export const normalizeDbWallClock = (value: string): string =>
  /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}(:\d{2})?$/.test(value) ? `${value.replace(' ', 'T')}Z` : value

export const parseDbDateMs = (value: string): number | null => {
  const ms = new Date(normalizeDbWallClock(value)).getTime()
  return Number.isNaN(ms) ? null : ms
}
