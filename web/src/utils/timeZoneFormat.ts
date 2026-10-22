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

// 紧凑时间（MM-DD HH:mm）：多列表格里时间列按此压缩，段取值仍来自同一 formatter
// （withTime 形态，h23 口径），不另造第二套时区来源。
export const formatCompactDateParts = (d: Date, formatter: Intl.DateTimeFormat): string => {
  const parts = formatter.formatToParts(d)
  const get = (type: string): string => parts.find((p) => p.type === type)?.value ?? ''
  return `${get('month')}-${get('day')} ${get('hour')}:${get('minute')}`
}

export const formatDateInTz = (d: Date, timeZone: string, withTime = true): string =>
  formatDateParts(d, createTzFormatter(timeZone, withTime), withTime)
