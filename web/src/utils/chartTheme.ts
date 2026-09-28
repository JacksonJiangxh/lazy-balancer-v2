// 共享 ECharts 主题（v2.3.4 任务监控引入；Dashboard/SecurityOverview 同源取色）
// ——统一色板/轴线/提示层基底，避免三页各持一套色值漂移。

export const chartPalette = {
  primary: '#4f8cff',
  cyan: '#38e1ff',
  violet: '#8b5cf6',
  pink: '#f472b6',
  green: '#34d399',
  amber: '#fbbf24',
  red: '#f87171',
  slate: '#9aa0b5',
  dim: '#62687f',
} as const

/** 分类色环（顺序即取色顺序） */
export const seriesColors: readonly string[] = [
  chartPalette.primary,
  chartPalette.cyan,
  chartPalette.violet,
  chartPalette.pink,
  chartPalette.green,
  chartPalette.amber,
  chartPalette.red,
  chartPalette.slate,
]

/** 状态 → 色（任务监控/安全总览共用语义色） */
export const statusColor: Record<string, string> = {
  running: chartPalette.primary,
  idle: chartPalette.slate,
  queued: chartPalette.amber,
  failed: chartPalette.red,
  cancelled: chartPalette.violet,
  disabled: chartPalette.dim,
  passive: chartPalette.cyan,
  no_runs: chartPalette.slate,
}

/** 通用网格/提示层基底（浅色面板卡片内） */
export const baseGrid = { left: 12, right: 16, top: 36, bottom: 8, containLabel: true } as const

export const baseTooltip = {
  backgroundColor: 'rgba(15, 18, 32, 0.92)',
  borderWidth: 0,
  textStyle: { color: '#e8eaf2', fontSize: 12 },
  extraCssText: 'box-shadow: 0 8px 24px rgba(0,0,0,.35); border-radius: 8px;',
} as const

/** 轴线基底（暗字浅线，适配面板卡片） */
export const baseAxis = {
  axisLine: { lineStyle: { color: '#d7dbe8' } },
  axisLabel: { color: '#6b7280', fontSize: 11 },
  splitLine: { lineStyle: { color: 'rgba(0,0,0,0.05)' } },
} as const

/** HTTP 状态码序列色（Dashboard 流量图既有语义色收编——零视觉变更，单一来源） */
export const httpStatusColors = {
  requests: '#3b82f6',
  s2xx: '#10b981',
  s3xx: '#f59e0b',
  s4xx: '#f97316',
  s5xx: '#ef4444',
  blocked: '#7c3aed',
} as const

/** 安全事件动作色（SecurityOverview 既有语义色收编） */
export const securityActionColors = {
  blocked: '#f56c6c',
  detected: '#e6a23c',
} as const
