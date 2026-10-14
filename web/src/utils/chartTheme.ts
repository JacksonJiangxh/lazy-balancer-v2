// 共享 ECharts 主题（v2.3.4 任务监控引入；Dashboard/SecurityOverview 同源取色）
// ——统一语义色单一来源，避免多页各持一套色值漂移。

const chartPalette = {
  primary: '#4f8cff',
  violet: '#8b5cf6',
  amber: '#fbbf24',
  red: '#f87171',
  slate: '#9aa0b5',
  dim: '#62687f',
} as const

/** 状态 → 色（任务监控/安全总览共用语义色）——键=TaskStatus 实际产出值
 * （running/idle/queued/failed/disabled；B1-3 历史清理：cancelled/stopped
 * 为零产出死键——方案 A 后 stopped 已退役、cancelled 仅存在于 task_runs
 * result 字段非状态列；passive/no_runs 曾为零产出死条目，历史问题-08 清理） */
export const statusColor: Record<string, string> = {
  running: chartPalette.primary,
  idle: chartPalette.slate,
  queued: chartPalette.amber,
  failed: chartPalette.red,
  disabled: chartPalette.dim,
}

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
