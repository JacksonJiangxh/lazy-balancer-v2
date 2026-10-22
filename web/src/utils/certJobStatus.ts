// 相对路径 + .ts 扩展名：本模块被 node --test 直接加载（无打包器别名解析）。
import { parseDbDateMs } from './timeZoneFormat.ts'

// 状态联合类型的唯一事实源在 types/index.ts（证书任务视图类型族同源处）；
// 此处 re-export 保持既有 `@/utils/certJobStatus` 导入面不变。
import type { CertJobStatus } from '../types/index.ts'
export type { CertJobStatus }

/**
 * 状态 → 中文标签全表。`satisfies Record<CertJobStatus, string>` 是**编译期穷尽性**
 * 约束：后端 db.certJobStatuses 新增一态后，此处不补文案即 tsc 报错（原先 switch
 * 缺 case 只会静默落 unknown 分支，标签显示原始 token）。
 */
const CERT_JOB_STATUS_LABELS = {
  issued: '已签发',
  failed: '失败',
  disabled: '已禁用',
  queued: '排队中',
  waiting_ca: '限流中',
  pending: '待处理',
  processing: '处理中',
  creating_account: '创建账户',
  creating_order: '创建订单',
  order_created: '建单完成',
  waiting_order_ready: '等待就绪',
  order_ready: '订单就绪',
  cleanup_dns: '清理中',
  cleanup_warning: '清理警告',
  presenting_dns: '配置解析',
  waiting_propagation: '等待传播',
  dns_propagated: '已传播',
  accepting_challenge: '提交验证',
  waiting_order_valid: '等待验证',
  order_valid: '验证完成',
  validating: '验证中',
  validated: '验证通过',
  finalizing: '最终化',
  finalized: '订单完成',
  downloading: '下载证书',
  downloaded: '下载完成',
} satisfies Record<CertJobStatus, string>

export const certJobStatusLabel = (status: CertJobStatus): string => {
  // 空值/undefined 静默回退（存量行 status 空列的瞬时形态，非异常——
  // 控制台噪音「Unknown cert job status: undefined」治理，2026-10-11）；
  // 非空未知值仍 warn 暴露真实状态机漂移。
  if (!status) return '未知'
  const label = CERT_JOB_STATUS_LABELS[status] as string | undefined
  if (label) return label
  console.warn('Unknown cert job status:', status)
  return String(status)
}

/** 证书任务状态色调（与 certJobStatusLabel 同一状态机）。 */
export type CertJobStatusTone = 'success' | 'danger' | 'warning' | 'info'

/** 状态 → Element tag 色调全表（同样受 `satisfies Record<CertJobStatus, …>` 穷尽性约束）。 */
const CERT_JOB_STATUS_TONES = {
  issued: 'success',
  failed: 'danger',
  disabled: 'info',
  queued: 'info',
  waiting_ca: 'warning',
  pending: 'warning',
  processing: 'warning',
  creating_account: 'warning',
  creating_order: 'warning',
  order_created: 'warning',
  waiting_order_ready: 'warning',
  order_ready: 'warning',
  cleanup_dns: 'warning',
  cleanup_warning: 'warning',
  presenting_dns: 'warning',
  waiting_propagation: 'warning',
  dns_propagated: 'warning',
  accepting_challenge: 'warning',
  waiting_order_valid: 'warning',
  order_valid: 'warning',
  validating: 'warning',
  validated: 'warning',
  finalizing: 'warning',
  finalized: 'warning',
  downloading: 'warning',
  downloaded: 'warning',
} satisfies Record<CertJobStatus, CertJobStatusTone>

export const certJobStatusTone = (status: CertJobStatus): CertJobStatusTone => {
  if (!status) return 'info'
  const tone = CERT_JOB_STATUS_TONES[status] as CertJobStatusTone | undefined
  if (tone) return tone
  console.warn('Unknown cert job status:', status)
  return 'info'
}

/**
 * 证书任务是否已过后端下发的重试冷却。冷却时长唯一由 API 决定；
 * 缺失/畸形时间戳维持原有 fail-open 行为，最终仍以后端重试门为准。
 */
export const certJobRetryReady = (
  cooldownSeconds: number | null,
  updatedAtValue: string | null | undefined,
  nowMs = Date.now(),
): boolean => {
  if (cooldownSeconds === null) return false
  if (cooldownSeconds <= 0 || !updatedAtValue) return true
  // 经 parseDbDateMs 的 +Z 规范化——裸 new Date 对空格分隔墙钟串在 Safari 返回 NaN，
  // 冷却判定会恒 true（fail-open 提前允许重试）。
  const updatedAt = parseDbDateMs(updatedAtValue)
  if (updatedAt === null) return true
  return nowMs - updatedAt >= cooldownSeconds * 1000
}
