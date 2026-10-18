export type CertJobStatus =
  | 'queued'
  | 'pending'
  | 'processing'
  | 'creating_account'
  | 'creating_order'
  | 'order_created'
  | 'waiting_order_ready'
  | 'order_ready'
  | 'cleanup_dns'
  | 'cleanup_warning'
  | 'presenting_dns'
  | 'waiting_propagation'
  | 'dns_propagated'
  | 'accepting_challenge'
  | 'waiting_order_valid'
  | 'order_valid'
  | 'validating'
  | 'validated'
  | 'finalizing'
  | 'finalized'
  | 'downloading'
  | 'downloaded'
  | 'issued'
  | 'failed'
  | 'waiting_ca'
  | 'disabled'

export const certJobStatusLabel = (status: CertJobStatus): string => {
  switch (status) {
    case 'issued': return '已签发'
    case 'failed': return '失败'
    case 'disabled': return '已禁用'
    case 'queued': return '排队中'
    case 'waiting_ca': return '限流中'
    case 'pending': return '待处理'
    case 'processing': return '处理中'
    case 'creating_account': return '创建账户'
    case 'creating_order': return '创建订单'
    case 'order_created': return '建单完成'
    case 'waiting_order_ready': return '等待就绪'
    case 'order_ready': return '订单就绪'
    case 'cleanup_dns': return '清理中'
    case 'cleanup_warning': return '清理警告'
    case 'presenting_dns': return '配置解析'
    case 'waiting_propagation': return '等待传播'
    case 'dns_propagated': return '已传播'
    case 'accepting_challenge': return '提交验证'
    case 'waiting_order_valid': return '等待验证'
    case 'order_valid': return '验证完成'
    case 'validating': return '验证中'
    case 'validated': return '验证通过'
    case 'finalizing': return '最终化'
    case 'finalized': return '订单完成'
    case 'downloading': return '下载证书'
    case 'downloaded': return '下载完成'
    default:
      // 空值/undefined 静默回退（存量行 status 空列的瞬时形态，非异常——
      // 控制台噪音「Unknown cert job status: undefined」治理，2026-10-11）；
      // 非空未知值仍 warn 暴露真实状态机漂移。
      if (!status) return '未知'
      console.warn('Unknown cert job status:', status)
      return String(status)
  }
}

/** 证书任务状态 → Element tag 色调（与 certJobStatusLabel 同一状态机）。 */
export const certJobStatusTone = (status: CertJobStatus): 'success' | 'danger' | 'warning' | 'info' => {
  if (!status) return 'info'
  switch (status) {
    case 'issued': return 'success'
    case 'failed': return 'danger'
    case 'disabled': return 'info'
    case 'queued': return 'info'
    case 'waiting_ca': return 'warning'
    case 'pending':
    case 'processing':
    case 'creating_account':
    case 'creating_order':
    case 'order_created':
    case 'waiting_order_ready':
    case 'order_ready':
    case 'cleanup_dns':
    case 'cleanup_warning':
    case 'presenting_dns':
    case 'waiting_propagation':
    case 'dns_propagated':
    case 'accepting_challenge':
    case 'waiting_order_valid':
    case 'order_valid':
    case 'validating':
    case 'validated':
    case 'finalizing':
    case 'finalized':
    case 'downloading':
    case 'downloaded':
      return 'warning'
    default:
      console.warn('Unknown cert job status:', status)
      return 'info'
  }
}

/** 证书任务重试冷却（分钟）；null=不可重试。 */
export const certJobRetryCooldown = (status: CertJobStatus): number | null => {
  if (!status) return 2
  switch (status) {
    case 'disabled': return null
    case 'issued':
    case 'waiting_ca':
      return 0
    case 'queued': return 15
    case 'failed': return 5
    default:
      return 2
  }
}
