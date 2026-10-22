// 采集健康位（后端 services.SecurityEventsIngestionStatus 的镜像）。
// 事件列表 / 安全总览 / 威胁大屏三处同源消费：是否需要提示、提示什么文案
// 只在此处定义，禁止各视图自造判据（口径分叉会让同一后端状态在不同页面
// 呈现不同结论）。字段名与后端 JSON tag 逐字对应。

export interface IngestionHealth {
  observed: boolean
  healthy: boolean
  consecutive_failures: number
  last_error?: string
  last_error_at?: string
  last_success_at?: string
  task_state?: string
  task_running?: boolean
  writer_dropped?: number
  writer_io_errors?: number
  writer_degraded?: boolean
  writer_last_failure_at?: string
  writer_stats_unavailable?: boolean
  data_loss?: boolean
}

/** 统一提示文案（空串 = 不提示）：判据与文案同源，三处视图只调这一个函数。 */
export function ingestionWarningMessage(status?: IngestionHealth | null): string {
  if (!status) return ''
  const needsAttention = status.task_state === 'stopped'
    || status.writer_degraded === true
    || status.writer_stats_unavailable === true
    || status.data_loss === true
    || (status.observed === true && status.healthy === false)
  if (!needsAttention) return ''
  if (status.task_state === 'stopped') {
    return '安全事件采集任务已停止（未在运行），安全事件不再更新；请到「任务监控」检查并启用「安全事件采集」任务。'
  }
  if (status.writer_stats_unavailable === true) {
    return '审计写侧计数不可用（计数侧车连续读取失败）：写侧丢弃/写盘错误计数显示 0 不代表无丢弃；请检查审计日志目录的磁盘空间与写权限。'
  }
  if (status.writer_degraded === true) {
    return `审计日志写侧失败：累计丢弃 ${status.writer_dropped ?? 0} 条、写盘错误 ${status.writer_io_errors ?? 0} 次，安全事件可能缺失；请检查审计日志目录的磁盘空间与写权限。`
  }
  if (status.observed === true && status.healthy === false) {
    const detail = status.last_error ? `：${status.last_error}` : ''
    return `安全事件采集连续失败 ${status.consecutive_failures ?? 0} 次${detail}，事件数据可能滞后；请检查任务日志与审计日志目录。`
  }
  // data_loss 单独成立（当前已恢复但曾丢失）：与「正在失败」文案区分。
  return `此前曾发生安全事件丢失（累计丢弃 ${status.writer_dropped ?? 0} 条、写盘错误 ${status.writer_io_errors ?? 0} 次，当前已恢复）：对应时间窗内的事件可能缺失。`
}
