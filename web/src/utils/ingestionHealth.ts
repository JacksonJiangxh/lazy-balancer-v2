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
  // 写侧 formatter 契约失败（代码/缺陷方向，与磁盘故障分开披露）。
  writer_format_errors?: number
  writer_degraded?: boolean
  writer_last_failure_at?: string
  writer_stats_unavailable?: boolean
  // 写侧单行上限截断掉的规则命中条数：事件在库，命中明细永久缺失。
  messages_dropped?: number
  // 摄取侧「畸形区跳过」：跳过即该段审计数据对应事件永久丢失，窗口内发生
  // 跳过时后端置 healthy=false（与写侧失败同一位）。
  skipped_bytes?: number
  skipped_regions?: number
  last_skip_at?: string
  data_loss?: boolean
}

/** 字节数人类可读（跳过量级从几 KB 到 GB，原始字节数不可读）。 */
function humanBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`
}

/** 丢失量归因分项（写侧丢弃/写盘错误/格式化失败/命中明细截断/畸形区跳过各自有则列出）。 */
function lostParts(status: IngestionHealth): string[] {
  const parts: string[] = []
  if ((status.writer_dropped ?? 0) > 0) parts.push(`丢弃 ${status.writer_dropped} 条`)
  if ((status.writer_io_errors ?? 0) > 0) parts.push(`写盘错误 ${status.writer_io_errors} 次`)
  if ((status.writer_format_errors ?? 0) > 0) parts.push(`格式化失败 ${status.writer_format_errors} 次`)
  if ((status.messages_dropped ?? 0) > 0) parts.push(`命中明细截断 ${status.messages_dropped} 条`)
  if ((status.skipped_regions ?? 0) > 0) parts.push(`跳过畸形区 ${status.skipped_regions} 处（${humanBytes(status.skipped_bytes ?? 0)}）`)
  return parts
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
    const format = status.writer_format_errors ?? 0
    const formatPart = format > 0 ? `、格式化失败 ${format} 次` : ''
    const hint = format > 0
      ? '格式化失败属 formatter 契约/代码缺陷，请同时检查审计格式化实现与镜像版本'
      : '请检查审计日志目录的磁盘空间与写权限'
    return `审计日志写侧失败：累计丢弃 ${status.writer_dropped ?? 0} 条、写盘错误 ${status.writer_io_errors ?? 0} 次${formatPart}，安全事件可能缺失；${hint}。`
  }
  if (status.observed === true && status.healthy === false) {
    const failures = status.consecutive_failures ?? 0
    if (failures > 0) {
      const detail = status.last_error ? `：${status.last_error}` : ''
      return `安全事件采集连续失败 ${failures} 次${detail}，事件数据可能滞后；请检查任务日志与审计日志目录。`
    }
    if ((status.skipped_regions ?? 0) > 0) {
      const lastSkip = status.last_skip_at ? `，最近 ${status.last_skip_at}` : ''
      return `安全事件采集跳过了 ${status.skipped_regions} 处畸形区（累计 ${humanBytes(status.skipped_bytes ?? 0)}${lastSkip}）：该段审计数据对应的事件已永久丢失；请检查审计日志是否被截断或存在并发写入异常。`
    }
    // 后端健康位为 false 但前端已知归因均不成立：不虚构「连续失败 0 次」。
    return '安全事件采集健康位异常（后端未提供进一步归因，可能为任务未运行或采集停摆）；请检查任务日志与审计日志目录。'
  }
  // data_loss 单独成立（当前已恢复但曾丢失）：与「正在失败」文案区分，
  // 丢失来源逐项归因（写侧与畸形区跳过都会永久丢事件）。
  const parts = lostParts(status)
  return `此前曾发生安全事件丢失（累计${parts.join('、') || '计数不可用'}，当前已恢复）：对应时间窗内的事件可能缺失。`
}
