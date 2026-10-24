import { ref, watch } from 'vue'
import { request } from '@/utils/api'

/** GET /logs/stats 的单行统计（服务端按 key 收窄后返回的条目）。 */
export interface LogStorageInfo {
  key: string
  name: string
  size_bytes: number
  rotated_bytes: number
  rotated_count: number
  limit_bytes?: number | null
  limit_rows?: number | null
  db_bytes?: number | null
  keep_count: number
  rows?: number | null
  // 行数读取失败披露：为真时保持条数口径并标注「计数暂不可用」，不再静默
  // 退回字节口径（口径切换会让用户以为统计规则被改）。
  rows_unavailable?: boolean
  retention_note: string
  config_source: string
}

export interface LogStorageTarget {
  /** 日志行键（后端统计口径的唯一标识）。 */
  logKey: string
  /** 按站点收窄的服务标识（Caddy 统计行传实例 id）。 */
  caddyId?: string
}

/**
 * 日志存储统计取数（LogStorageBar 的数据层）。
 *
 * 两类触发源语义不同：
 * - `target`（logKey / caddyId）变化 = 换了一行日志：必须**先清空**再取数。
 *   后端只返回所看那一行的统计，旧值不会被覆盖，清空是防止模板继续渲染上一条
 *   日志的名称/字节/百分比（原实现只在 refreshKey 时重取，换行靠调用方重挂
 *   组件规避——隐式契约，破坏后无声显示错行）。
 * - `refreshKey` 变化 = 同一行重取（保留/清理改变占用）：不清空，避免闪烁。
 *
 * 两个触发源合并为单个 watch：同一 tick 内换行 + 刷新号自增只发一次请求
 * （原实现两条独立 watch，并发两次 /logs/stats，序号只保证写回正确不省请求）。
 * 取数序号保证迟到响应不写回（换行后上一行的慢响应被丢弃）。
 *
 * 失败不静默：`error` 置位且保留上一次 `info`，由消费方显性呈现——失败时
 * 整条统计消失与站内「读取失败要显性」口径不一致。
 */
export const useLogStorageStats = (options: {
  target: () => LogStorageTarget
  refreshKey?: () => number | undefined
}) => {
  const info = ref<LogStorageInfo | null>(null)
  const error = ref<string | null>(null)
  let loadStatsSeq = 0
  let lastTargetKey: string | null = null

  const targetKeyOf = (target: LogStorageTarget): string => `${target.logKey}\u0000${target.caddyId ?? ''}`

  const loadStats = async (): Promise<void> => {
    const { logKey, caddyId } = options.target()
    const seq = ++loadStatsSeq
    try {
      // 服务端按 key 收窄（只统计所看那一行）；缺省全量会为每个弹框
      // 做全部 DB 计数与目录统计。
      const params: Record<string, string> = { key: logKey }
      if (caddyId) params.caddy_id = caddyId
      const res = await request.get<{ data?: { logs?: LogStorageInfo[] } }>('/logs/stats', { params })
      if (seq === loadStatsSeq) {
        info.value = res.data?.logs?.find((l) => l.key === logKey) || null
        error.value = null
      }
    } catch (e) {
      if (seq === loadStatsSeq) {
        error.value = e instanceof Error ? e.message : '日志统计取数失败'
        console.error('Failed to load log stats:', e)
      }
    }
  }

  watch(
    () => [targetKeyOf(options.target()), options.refreshKey?.()] as const,
    ([nextTarget]) => {
      if (nextTarget !== lastTargetKey) {
        lastTargetKey = nextTarget
        info.value = null
      }
      void loadStats()
    },
    { immediate: true },
  )

  return { info, error }
}
