// 系统指标分项降级展示单源：后端 getSystemMetrics 对失败分项返回零值并在
// `degraded` 中披露（全失败才 500）。展示层必须据此把「没采到」呈现为
// 「采集失败」而非 0——否则 CPU 单点故障时用户看到「内存 0 B / 磁盘 0%」，
// 排障窗口反而误判。

/** 已知分项（顺序即文案顺序）；仅模块内使用，导出面只留消费函数。 */
const SYSTEM_METRIC_PARTS = ['cpu', 'memory', 'disk'] as const
type SystemMetricPart = (typeof SYSTEM_METRIC_PARTS)[number]

const SYSTEM_METRIC_LABELS: Record<SystemMetricPart, string> = {
  cpu: 'CPU',
  memory: '内存',
  disk: '磁盘',
}

/** 只收已知分项（未知值忽略，向前兼容后端新增分项）。 */
export const degradedMetricParts = (degraded: readonly string[] | undefined): Set<SystemMetricPart> => {
  const parts = new Set<SystemMetricPart>()
  for (const value of degraded ?? []) {
    if ((SYSTEM_METRIC_PARTS as readonly string[]).includes(value)) parts.add(value as SystemMetricPart)
  }
  return parts
}

/** 降级提示文案用的分项名（保持稳定顺序 cpu→memory→disk）。 */
export const degradedMetricLabels = (degraded: readonly string[] | undefined): string[] => {
  const parts = degradedMetricParts(degraded)
  return SYSTEM_METRIC_PARTS.filter((part) => parts.has(part)).map((part) => SYSTEM_METRIC_LABELS[part])
}
