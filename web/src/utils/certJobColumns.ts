// 证书任务表列宽与「按容器宽收敛」单源：表格列宽固定，容器变窄时按优先级
// 隐藏低价值列，避免出现水平滚动条（隐藏列的信息由相邻单元格 tooltip / 日志
// 弹框承载，见 CertJobs.vue）。
//
// 纯函数便于单测：给定容器宽度返回应显示的列集合。

export type CertJobColumnId =
  | 'rule_id'
  | 'domain'
  | 'status'
  | 'issuer'
  | 'validity'
  | 'renewal'
  | 'updated'
  | 'attempts'
  | 'cooling'
  | 'actions'

/** 各列固定宽度（px）；合计须与 CertJobs.vue 的 width 声明一致。 */
export const CERT_JOB_COLUMN_WIDTHS: Record<CertJobColumnId, number> = {
  rule_id: 96,
  domain: 170,
  status: 84,
  issuer: 96,
  validity: 170,
  renewal: 110,
  updated: 110,
  attempts: 64,
  cooling: 104,
  actions: 96,
}

export const CERT_JOB_COLUMNS: readonly CertJobColumnId[] = [
  'rule_id',
  'domain',
  'status',
  'issuer',
  'validity',
  'renewal',
  'updated',
  'attempts',
  'cooling',
  'actions',
]

/**
 * 隐藏优先级：容器不足时依次让位。规则 ID 先让位（并入域名单元格副行），
 * 其次冷却时间（并入重试单元格 tooltip）、更新时间、颁发者、自动重签时间。
 * 域名/状态/有效期/重试/操作恒保留——没有它们表格失去意义。
 */
export const CERT_JOB_COLUMN_HIDE_ORDER: readonly CertJobColumnId[] = [
  'rule_id',
  'cooling',
  'updated',
  'issuer',
  'renewal',
]

export const certJobColumnsWidth = (columns: Iterable<CertJobColumnId>): number => {
  let total = 0
  for (const id of columns) total += CERT_JOB_COLUMN_WIDTHS[id]
  return total
}

export const CERT_JOB_COLUMNS_TOTAL_WIDTH = certJobColumnsWidth(CERT_JOB_COLUMNS)

/**
 * 贪心选择：从全列出发，按隐藏优先级逐列让位，直到合计宽度不超过容器宽，
 * 或已无列可让。返回应显示的列集合（恒包含不可让位列）。
 */
export const pickVisibleCertJobColumns = (
  containerWidth: number,
): ReadonlySet<CertJobColumnId> => {
  const visible = new Set<CertJobColumnId>(CERT_JOB_COLUMNS)
  let total = CERT_JOB_COLUMNS_TOTAL_WIDTH
  // 容器宽未知/未测量（0 或非有限）时按最简集处理会闪列；调用侧初始为
  // Infinity，仅在 ResizeObserver 给出真实宽度后才会进入隐藏分支。
  if (!Number.isFinite(containerWidth) || containerWidth <= 0) return visible
  for (const id of CERT_JOB_COLUMN_HIDE_ORDER) {
    if (total <= containerWidth) break
    if (!visible.has(id)) continue
    visible.delete(id)
    total -= CERT_JOB_COLUMN_WIDTHS[id]
  }
  return visible
}
