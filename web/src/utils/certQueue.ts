/**
 * ACME 证书任务队列横幅的展示口径。
 *
 * 判据与后端 `status_counts` 同口径：队列非空 = 排队 + 进行中 + 等 CA 的计数之和
 * > 0。此前标签只看 `running`——全队列都在排队/等 CA 时仍显示「空闲」，正文分支
 * 又以首页存活行数（可能为 0）为准，与聚合计数互相矛盾。
 */

/** 横幅最多列出的域名 chip 数（其余以「+N」折叠）。 */
export const CERT_QUEUE_VISIBLE_JOBS = 4

export interface CertQueueCounts {
  readonly queued: number
  readonly running: number
  readonly waiting: number
  readonly total: number
  readonly jobs: readonly { readonly id: number }[]
}

/** 队列非空（排队 / 进行中 / 等 CA 任一存在）——标签与正文空态的单一判据。 */
export const certQueueIsBusy = (q: Pick<CertQueueCounts, 'queued' | 'running' | 'waiting'>): boolean =>
  q.queued + q.running + q.waiting > 0

/** 存活任务总数 > 0（status_counts 聚合值，与首页行数解耦）。 */
export const certQueueHasLive = (q: Pick<CertQueueCounts, 'total'>): boolean => q.total > 0

/** 已列出的 chip 数（最多 4 个；首页存活行不足时按实际行数）。模块内 helper。 */
const certQueueShownCount = (q: Pick<CertQueueCounts, 'jobs'>): number =>
  Math.min(CERT_QUEUE_VISIBLE_JOBS, q.jobs.length)

/** 「+N」折叠数 = 存活总数 − 已列出数。此前恒用 `total - 4`，行数不足时偏大。 */
export const certQueueMoreCount = (q: CertQueueCounts): number =>
  Math.max(0, q.total - certQueueShownCount(q))
