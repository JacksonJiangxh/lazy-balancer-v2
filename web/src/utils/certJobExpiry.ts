// 证书任务的到期派生口径：任务页「证书有效期」与「自动重签时间」两列共用，
// 也供后续消费方（批量视图/导出）复用，避免各自判 expires_at 出现跨页分叉。
//
// 后端 /certificates/jobs 同时下发：
//   - expires_at：库列原值，导入/旧备份/集群回插可能为 null（契约不变）；
//   - not_after：真实到期时刻的派生值（expires_at 缺失时按 PEM 解析）。
// UI 必须以 not_after 为准，否则后端已算出的 days_remaining/certificate_status
// 在 expires_at 为 null 的行上没有任何消费方，页面显示「-」而规则页显示
// 「剩 N 天」，运维会误判为未签发并重复触发签发。

interface CertJobExpiryFields {
  expires_at?: string | null
  not_after?: string | null
}

/** 证书真实到期时刻（ISO 串）；两列都缺失/为旧版响应时返回空串。 */
export const certJobEffectiveNotAfter = (job: CertJobExpiryFields): string =>
  job.not_after || job.expires_at || ''

/**
 * 自动重签时间 = 到期时刻前 renewalDays 天，返回 ISO 原值（列内紧凑格式与
 * tooltip 完整格式各自取用，不在 helper 里预先格式化）。
 * 畸形时间/非法天数一律返回空串——`new Date(NaN).toISOString()` 会抛
 * RangeError 并中断整行渲染。
 */
export const certJobRenewalAt = (job: CertJobExpiryFields, renewalDays: number): string => {
  const expiryValue = certJobEffectiveNotAfter(job)
  if (!expiryValue) return ''
  const expiry = new Date(expiryValue)
  if (Number.isNaN(expiry.getTime())) return ''
  if (!Number.isFinite(renewalDays)) return ''
  return new Date(expiry.getTime() - renewalDays * 24 * 60 * 60 * 1000).toISOString()
}
