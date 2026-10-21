// 自动封禁「未生效黄条」判据单源（历史问题-02，历史问题 行为化）：
// ban_effective 为生效面单一判据（名单非空且被启用 + deny 的策略引用）；
// list_referenced（四面引用集，含仅被白名单/受信代理引用的误判面）仅保留为
// 后端内部字段，不得驱动 UI。
export interface AutobanEffectivenessView {
  readonly enabled: boolean
  readonly ban_effective?: boolean
}

/** 是否展示「已启用但未生效」黄条：仅显式 ban_effective === false 时提示。 */
export const isAutobanIneffective = (status: AutobanEffectivenessView): boolean =>
  status.enabled && status.ban_effective === false
