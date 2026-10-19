/** 水合期间保留库值；只有用户主动关闭 DNS 服务器才清空。 */
export const dnsServerAfterToggle = (current: string, enabled: boolean, hydrating: boolean): string => {
  if (hydrating || enabled) return current
  return ''
}

/**
 * 规则级阶段拦截页覆盖（W87-01）：由规则列表「批量设置阶段拦截页」写入，向导
 * 不提供编辑入口但必须随规则往返。这也是向导两份手工键集的共享来源——
 * `newRuleWizardStageOverrides()` 供「新建」路径清态，`stageBlockPageOverrides()`
 * 供编辑/复制路径回填，两侧口径同源，避免新建静默继承上一条规则的覆盖。
 */
export interface StageBlockPageOverrideState {
  block_page_stage1_id: number
  block_page_stage1_status: number
  block_page_stage3_id: number
  block_page_stage3_status: number
}

/** 新建规则的阶段拦截页覆盖恒为 0（0=不覆盖）。 */
export const newRuleWizardStageOverrides = (): StageBlockPageOverrideState => ({
  block_page_stage1_id: 0,
  block_page_stage1_status: 0,
  block_page_stage3_id: 0,
  block_page_stage3_status: 0,
})

/** 编辑/复制路径回填：源规则缺键按 0 处理（0=不覆盖）。 */
export const stageBlockPageOverrides = (source: {
  block_page_stage1_id?: number | null
  block_page_stage1_status?: number | null
  block_page_stage3_id?: number | null
  block_page_stage3_status?: number | null
}): StageBlockPageOverrideState => ({
  block_page_stage1_id: source.block_page_stage1_id || 0,
  block_page_stage1_status: source.block_page_stage1_status || 0,
  block_page_stage3_id: source.block_page_stage3_id || 0,
  block_page_stage3_status: source.block_page_stage3_status || 0,
})

/**
 * 被动健康检查下隐藏的超时字段（A85历史问题-1 只把 timeout 输入放进主动探测模板）：
 * 后端 validateRuleFeatures（rule_features.go 历史 历史问题）**不区分主动/被动**地
 * 要求 `0 < timeout < interval`，提交载荷也恒带该值。存量/带外数据（历史
 * 之前、迁移只回填 ≤0）在关闭主动检查后会被保存校验拦下，而输入框不可见 →
 * 「请让超时小于间隔」无处修改的死锁提示（审计 87 WEBT-10）。
 * 保存前在被动模式下把越界值钳到 `interval-1` 并显性提示：保留后端不变式，
 * 不降级校验、不静默改动可见字段（interval>1 才有合法解，否则原样返回）。
 */
export const clampPassiveHealthCheckTimeout = (
  interval: number,
  timeout: number,
): { timeout: number; clamped: boolean } => {
  if (!(interval > 1) || !(timeout >= interval)) return { timeout, clamped: false }
  return { timeout: Math.max(1, Math.floor(interval) - 1), clamped: true }
}

/**
 * 复制向导载荷的规则级回源 Host（W87-02）：向导「复制」走 POST /rules 重建，
 * CreateRule 无 Update 的 nil=保留语义——省略 host_header 会落空串，副本丢失
 * 源规则的 Host 覆盖。复制路径必须显式携带源值（空串=源规则本就未覆盖）。
 */
export const copyRuleHostHeader = (source: { host_header?: string | null }): string => source.host_header ?? ''
