// 安全事件动作（后端 action：blocked | logged）的展示映射单源。
//
// 此前四处各自映射且措辞互斥：事件列表「拦截/检测」、请求详情「已拦截/已记录」、
// 大屏告警「已拦截/仅检测」、触发详情「已拦截/已记录（检测）」——同一事件在四个
// 视图里要读者自行翻译。新增动作时也只改本表。
//
// 未知动作 fail-visible：原样回显后端值（空值兜底「—」），不再把未知动作一律
// 当作「检测」——那会把「拦截语义的新动作」静默呈现为未拦截。

export type EventActionTone = 'danger' | 'warning'

const EVENT_ACTION_LABELS: Readonly<Record<string, { readonly short: string; readonly full: string; readonly tone: EventActionTone }>> = {
  blocked: { short: '拦截', full: '已拦截', tone: 'danger' },
  logged: { short: '检测', full: '已记录', tone: 'warning' },
}

/** 短标签（列表/筛选等紧凑位）：拦截 / 检测。 */
export const eventActionShort = (action: string | undefined | null): string =>
  (action ? EVENT_ACTION_LABELS[action]?.short : '') || action || '—'

/** 完整标签（详情/告警等叙述位）：已拦截 / 已记录。 */
export const eventActionFull = (action: string | undefined | null): string =>
  (action ? EVENT_ACTION_LABELS[action]?.full : '') || action || '—'

/** el-tag 色调：拦截 danger、检测 warning；未知动作按检测色（未拦截语义）。 */
export const eventActionTone = (action: string | undefined | null): EventActionTone =>
  (action ? EVENT_ACTION_LABELS[action]?.tone : undefined) ?? 'warning'
