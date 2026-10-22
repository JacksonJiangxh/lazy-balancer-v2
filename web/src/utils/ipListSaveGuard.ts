/**
 * 每个 IP 名单的条目上限（与后端 internal/handlers/securityiplists.go
 * `ipListMaxEntries = 2000` 同源）。SFC 内曾有 2000 双份硬编码（校验一处、
 * 文案一处），收敛于此；跨栈对表见 ipList.spec.ts。
 */
export const IP_LIST_MAX_ENTRIES = 2000

// IP 名单保存守卫：弹框以「空 entries 起步 → 详情
// GET 回填」加载。详情在途或失败时保存按钮若可点，会把空数组全量 PUT——直接
// 清空该名单（PUT 语义=全量替换）。守卫在此集中供模板/脚本同源消费。

/** 保存按钮可用性：详情在途或加载失败时禁止保存。 */
export function canSaveIpList(detailLoading: boolean, detailFailed: boolean): boolean {
  return !detailLoading && !detailFailed
}

/**
 * 「已有名单 + 提交条目为空」需要二次确认（文案必须明示清空）。
 * 新建空名单属于正常操作（后端 validateIPListShape 允许空），不弹确认。
 */
export function needsEmptyListConfirm(editingId: number | null, entries: number): boolean {
  return editingId !== null && entries === 0
}
