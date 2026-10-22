// CA 选择器选项口径单源（规则向导 TLS 步 + 免费证书全局默认共用）。
//
// 原两处各自 `filter(p => p.enabled)`：存量配置指向已禁用 CA 时，选中值不在
// 选项集内——el-select 显示裸数字 id（像「未设置」），保存又原样保留旧引用。
// 口径：启用项 ∪ 当前值对应项（已禁用项仅供回显，视图为该 option 置
// :disabled 不允许新选）。

interface CAProviderOptionSource {
  readonly id: number
  readonly enabled: boolean
}

/** 选择器可见集：全部启用项 + 当前选中值对应项（无论其是否禁用）。 */
export const selectableCAProviders = <T extends CAProviderOptionSource>(
  providers: readonly T[],
  currentId: number,
): T[] => providers.filter((p) => p.enabled || p.id === currentId)

/** 选项展示名：已禁用的回显项标注「（已禁用）」，避免被读成可用项。 */
export const caProviderOptionLabel = (p: CAProviderOptionSource & { readonly name: string }): string =>
  p.enabled ? p.name : `${p.name}（已禁用）`
