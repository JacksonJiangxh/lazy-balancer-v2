/**
 * DNS 提供商凭证字段的展示口径（WS-13，历史）。
 *
 * 字段可见性与选项文案此前在前端按 dnspod 的两种认证模式硬编码
 * （`auth_mode/secret_id/secret_key/app_id/app_token` 逐个判断），而后端新增
 * 提供商时其 `credential_fields` 会被整体隐藏、选项只能显示原始值。现由
 * `/dns-providers` 下发的字段元数据驱动：
 *
 * - `visible_when`: { 其它字段名: 允许的取值[] }——全部条件命中才显示；
 * - `option_labels`: { 选项值: 显示文案 }——缺失时回退原始值。
 */

export interface CredentialFieldMeta {
  readonly name: string
  readonly label: string
  readonly type: string
  readonly required: boolean
  readonly placeholder?: string
  readonly options?: readonly string[]
  readonly visible_when?: Readonly<Record<string, readonly string[]>>
  readonly option_labels?: Readonly<Record<string, string>>
}

/** 字段是否应显示：无 `visible_when` 元数据 → 恒显示（不再按 provider 硬编码）。 */
export const credentialFieldVisible = (
  field: CredentialFieldMeta,
  credentials: Readonly<Record<string, string>>,
): boolean => {
  const conditions = field.visible_when
  if (!conditions) return true
  return Object.entries(conditions).every(([key, allowed]) => allowed.includes(credentials[key] ?? ''))
}

/** 选项显示文案：优先元数据 label，缺失回退选项值。 */
export const credentialOptionLabel = (field: CredentialFieldMeta, option: string): string =>
  field.option_labels?.[option] ?? option

/**
 * 新建/切换提供商时的凭证初始值：每个 select 字段取首个选项。
 * （原实现固定写死 `{ auth_mode: 'dnspod' }`——新增无 auth_mode 的 provider
 * 会带入多余键，且 select 初值与其 options 脱节。）
 */
export const defaultCredentialsFor = (
  fields: readonly CredentialFieldMeta[],
): Record<string, string> => {
  const credentials: Record<string, string> = {}
  for (const field of fields) {
    if (field.type === 'select' && field.options?.length) credentials[field.name] = field.options[0]
  }
  return credentials
}
