// OIDC 访问白名单文本 ↔ 数组解析单源（OIDCSettings.vue 的 load/save 共用）。
//
// 两个字段的分隔口径**有意不同**：
// - 邮箱域：条目本身不含空白，故空白/半角逗号/分号/全角逗号/顿号一律当分隔符
//   （管理员从表格/邮件里粘贴常带空格与中英文标点）；
// - 用户组：IdP 组名可以含内部空格（如 "Platform Ops"），空白**不得**当分隔符，
//   只按逗号/分号（含全角）与换行切分。
// 两侧都 trim、去空、保序去重；formatAllowList 用换行拼接，两种字段都能无损往返。

const EMAIL_DOMAIN_SEPARATORS = /[\s,;，、；]+/
const GROUP_SEPARATORS = /[,;，、；\r\n]+/

const splitAllowList = (raw: string, separators: RegExp): string[] => {
  const seen = new Set<string>()
  const result: string[] = []
  for (const item of raw.split(separators)) {
    const trimmed = item.trim()
    if (!trimmed || seen.has(trimmed)) continue
    seen.add(trimmed)
    result.push(trimmed)
  }
  return result
}

/** 邮箱域白名单：空白与中英文逗号/分号/顿号均为分隔符。 */
export const parseDomainAllowList = (raw: string): string[] =>
  splitAllowList(raw, EMAIL_DOMAIN_SEPARATORS)

/** 用户组白名单：仅按中英文逗号/分号与换行切分——组名允许内部空格。 */
export const parseGroupAllowList = (raw: string): string[] =>
  splitAllowList(raw, GROUP_SEPARATORS)

/** 数组 → 编辑文本（换行分隔，组名含空格也能无损往返）。 */
export const formatAllowList = (values?: readonly string[]): string => (values ?? []).join('\n')
