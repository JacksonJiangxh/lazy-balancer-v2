// IP 名单 CSV 往返（历史问题）：导出对含逗号/引号的备注加双引号并
// 双写内部引号，而原解析器只按 `^([^,\s]+)(?:[,\s]+(.*))?$` 切分、不做 CSV
// 反转义——自产文件导回后备注被截断/保留外层引号，二次往返累积漂移。
// 此模块是导出/导入共用的字段级单源。

/**
 * 备注字段导出：换行归一为空格（导入端按行切分，多行备注无法回读——历史问题-11），
 * 含逗号或双引号时按 RFC4180 包裹并双写内部引号。
 */
function formatCsvRemark(remark: string): string {
  const singleLine = remark.replace(/[\r\n]+/g, ' ')
  return /[",]/.test(singleLine) ? `"${singleLine.replace(/"/g, '""')}"` : singleLine
}

/** 导出一行（第一列 IP/CIDR，第二列备注；备注为空保留尾随逗号）。 */
export function formatIpListEntryLine(value: string, remark: string): string {
  return `${value},${formatCsvRemark(remark)}`
}

/** 解析行尾/字段内的双引号包裹值（`""` 反转义）；未闭合返回 null。 */
function readQuotedField(raw: string, start: number): { text: string; next: number } | null {
  let i = start + 1
  let text = ''
  while (i < raw.length) {
    const ch = raw[i]
    if (ch === '"') {
      if (raw[i + 1] === '"') {
        text += '"'
        i += 2
        continue
      }
      return { text, next: i + 1 }
    }
    text += ch
    i++
  }
  return null
}

/**
 * 解析导入行：第一列可为双引号包裹的 CSV 字段（`""` 反转义），列间分隔符为
 * 半角逗号或空白（与旧行为兼容；纯文本行不带引号时按原正则切分）。
 * validate 由调用方注入（isValidCidr）——本模块不依赖校验实现。
 */
export function parseIpListEntryLine(
  line: string,
  validate: (value: string) => boolean,
): { value: string; remark: string } | null {
  const text = line.trim()
  if (text === '') return null
  let value: string
  let rest: string
  if (text.startsWith('"')) {
    const field = readQuotedField(text, 0)
    if (!field) return null
    value = field.text
    rest = text.slice(field.next).replace(/^\s*,\s*/, '').replace(/^\s+/, '')
  } else {
    const match = text.match(/^([^,\s]+)(?:[,\s]+([\s\S]*))?$/)
    if (!match) return null
    value = match[1] ?? ''
    rest = match[2] ?? ''
  }
  const normalized = value.trim()
  if (!normalized || !validate(normalized)) return null
  let remark = rest.trim()
  if (remark.startsWith('"')) {
    const field = readQuotedField(remark, 0)
    if (!field) return null
    remark = field.text
  }
  return { value: normalized, remark: Array.from(remark).slice(0, 100).join('') }
}
