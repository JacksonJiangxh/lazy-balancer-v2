// escapeHtml 共享实现——收敛原 ansi/branding/highlight 三份独立实现。
// HTML 属性上下文必须含引号转义(与原 ansi/branding 版一致;highlight 版在
// Prism 上下文无属性注入面,统一到含引号版无行为回归)。
// 查表为模块级常量——replace 回调每个匹配字符触发一次，逐字符构造字面量在
// 大日志（上限 256KB）渲染路径上是可消除的分配。
const escapeHtmlTable: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}

export const escapeHtml = (raw: string): string =>
  raw.replace(/[&<>"']/g, (ch) => escapeHtmlTable[ch] ?? ch)
