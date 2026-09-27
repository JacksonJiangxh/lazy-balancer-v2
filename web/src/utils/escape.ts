// escapeHtml 共享实现(第 62 轮 F62-12 收敛——原 ansi/branding/highlight 三份独立实现)。
// HTML 属性上下文必须含引号转义(与原 ansi/branding 版一致;highlight 版在
// Prism 上下文无属性注入面,统一到含引号版无行为回归)。
export const escapeHtml = (raw: string): string =>
  raw.replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch] ?? ch))
