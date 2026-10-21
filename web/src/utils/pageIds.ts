// 页面键唯一事实源：App.vue 深链/OIDC return_to 校验、威胁大屏全屏分支、
// auth store 的 currentPage 初值共用。禁止另起字面量清单（双源漂移会让深链
// 静默回落 dashboard）。

export const PAGE_IDS = [
  'dashboard',
  'rules',
  'security-policies',
  'security-rules',
  'security-block-pages',
  'security-overview',
  'security-events',
  'threat-screen',
  'caddy',
  'users',
  'audit-log',
  'settings-basic',
  'settings-cluster',
  'settings-certificates',
  'settings-apikeys',
  'settings-tasks',
] as const

export type PageId = (typeof PAGE_IDS)[number]

const validPages: ReadonlySet<string> = new Set(PAGE_IDS)

/** 页面键收窄（深链/URL hash/localStorage 读出值统一经此校验）。 */
export const isPageId = (page: string): page is PageId => validPages.has(page)
