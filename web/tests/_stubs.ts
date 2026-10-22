// showSaveResult 的行为测试：退化 200（DB 已提交、Caddy 应用失败）必须以常驻警告
// 呈现并保留后端文案；普通成功统一走 mfaAwareSuccess。element-plus 与 api.ts
// 都是字节级依赖（CSS 导入/DOM），测试用本文件的替身记录调用。
//
// 另含 data: 模块替身的共享定义：composable 行为用例（useIpListAdd /
// useTrustAssociation / useCountryNamesCn）此前各持一份逐字相同的 stub，
// 替身契约（如 ElMessage.info）改动需要多处同步。宿主只需提供
// globalThis.__calls / __gets / __get / __post / __put / __confirm。

export interface StubCall {
  fn: 'ElMessage' | 'mfaAwareSuccess'
  arg: unknown
}

export const calls: StubCall[] = []

export const resetCalls = (): void => {
  calls.length = 0
}

export const ElMessage = (arg: unknown): void => {
  calls.push({ fn: 'ElMessage', arg })
}

export const mfaAwareSuccess = (message: string): void => {
  calls.push({ fn: 'mfaAwareSuccess', arg: message })
}

/** data: 模块源码包装（node 直接求值，不落盘）。 */
export const dataModule = (code: string): string => `data:text/javascript,${encodeURIComponent(code)}`

/** element-plus 替身：ElMessage 的 info/error/success 与 MessageBox.confirm 均记录调用。 */
export const STUB_ELEMENT = dataModule(`
export const ElMessage = Object.assign(
  (arg) => globalThis.__calls?.push({ fn: 'ElMessage', arg }),
  {
    info: (arg) => globalThis.__calls?.push({ fn: 'ElMessage.info', arg }),
    error: (arg) => globalThis.__calls?.push({ fn: 'ElMessage.error', arg }),
    success: (arg) => globalThis.__calls?.push({ fn: 'ElMessage.success', arg }),
  },
)
export const ElMessageBox = { confirm: (...args) => globalThis.__confirm(...args) }
`)

/** api 替身：get 额外记录到 __gets（宿主提供时），请求全部委托宿主注入的函数。 */
export const STUB_API = dataModule(`
export const request = {
  get: (url, config) => { globalThis.__gets?.push({ url, config }); return globalThis.__get(url, config) },
  post: (...args) => globalThis.__post(...args),
  put: (...args) => globalThis.__put(...args),
}
export const mfaAwareSuccess = (message) => globalThis.__calls?.push({ fn: 'mfaAwareSuccess', arg: message })
`)

/** saveResult 替身：记录 showSaveResult 的完整入参。 */
export const STUB_SAVE_RESULT = dataModule(`
export const showSaveResult = (...args) => globalThis.__calls?.push({ fn: 'showSaveResult', args })
`)
