// showSaveResult 的行为测试：退化 200（DB 已提交、Caddy 应用失败）必须以常驻警告
// 呈现并保留后端文案；普通成功统一走 mfaAwareSuccess。element-plus 与 api.ts
// 都是字节级依赖（CSS 导入/DOM），测试用本文件的替身记录调用。

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
