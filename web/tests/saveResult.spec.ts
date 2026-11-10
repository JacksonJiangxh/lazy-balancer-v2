// showSaveResult 的行为测试：退化 200（DB 已提交、Caddy 应用失败）必须以常驻
// 警告呈现并保留后端文案，不能被后续成功提示顶掉；普通成功统一走 mfaAwareSuccess。
// element-plus 与 api.ts 是字节级依赖（CSS 导入/DOM），用 _stubs.ts 记录调用。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { STUB_SAVE_RESULT_DEPS, calls, resetCalls } from './_stubs.ts'
import { registerModuleHooks } from './_helpers.ts'

// 替身把调用写进宿主提供的记录面（与断言共享同一数组）。
const host = globalThis as unknown as { __calls: unknown[] }
host.__calls = calls
// 静态 import 会先于钩子注册执行，故被测模块只能动态 import（钩子必须先装）。
// `@/utils/bulkApplyResult` 走真实实现——退化标记必须与真实常量同源。
registerModuleHooks({ 'element-plus': STUB_SAVE_RESULT_DEPS, '@/utils/api': STUB_SAVE_RESULT_DEPS })
const { showSaveResult } = await import('../src/utils/saveResult.ts')
const { CADDY_APPLY_FAILED_MARKER } = await import('../src/utils/bulkApplyResult.ts')

test('退化 200 走常驻警告：保留后端文案、不自动消失、可手动关闭', () => {
  resetCalls()
  const message = `已保存${CADDY_APPLY_FAILED_MARKER}：caddy reload 超时`
  showSaveResult({ message }, '保存成功')
  assert.deepEqual(calls, [
    { fn: 'ElMessage', arg: { type: 'warning', message, duration: 0, showClose: true } },
  ])
})

test('普通成功走 mfaAwareSuccess 单源（含 MFA 宽限文案）', () => {
  resetCalls()
  showSaveResult({ message: '已保存' }, '保存成功')
  assert.deepEqual(calls, [{ fn: 'mfaAwareSuccess', arg: '已保存' }])
})

test('响应缺 message 时用调用方兜底文案', () => {
  resetCalls()
  showSaveResult(undefined, '创建成功')
  showSaveResult({}, '更新成功')
  showSaveResult({ message: '' }, '删除成功')
  assert.deepEqual(calls, [
    { fn: 'mfaAwareSuccess', arg: '创建成功' },
    { fn: 'mfaAwareSuccess', arg: '更新成功' },
    { fn: 'mfaAwareSuccess', arg: '删除成功' },
  ])
})
