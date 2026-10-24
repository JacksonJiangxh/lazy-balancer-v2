// 构建壳与测试卫生（构建配置单源盘）：
//   - web/index.html 的挂载点/入口脚本/语言/首帧标题——被删时 vite build 仍产出
//     空壳，运行期整页空白，而全部行为用例照绿；
//   - 每个 spec 必须至少含 `test(` 与 `assert`（新增空 spec 文件不得静默混入）；
//   - `_stubs` 的两处 ElMessage 替身共用同一契约（可调用 + 同名记录）。

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

import { calls, resetCalls, STUB_ELEMENT, STUB_SAVE_RESULT_DEPS, type StubCall } from './_stubs.ts'
import { source } from './_helpers.ts'

const webRoot = new URL('../', import.meta.url)

test('index.html 保留挂载点、入口脚本与首帧标题（否则运行期整页空白）', () => {
  const html = readFileSync(new URL('index.html', webRoot), 'utf8')
  assert.match(html, /<div id="app"><\/div>/, 'SFC 挂载点缺失（main.ts 挂到 #app）')
  assert.match(html, /<script type="module" src="\/src\/main\.ts"><\/script>/, '入口脚本缺失或路径漂移')
  assert.match(html, /<html lang="zh-CN">/, '语言声明漂移（字体/断行与读屏口径）')
  // 首帧标题与 branding 的品牌化口径一致：`${appName} V2`。
  assert.match(html, /<title>Lazy Balancer V2<\/title>/)
  const branding = source('src/utils/branding.ts')
  assert.match(branding, /export const appName = ref\('Lazy Balancer'\)/, '品牌默认名漂移（首帧标题与运行期标题会分叉）')
  assert.match(branding, /document\.title = `\$\{appName\.value\} V2`/, '运行期标题必须同形')
})

test('每个 spec 都含 test( 与 assert（防空用例文件混入）', () => {
  const specDir = fileURLToPath(new URL('./', import.meta.url))
  const offenders: string[] = []
  for (const name of readdirSync(specDir)) {
    if (!name.endsWith('.spec.ts')) continue
    const text = readFileSync(`${specDir}${name}`, 'utf8')
    if (!/\btest\(/.test(text) || !/\bassert[.(]/.test(text)) offenders.push(name)
  }
  assert.deepEqual(offenders, [], '空 spec（无 test/assert）不得入库')
})

test('_stubs 两处 ElMessage 替身共用同一契约（可调用 + 同名记录）', async () => {
  const g = globalThis as unknown as { __calls?: StubCall[] }
  const previous = g.__calls
  g.__calls = calls
  resetCalls()
  try {
    // 测试本身即在验证「data: 模块替身」的加载边界（静态 import 无法加载
    // 运行时拼接的 data: URL），故此处必须用动态 import。
    const saveDeps = (await import(STUB_SAVE_RESULT_DEPS)) as { ElMessage: (arg: string) => void }
    const element = (await import(STUB_ELEMENT)) as {
      ElMessage: ((arg: string) => void) & { info: (arg: string) => void; error: (arg: string) => void; success: (arg: string) => void }
    }
    assert.equal(typeof saveDeps.ElMessage, 'function', 'saveResult 替身的 ElMessage 必须可调用（真实 API 同形）')
    assert.equal(typeof element.ElMessage, 'function', 'element 替身的 ElMessage 必须可调用')
    saveDeps.ElMessage('a')
    element.ElMessage('b')
    element.ElMessage.info('c')
    assert.deepEqual(
      calls.map((call) => call.fn),
      ['ElMessage', 'ElMessage', 'ElMessage.info'],
      '两处替身记录的函数名必须一致（新增 ElMessage.warning 等调用时各自漂移即红）',
    )
  } finally {
    g.__calls = previous
  }
})
