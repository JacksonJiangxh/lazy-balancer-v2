// 未被任何 spec 引用但承担跨栈/注入面的工具单源：
//   - caddyDefaults：访问日志格式模板末行必须与后端强制注入行逐字一致
//     （落库格式 ≠ 实际生效格式会让用户以为脱敏没生效）；
//   - escape / highlight：HTML 注入面的兜底转义；
//   - branding：footerHtml 的默认/自定义分支与转义。
//
// branding 依赖 api.ts（element-plus 字节级依赖），用替身加载；highlight 顶层
// 导入 Prism CSS（node 不可加载），兜底分支用源码钉。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks, repoSource, section, source } from './_helpers.ts'
import { STUB_API } from './_stubs.ts'
import { DEFAULT_ACCESS_LOG_FORMAT } from '../src/utils/caddyDefaults.ts'
import { escapeHtml } from '../src/utils/escape.ts'

const g = globalThis as unknown as { __gets: unknown[]; __get: (url: string, config?: unknown) => Promise<unknown> }
g.__gets = []
registerModuleHooks({ '@/utils/api': STUB_API })

test('默认访问日志格式末行与后端脱敏注入行逐字一致（跨栈钉）', () => {
  const go = repoSource('internal/handlers/caddy.go')
  const constBlock = section(go, 'const accessLogRedactionLine', '\n')
  const match = constBlock.match(/accessLogRedactionLine = "([^"]+)"/)
  assert.ok(match, '后端 accessLogRedactionLine 常量缺失')
  const lines = DEFAULT_ACCESS_LOG_FORMAT.split('\n')
  assert.equal(lines[lines.length - 1], match[1], '模板末行必须等于后端强制注入的脱敏行')
  // db.go 迁移补齐同一行（既有格式升级路径同源）：迁移以「路径 + " -> delete"」
  // 组合出规范行，路径常量必须与模板末行同值。
  const db = repoSource('internal/db/db.go')
  assert.match(db, /const apiKeyPath = "request>headers>X-API-Key"/, 'db.go 迁移的脱敏路径常量漂移')
  assert.match(db, /apiKeyPath\+\s*" -> delete"/, 'db.go 迁移必须追加 delete 动作（与模板末行同形）')
  // 第三处（匹配/移除侧）：normalizeAccessLogRedaction 用独立 `path` 常量决定
  // 移除哪些既有行——它漂移时输出行仍取模板末行，库内格式与面板展示会分叉。
  assert.match(go, /const path = "request>headers>X-API-Key"/, 'caddy.go 移除侧脱敏路径常量漂移（与写入侧必须同源）')
  assert.equal(
    [...go.matchAll(/request>headers>X-API-Key/g)].length,
    2,
    '脱敏路径字面量在 caddy.go 只允许写入行常量与移除侧 path 两处（新增副本即失去单源）',
  )
})

test('escapeHtml 覆盖五个 HTML 危险字符（含引号属性上下文）', () => {
  assert.equal(escapeHtml(`<a href="x">'&'</a>`), '&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;')
  assert.equal(escapeHtml('plain'), 'plain')
})

test('highlight 的 Prism 异常兜底必须转义（注入面不得回退原文）', () => {
  const highlight = source('src/utils/highlight.ts')
  const catchBlock = section(highlight, '} catch {', '\n  }\n}')
  assert.match(catchBlock, /return escapeHtml\(content\)/, '兜底必须走共享 escapeHtml，不得返回原文')
})

test('branding.footerHtml：默认加 GitHub 链接、自定义仅转义文本', async (t) => {
  // 先加载模块（vue runtime-dom 在无 document 时初始化），再注入 host——先注入
  // 半成品 document 会让 runtime-dom 的探测代码调用不存在的 createElement。
  const branding = await import('../src/utils/branding.ts')
  const host = globalThis as { document?: unknown }
  const previousDocument = host.document
  const documentStub = { title: '' }
  host.document = documentStub
  // 与 threatHotPathCaching 同范式：假 DOM 不得留给同进程其它用例
  // （node --test --test-isolation=none 下会污染 Vue 的 DOM 探测）。
  t.after(() => {
    if (previousDocument === undefined) Reflect.deleteProperty(host, 'document')
    else host.document = previousDocument
    assert.equal(host.document, previousDocument, 'document 替身必须还原')
  })

  // 默认分支（footer_uses_default 未关闭）：带 GitHub 外链
  const defaultHtml = branding.footerHtml.value
  assert.match(defaultHtml, /class="footer-link"/)
  assert.match(defaultHtml, /github\.com/, '默认页脚必须含仓库链接')

  // 自定义分支：后端声明 footer_uses_default=false → 不加链接，且文本转义
  g.__get = async () => ({ data: { footer_text: '<b>x & y</b>', footer_uses_default: false, app_name: 'Corp' } })
  await branding.loadBranding()
  const customHtml = branding.footerHtml.value
  assert.equal(customHtml, '&lt;b&gt;x &amp; y&lt;/b&gt;')
  assert.doesNotMatch(customHtml, /footer-link/, '自定义页脚不得追加 GitHub 链接')
  assert.equal(documentStub.title, 'Corp V2')
})
