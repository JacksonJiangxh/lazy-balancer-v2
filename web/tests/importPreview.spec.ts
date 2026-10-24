// 导入预览校验的复用层：分类勾选只改后端过滤口径，备份字节不变——修复前每次
// 勾选都重传整份备份（上限 128MB）。现在按「内容指纹 + 所选分类」缓存结果，
// 并在分类连续切换时取消在途请求。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createImportPreviewSession, importPreviewFingerprint, invalidateImportPreviews } from '../src/utils/importPreview.ts'
import type * as ImportPreviewModule from '../src/utils/importPreview.ts'
import { code, section } from './_helpers.ts'

const deferred = <T>() => Promise.withResolvers<T>()

test('同一份备份 + 同一分类集合只发一次请求（回到已看过的分类不重传）', async () => {
  const sent: string[] = []
  const session = createImportPreviewSession<{ sections: string }>({
    fingerprint: 'fp-a',
    send: async (sections) => {
      sent.push([...sections].join(','))
      return { sections: sections.join(',') }
    },
  })
  const first = await session.validate(['users', 'rules'])
  const again = await session.validate(['rules', 'users'])
  assert.equal(first.cached, false)
  assert.equal(again.cached, true, '同一分类集合（顺序无关）必须命中缓存')
  assert.equal(again.value.sections, 'users,rules')
  assert.deepEqual(sent, ['users,rules'], '缓存命中不得再发请求')
})

test('不同分类集合才发新请求，且上一轮在途请求被取消', async () => {
  const signals: AbortSignal[] = []
  const firstGate = deferred<{ mark: string }>()
  const session = createImportPreviewSession<{ mark: string }>({
    fingerprint: 'fp-abort',
    send: (_sections, signal) => {
      signals.push(signal)
      return signals.length === 1 ? firstGate.promise : Promise.resolve({ mark: 'second' })
    },
  })
  const stale = session.validate(['users'])
  const fresh = session.validate(['rules'])
  assert.equal(signals[0]?.aborted, true, '新选择必须取消上一轮在途的整份备份上传')
  assert.equal(signals[1]?.aborted, false)
  assert.equal((await fresh).value.mark, 'second')
  firstGate.reject(new Error('aborted by supersede'))
  await assert.rejects(stale)
})

test('缓存按内容指纹隔离：换了一份备份后同分类集合必须重新校验', async () => {
  const sent: string[] = []
  const make = (fingerprint: string) => createImportPreviewSession<string>({
    fingerprint,
    send: async () => { sent.push(fingerprint); return fingerprint },
  })
  assert.equal((await make('fp-1').validate(['users'])).value, 'fp-1')
  assert.equal((await make('fp-2').validate(['users'])).value, 'fp-2')
  assert.deepEqual(sent, ['fp-1', 'fp-2'])
})

test('失败不入缓存：同分类集合可重试', async () => {
  let calls = 0
  const session = createImportPreviewSession<string>({
    fingerprint: 'fp-retry',
    send: async () => {
      calls++
      if (calls === 1) throw new Error('network')
      return 'ok'
    },
  })
  await assert.rejects(session.validate(['users']))
  assert.equal((await session.validate(['users'])).value, 'ok')
  assert.equal(calls, 2, '失败必须可重试')
})

test('dispose 取消在途请求（关闭弹框不再白传整份备份）', async () => {
  const gate = deferred<string>()
  const signals: AbortSignal[] = []
  const session = createImportPreviewSession<string>({
    fingerprint: 'fp-dispose',
    send: (_sections, requestSignal) => {
      signals.push(requestSignal)
      return gate.promise
    },
  })
  const pending = session.validate(['users'])
  session.dispose()
  assert.equal(signals[0]?.aborted, true)
  gate.reject(new Error('aborted by dispose'))
  await assert.rejects(pending)
})

test('内容指纹：采样内容 + 长度决定，同一内容稳定、不同内容分离', async () => {
  const content = new Blob(['{"version":3,"sections":[]}'])
  assert.equal(await importPreviewFingerprint(content), await importPreviewFingerprint(new Blob(['{"version":3,"sections":[]}'])))
  assert.notEqual(await importPreviewFingerprint(content), await importPreviewFingerprint(new Blob(['{"version":3,"sections":[1]}'])))
  assert.notEqual(await importPreviewFingerprint(content), await importPreviewFingerprint('{"version":3,"sections":[]}'.repeat(2)))
  // 字符串（JSON 备份）与 lbbak Blob 各自稳定：同一文本两次选择要到同一缓存键
  const text = '{"version":3}'
  assert.equal(await importPreviewFingerprint(text), await importPreviewFingerprint(text))
})

test('内容指纹只采样首尾（不把整份备份复制成第二个 ArrayBuffer）', async () => {
  const big = 'x'.repeat(4 * 1024 * 1024)
  const start = Date.now()
  await importPreviewFingerprint(new Blob([big]))
  assert.ok(Date.now() - start < 2000, '指纹必须是采样级开销，不能整份读入')
  // 采样边界的可观测形态：仅中段不同（首尾采样窗口相同、长度相同）→ 同一指纹
  // （缓存复用的是「同一份备份」；内容完整性由后端校验和负责）
  const head = 'a'.repeat(600 * 1024)
  const tail = 'z'.repeat(600 * 1024)
  const left = `${head}${'m'.repeat(2048)}${tail}`
  const right = `${head}${'n'.repeat(2048)}${tail}`
  assert.equal(await importPreviewFingerprint(left), await importPreviewFingerprint(right))
})

test('非安全上下文（无 crypto.subtle）同样可得指纹：HTTP 访问不影响选文件', async () => {
  // 面板常经 http://<host>:8000 访问——此时 crypto.subtle 不存在。
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, 'crypto')
  try {
    Object.defineProperty(globalThis, 'crypto', { value: {}, configurable: true, writable: true })
    assert.match(await importPreviewFingerprint(new Blob(['{"version":3}'])), /^fnv1a:/)
  } finally {
    if (descriptor) Object.defineProperty(globalThis, 'crypto', descriptor)
  }
})

test('缓存超过上限后淘汰最旧键，最新结果仍命中（长会话不无界增长）', async () => {
  // 缓存是模块级状态：查询串加载独立实例，避免受本文件其它用例已写入的键影响。
  const fresh = (await import(`../src/utils/importPreview.ts?evict=${Date.now()}`)) as typeof ImportPreviewModule
  let sends = 0
  const session = fresh.createImportPreviewSession<string>({
    fingerprint: 'fp-evict',
    send: async (sections) => { sends++; return sections.join(',') },
  })
  // 33 个不同分类组合 > 上限 32：最早的 k0 被淘汰
  for (let i = 0; i < 33; i++) {
    assert.equal((await session.validate([`k${i}`])).cached, false)
  }
  assert.equal((await session.validate(['k0'])).cached, false, '最旧键必须已淘汰（否则会话无界增长）')
  assert.equal((await session.validate(['k32'])).cached, true, '最新键必须仍在缓存（不得删最新）')
  // 重新插入的 k0 排到最新，淘汰顺延到 k1
  assert.equal((await session.validate(['k1'])).cached, false)
  assert.equal(sends, 35)
})

test('组件接线：预览经会话复用，请求带 abort signal，关闭/换文件即取消', () => {
  const page = code('src/views/settings/BasicSettings.vue')
  const preview = section(page, 'const postImportValidation', 'const revalidateImport')
  assert.match(preview, /signal/, '预览请求必须可被取消')
  assert.match(preview, /\?sections=/, '预览必须携带 sections query')
  assert.doesNotMatch(preview, /JSON\.parse/, '预览不得为注入 sections 重新序列化请求体')

  const revalidate = section(page, 'const revalidateImport', 'const confirmImport')
  assert.match(revalidate, /const session = importPreviewSession/, '分类切换必须走会话缓存/取消层')
  assert.match(revalidate, /session\.validate\(sections\)/)
  assert.doesNotMatch(revalidate, /postImportValidation\(sections\)/, '分类切换不得直接重传备份')

  const upload = section(page, 'const handleImportFile', 'const postImportValidation')
  assert.match(upload, /const fingerprint = await importPreviewFingerprint\(importFileContent\.value\)/, '会话键来自内容指纹')
  assert.match(upload, /createImportPreviewSession<ImportValidation>\(\{\s*fingerprint,/)

  const closed = section(page, 'const onImportDialogClosed', 'const chooseImportFile')
  assert.match(closed, /importPreviewSession\?\.dispose\(\)/, '关闭弹框必须取消在途上传')
  assert.match(closed, /importPreviewSession = null/)
})

// 缓存时效：预览事实依赖服务端「当时」的库状态，跨会话常驻会让同一份备份在
// 配置改变后仍返回旧预览（例如刚删掉一个 CA 提供商，预览却说无悬挂告警）。
test('缓存有 TTL：超过有效期必须重新校验', async () => {
  const realNow = Date.now
  let now = 1_000_000
  Date.now = () => now
  try {
    const sent: string[] = []
    const session = createImportPreviewSession<string>({
      fingerprint: 'fp-ttl',
      send: async () => { sent.push('x'); return 'v' },
    })
    assert.equal((await session.validate(['users'])).cached, false)
    now += 4 * 60 * 1000
    assert.equal((await session.validate(['users'])).cached, true, '有效期内仍可复用')
    now += 2 * 60 * 1000
    assert.equal((await session.validate(['users'])).cached, false, '过期条目必须重新校验')
    assert.equal(sent.length, 2)
  } finally {
    Date.now = realNow
  }
})

test('invalidateImportPreviews 清空跨会话缓存，且弹框打开时调用它', async () => {
  const sent: string[] = []
  const session = createImportPreviewSession<string>({
    fingerprint: 'fp-invalidate',
    send: async () => { sent.push('x'); return 'v' },
  })
  await session.validate(['users'])
  assert.equal((await session.validate(['users'])).cached, true)
  invalidateImportPreviews()
  assert.equal((await session.validate(['users'])).cached, false)
  assert.equal(sent.length, 2)

  const page = code('src/views/settings/BasicSettings.vue')
  const trigger = section(page, 'const triggerImport = (): void =>', 'const onImportDialogClosed')
  assert.match(trigger, /invalidateImportPreviews\(\)/, '打开导入弹框必须清空预览缓存')
})
