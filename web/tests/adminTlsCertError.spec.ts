// 管理面板 HTTPS 证书损坏态的 fail-visible 契约：后端以 cert_info_error 显式
// 申报「库内证书不可读」，前端必须消费——否则带外改库/旧版本导入造成的损坏
// 证书在界面上与「未配置证书」无法区分（用户只看到开关开启却查无信息）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

test('/admin-tls 响应类型声明 cert_info_error', () => {
  const api = source('src/utils/api.ts')
  assert.match(api, /cert_info_error\?: string/, 'API 类型必须声明 fail-visible 字段')
})

test('设置页消费 cert_info_error 并渲染错误条', () => {
  const page = source('src/views/settings/BasicSettings.vue')
  assert.match(page, /const adminTlsCertError = ref\(''\)/)
  assert.match(page, /adminTlsCertError\.value = res\.data\.cert_info_error \|\| ''/, '读取时必须从响应取值')

  // 仅 upload 模式的存量证书可能损坏（selfsigned 由 ResolveCertificate 自愈），
  // 以已保存的 mode 判定，不受弹框内未提交切换影响。
  assert.match(
    page,
    /const adminTlsCertBroken = computed\(\(\) => adminTlsSaved\.value\.mode === 'upload' && adminTlsCertError\.value !== ''\)/,
  )

  // 错误条复用全局 info-note-bar（禁止局部 :deep 或重定义全局类）。
  const bar = section(page, 'v-if="adminTlsCertBroken"', '</div>')
  assert.match(bar, /class="info-note-bar"/)
  assert.match(bar, /adminTlsCertError/)
  assert.match(bar, /重新上传/, '须给出修复指引')
})

test('日志统计条消费 rows_unavailable：保持条数口径并标注不可用', () => {
  const bar = source('src/components/LogStorageBar.vue')
  assert.match(bar, /rows_unavailable\?: boolean/, '响应字段类型必须声明')
  assert.match(bar, /const rowsUnavailable = computed/, '必须显式判定不可用态')
  const sizeText = section(bar, 'const sizeText = computed(', '\n})\n')
  assert.match(sizeText, /计数暂不可用 \/ /, '行数缺席时保持条数口径文案')
  assert.doesNotMatch(
    section(bar, 'const sizeText = computed(', '\n})\n'),
    /if \(i\.limit_rows && i\.rows != null\)/,
    '不得在行数缺席时滑回字节口径',
  )
  const noteText = section(bar, 'const noteText = computed(', '\n})\n')
  assert.match(noteText, /行数暂不可用/, '附注必须披露计数不可用')
})
