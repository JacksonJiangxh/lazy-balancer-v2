// file 模式证书「路径引用语义」契约钉测（JJC-20261125-001 子任务 5）：
// 后端语义变更——tls_source='file' 从「保存时摄取 PEM 内容入库」改为
// 「数据库只存 tls_cert_path/tls_key_path 路径，运行时按路径读文件」。
// 前端同步口径：
//   A. file 模式表单：两个路径输入框 required（非空门），无任何 PEM 内容输入；
//      文案不得残留「入库」类旧语义。
//   B. 保存门（TLS 步 nextStep + submitWizard 兜底镜像）：file 模式两路径
//      非空必校验。
//   C. 列表/预览对 file 行展示路径而非内容摘要，标签「引用文件」。
//   D. manual 模式（粘贴 PEM）语义不变。
//
// 运行：cd web && node --test tests/ruleFileSourceCertPath.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { code, section, source } from './_helpers.ts'

const rawPage = source('src/views/Rules.vue')
const page = code('src/views/Rules.vue')

// file 模式表单块：从 file 分支 template 起点到 manual 分支（v-else）template
const fileFormBlock = section(
  rawPage,
  '<template v-else-if="wizardForm.tls_source === \'file\'">',
  '<template v-else>',
)

test('A1 file 模式表单：证书/私钥两个路径输入框均 required（非空门在 UI 层可见）', () => {
  assert.match(fileFormBlock, /<el-form-item label="证书文件" required>/, '证书文件路径输入框须 required')
  assert.match(fileFormBlock, /<el-form-item label="私钥文件" required>/, '私钥文件路径输入框须 required')
  assert.match(fileFormBlock, /v-model="wizardForm\.tls_cert_path"/, '证书文件输入绑定 tls_cert_path')
  assert.match(fileFormBlock, /v-model="wizardForm\.tls_key_path"/, '私钥文件输入绑定 tls_key_path')
})

test('A2 file 模式表单不再有任何 PEM 内容输入（textarea/从文件粘贴仅属 manual 块）', () => {
  assert.ok(!fileFormBlock.includes('textarea'), 'file 块内不得出现 PEM 内容 textarea')
  assert.ok(!fileFormBlock.includes('从文件粘贴'), '「从文件粘贴」属 manual 语义，不得出现在 file 块')
})

test('A3 file 模式文案不得残留「入库」类旧语义（内容入库=已废除的摄取语义）', () => {
  assert.ok(!fileFormBlock.includes('入库'), 'file 表单块内不得出现「入库」文案——数据库只存路径，运行时读文件')
  assert.match(fileFormBlock, /运行时按此路径读取/, 'file 文案须传达「运行时按路径读取」新语义')
})

// B1：TLS 步进门——从 TLS 步 marker 切到其后首个 moveToAdjacentWizardStep(1)
const tlsStep = section(
  rawPage,
  'if (currentStep.value === WIZARD_STEP.TLS) {',
  'moveToAdjacentWizardStep(1)',
)

test('B1 保存门：TLS 步 nextStep 校验 file 模式两路径非空', () => {
  assert.match(
    tlsStep,
    /if \(wizardForm\.tls_source === 'file' && \(!wizardForm\.tls_cert_path\.trim\(\) \|\| !wizardForm\.tls_key_path\.trim\(\)\)\)/,
    'TLS 步进门须校验 file 模式两路径均非空',
  )
  assert.match(tlsStep, /请填写证书文件与私钥文件路径/, 'TLS 步进门须给出路径必填提示')
})

// B2：submitWizard 兜底镜像——TLS 步校验镜像注释起到上游列表门止（都是代码，走剥注释视图）
const mirror = section(
  page,
  'if (wizardForm.enable_tls && wizardForm.protocol === \'http\') {',
  'if (wizardForm.protocol !== \'passthrough\' && wizardForm.upstreams.length === 0)',
)

test('B2 保存门：submitWizard 兜底镜像同样校验 file 模式两路径非空', () => {
  assert.match(
    mirror,
    /if \(wizardForm\.tls_source === 'file' && \(!wizardForm\.tls_cert_path\?\.trim\(\) \|\| !wizardForm\.tls_key_path\?\.trim\(\)\)\)/,
    'submitWizard 兜底镜像须校验 file 模式两路径均非空',
  )
  assert.match(mirror, /引用证书文件模式须填写证书与私钥文件路径/, '兜底镜像须给出路径必填提示')
})

test('C1 向导预览对 file 行展示路径（cert-preview-info 绑定 tls_cert_path）', () => {
  assert.match(
    rawPage,
    /cert-preview-info">\{\{ wizardForm\.tls_cert_path \|\| '未填写证书文件' \}\}/,
    '预览须直接展示证书文件路径',
  )
})

test('C2 列表 TLS 标签对 file 行显示「引用文件」（不复用「手动」标签）', () => {
  assert.doesNotMatch(
    page,
    /return row\.tls_source === 'acme_dns' \? '已签发' : '手动'$/,
    'tlsTagLabel 不得对 file 行回落「手动」标签',
  )
  assert.match(page, /'引用文件' : '手动'/, 'file 行标签须为「引用文件」')
})

test('D manual 模式（粘贴 PEM）语义不变：textarea、blur 解析、tlsKeySet 掩码豁免俱在', () => {
  assert.match(page, /v-model="wizardForm\.tls_cert"/, 'manual 证书 PEM 输入绑定保留')
  assert.match(page, /type="textarea"/, 'manual 模式 textarea 保留')
  assert.match(page, /@blur="validateCertificate"/, 'manual 模式 blur 解析保留')
  assert.match(page, /tlsKeySet && !wizardForm\.tls_key\.trim/, 'manual 模式掩码私钥豁免保留')
  // 保存门 manual 分支未动
  assert.match(
    page,
    /wizardForm\.tls_source === 'manual' && \(!wizardForm\.tls_cert\.trim\(\) \|\| \(!wizardForm\.tls_key\.trim\(\) && !wizardForm\.tlsKeySet\)\)/,
    'manual 模式保存门条件保持原状',
  )
})
