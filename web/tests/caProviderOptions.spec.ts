// 引用型下拉选项口径单源验收：启用项 ∪ 当前值（已禁用项回显且不可新选），
// 规则向导的 CA 提供商 / DNS 配置与免费证书全局默认同口径。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { source } from './_helpers.ts'
import { referencedOptionLabel, selectableReferencedOptions } from '../src/utils/caProviderOptions.ts'

const options = [
  { id: 1, name: 'ZeroSSL', enabled: true },
  { id: 2, name: '旧项', enabled: false },
  { id: 3, name: '公益 CA', enabled: true },
]

test('选项集=启用项 ∪ 当前值；其余禁用项不出现', () => {
  assert.deepEqual(selectableReferencedOptions(options, 0).map((p) => p.id), [1, 3])
  assert.deepEqual(selectableReferencedOptions(options, 2).map((p) => p.id), [1, 2, 3], '存量指向已禁用项必须回显')
  assert.deepEqual(selectableReferencedOptions([], 2), [])
})

test('已禁用回显项标注「（已禁用）」', () => {
  assert.equal(referencedOptionLabel(options[0]), 'ZeroSSL')
  assert.equal(referencedOptionLabel(options[1]), '旧项（已禁用）')
})

test('消费视图均走共享 helper（不得各自 filter(x => x.enabled)）', () => {
  for (const path of ['src/views/Rules.vue', 'src/views/settings/FreeCertificates.vue']) {
    const text = source(path)
    assert.match(text, /from '@\/utils\/caProviderOptions'/, `${path} 未接入单源`)
    assert.match(text, /referencedOptionLabel\(/)
    assert.match(text, /:disabled="!p\.enabled"/, `${path} 已禁用项必须不可新选`)
    assert.doesNotMatch(text, /filter\(p => p\.enabled\)/, `${path} 裸过滤口径不得回流`)
  }
})

test('向导的 DNS 配置下拉与 CA 下拉同口径（启用 ∪ 当前值 + 禁用标注）', () => {
  const rules = source('src/views/Rules.vue')
  assert.match(rules, /selectableReferencedOptions\(certConfigs\.value, Number\(wizardForm\.acme_config_id \|\| 0\)\)/)
  assert.match(rules, /v-for="cfg in wizardCertConfigOptions"[\s\S]*?:disabled="!cfg\.enabled"/)
  assert.doesNotMatch(rules, /v-for="cfg in certConfigs"/, 'DNS 配置下拉不得回退为全量渲染')
})
