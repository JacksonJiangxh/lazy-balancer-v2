// CA 选择器选项口径单源验收：启用项 ∪ 当前值（已禁用项回显且不可新选），
// 规则向导与免费证书全局默认同口径。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { source } from './_helpers.ts'
import { caProviderOptionLabel, selectableCAProviders } from '../src/utils/caProviderOptions.ts'

const providers = [
  { id: 1, name: 'ZeroSSL', enabled: true },
  { id: 2, name: '旧 CA', enabled: false },
  { id: 3, name: '公益 CA', enabled: true },
]

test('选项集=启用项 ∪ 当前值；其余禁用项不出现', () => {
  assert.deepEqual(selectableCAProviders(providers, 0).map((p) => p.id), [1, 3])
  assert.deepEqual(selectableCAProviders(providers, 2).map((p) => p.id), [1, 2, 3], '存量指向已禁用 CA 必须回显')
  assert.deepEqual(selectableCAProviders([], 2), [])
})

test('已禁用回显项标注「（已禁用）」', () => {
  assert.equal(caProviderOptionLabel(providers[0]), 'ZeroSSL')
  assert.equal(caProviderOptionLabel(providers[1]), '旧 CA（已禁用）')
})

test('两个消费视图均走共享 helper（不得各自 filter(p => p.enabled)）', () => {
  for (const path of ['src/views/Rules.vue', 'src/views/settings/FreeCertificates.vue']) {
    const text = source(path)
    assert.match(text, /from '@\/utils\/caProviderOptions'/, `${path} 未接入单源`)
    assert.match(text, /caProviderOptionLabel\(p\)/)
    assert.match(text, /:disabled="!p\.enabled"/, `${path} 已禁用项必须不可新选`)
    assert.doesNotMatch(text, /filter\(p => p\.enabled\)/, `${path} 裸过滤口径不得回流`)
  }
})
