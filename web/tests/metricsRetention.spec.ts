// metrics 治理三键（metrics_history_retention_days / lb_l4_conn_retention_days /
// metrics_max_bytes）表单契约钉：0=禁用为合法库值，展示与载荷都不得归一/钳制。
// 运行：cd web && npm test -- tests/metricsRetention.spec.ts

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code } from './_helpers.ts'

const vue = code('src/views/settings/BasicSettings.vue')
const settingsVue = code('src/views/Settings.vue')
const types = code('src/types/index.ts')

test('默认值：Settings.vue 初始值与回填默认均为 7/7/0，types 声明三键', () => {
  assert.match(settingsVue, /metrics_history_retention_days:\s*7/, '初始默认应为 7')
  assert.match(settingsVue, /lb_l4_conn_retention_days:\s*7/, '初始默认应为 7')
  assert.match(settingsVue, /metrics_max_bytes:\s*0/, '初始默认应为 0（禁用）')
  assert.match(settingsVue, /metrics_history_retention_days = data\.metrics_history_retention_days \?\? 7/, '回填默认 7')
  assert.match(settingsVue, /lb_l4_conn_retention_days = data\.lb_l4_conn_retention_days \?\? 7/, '回填默认 7')
  assert.match(settingsVue, /metrics_max_bytes = data\.metrics_max_bytes \?\? 0/, '回填默认 0')
  assert.match(types, /metrics_history_retention_days:\s*number/)
  assert.match(types, /lb_l4_conn_retention_days:\s*number/)
  assert.match(types, /metrics_max_bytes:\s*number/)
})

test('表单：三输入项存在，保留天数允许 0（禁用），硬上限允许 0', () => {
  assert.match(vue, /v-model="settings\.metrics_history_retention_days"[^>]*:min="0"/, '保留天数 0=禁用 必须可输入')
  assert.match(vue, /v-model="settings\.lb_l4_conn_retention_days"[^>]*:min="0"/, 'L4 保留天数 0=禁用 必须可输入')
  assert.match(vue, /v-model="metricsMaxBytes"[^>]*:min="0"/, '硬上限 0=禁用 必须可输入')
})

test('非法值：保留天数非负（min=0 挡负数）；载荷无条件提交三键（0 原样提交）', () => {
  assert.doesNotMatch(vue, /v-model="settings\.metrics_history_retention_days"[^>]*:min="-1"/, '不得出现负下限')
  assert.match(
    vue,
    /metrics_history_retention_days:\s*settings\.value\.metrics_history_retention_days \?\? 7/,
    '载荷必须携带 metrics_history_retention_days（0 原样提交，不做脏检查省略）',
  )
  assert.match(
    vue,
    /lb_l4_conn_retention_days:\s*settings\.value\.lb_l4_conn_retention_days \?\? 7/,
    '载荷必须携带 lb_l4_conn_retention_days',
  )
  assert.match(
    vue,
    /metrics_max_bytes:\s*settings\.value\.metrics_max_bytes \?\? 0/,
    '载荷必须携带 metrics_max_bytes',
  )
})
