import { test } from 'node:test'
import assert from 'node:assert/strict'

import { buildCaddyConfigPayload } from '../src/utils/caddyConfigPayload.ts'
import { section, source } from './_helpers.ts'

// 关闭「自定义 JSON」时后端的跨字段门（internal/handlers/caddy.go
// resolveAccessLogFormatGate）：json=false 且请求显式携带非空格式 → 400；
// json=false + 缺键 + 存量非空 → 清空存量并说明。前端必须走后者，否则保存
// 在预览阶段就被 400 阻断（而清空输入框已随开关隐藏）。

const KEYS = ['caddy_log_level', 'access_log_json', 'access_log_format'] as const

test('关闭且存量格式非空：格式键从载荷剔除，并标记库中映射将被清空', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'info', access_log_json: false, access_log_format: 'request>method -> m' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, true)
  assert.deepEqual(Object.keys(payload), ['caddy_log_level', 'access_log_json'], '载荷不得携带格式键')
  assert.equal(payload.access_log_format, undefined)
  assert.equal(payload.access_log_json, false)
})

test('纯空白格式同样剔除（后端按「存量非空」清空，提交空白会被判显式非空）', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'info', access_log_json: false, access_log_format: '   ' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, true)
  assert.equal('access_log_format' in payload, false)
})

test('开启自定义 JSON：格式原样提交，无清空语义', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'info', access_log_json: true, access_log_format: 'request>method -> m' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, false)
  assert.equal(payload.access_log_format, 'request>method -> m')
})

test('关闭且存量格式为空：键照常提交（空串不触发后端门）', () => {
  const { payload, accessLogFormatCleared } = buildCaddyConfigPayload(
    { caddy_log_level: 'warn', access_log_json: false, access_log_format: '' },
    KEYS,
  )
  assert.equal(accessLogFormatCleared, false)
  assert.equal(payload.access_log_format, '')
})

test('白名单外的键不会泄露进载荷（兄弟卡片未保存编辑不得连带提交）', () => {
  const settings = { caddy_log_level: 'info', access_log_json: true, access_log_format: '', acme_email: 'a@b.c' }
  const { payload } = buildCaddyConfigPayload(settings, KEYS)
  assert.deepEqual(Object.keys(payload).sort(), [...KEYS].sort())
})

test('视图消费单源：载荷经统一组装，清空语义进确认框且与开关提示同口径', () => {
  const card = source('src/views/settings/CaddyGlobalSettings.vue')
  const save = section(card, 'const handleSave = async', 'const handleReloadCaddy')
  assert.match(save, /buildCaddyConfigPayload\(settings\.value, CADDY_CONFIG_KEYS\)/)
  assert.doesNotMatch(save, /Object\.fromEntries\(CADDY_CONFIG_KEYS/, '不得保留第二处白名单展开')
  assert.match(save, /accessLogFormatCleared/, '确认框必须消费清空标记')
  assert.match(save, /库中自定义字段映射将被清空/)
  assert.match(card, /关闭后保存会清空已配置的自定义字段映射/, '开关提示与确认框同口径')
})
