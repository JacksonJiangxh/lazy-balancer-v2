// 安全事件动作文案单源（utils/eventAction）行为 + 四处消费接线。
//
// 原四处独立映射且措辞互斥（拦截/检测、已拦截/已记录、已拦截/仅检测、
// 已拦截/已记录（检测））：同一事件在列表→请求详情→大屏→触发详情要读者自行
// 翻译。行为断言落在纯函数上，接线断言落在各视图的调用点。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { eventActionFull, eventActionShort, eventActionTone } from '../src/utils/eventAction.ts'
import { code } from './_helpers.ts'

test('动作文案：两值枚举的短/全长标签与色调', () => {
  assert.equal(eventActionShort('blocked'), '拦截')
  assert.equal(eventActionShort('logged'), '检测')
  assert.equal(eventActionFull('blocked'), '已拦截')
  assert.equal(eventActionFull('logged'), '已记录')
  assert.equal(eventActionTone('blocked'), 'danger')
  assert.equal(eventActionTone('logged'), 'warning')
})

test('未知动作 fail-visible：原样回显，不回落到「检测」', () => {
  assert.equal(eventActionShort('throttled'), 'throttled')
  assert.equal(eventActionFull('throttled'), 'throttled')
  assert.equal(eventActionShort(''), '—')
  assert.equal(eventActionFull(null), '—')
  assert.equal(eventActionTone(undefined), 'warning', '未知动作按未拦截色调渲染')
})

test('四个视图共用单源映射，本地副本已删除', () => {
  const screen = code('src/views/security/ThreatScreen.vue')
  assert.match(screen, /from '@\/utils\/eventAction'/)
  assert.match(screen, /eventActionFull\(t\.action\)/, '大屏告警弹框使用全长标签')
  assert.match(screen, /eventActionShort\(event\.action\)/, '事件流紧凑位使用短标签')
  assert.doesNotMatch(screen, /function actionLabel/, '本地映射函数必须删除')

  const events = code('src/views/security/SecurityEvents.vue')
  assert.match(events, /from '@\/utils\/eventAction'/)
  assert.match(events, /eventActionShort\(row\.action\)/)
  assert.match(events, /eventActionFull\(ctxEvent\.action\)/)
  assert.doesNotMatch(events, /row\.action === 'blocked' \? '拦截' : '检测'/, '列表本地三元必须退役')

  const trigger = code('src/components/events/TriggerDetailDialog.vue')
  assert.match(trigger, /from '@\/utils\/eventAction'/)
  assert.match(trigger, /eventActionFull\(row\?\.action\)/)
  assert.doesNotMatch(trigger, /已记录（检测）/, '第四份措辞必须退役')
})
