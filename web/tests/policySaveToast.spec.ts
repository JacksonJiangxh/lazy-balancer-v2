// 策略保存的成功提示只弹一条：原实现在阶段拦截页覆盖同步后先弹「已同步 N 条…」，
// 紧接着 showSaveResult 又弹「保存成功」——两条 toast 叠加。合并后同步数作为后缀
// 附在保存结果消息后（服务端 message 优先，Caddy 应用失败后缀判定不受影响）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, code } from './_helpers.ts'

const page = code('src/views/security/SecurityPolicies.vue')

test('策略保存：同步条数并入唯一的成功提示，不再叠加第二条 toast', () => {
  const save = section(page, 'let pendingOverrides = pendingOverrideRules.value', 'const mergedBind = mergeBulkResults(')
  assert.doesNotMatch(save, /mfaAwareSuccess\(`已同步/, '不得再单独弹同步成功 toast')
  assert.match(save, /let syncedCount = 0/)
  assert.match(save, /syncedCount = pendingOverrides\.length - skippedNotes\.length/)
  assert.match(save, /syncedCount > 0 \? `\$\{saveMessage\}，已同步 \$\{syncedCount\} 条规则的阶段拦截页覆盖` : saveMessage/)
  assert.equal(save.match(/showSaveResult\(/g)?.length, 1, '保存结果只调一次 showSaveResult（Caddy 应用失败后缀的独立警告在切片之外）')
})
