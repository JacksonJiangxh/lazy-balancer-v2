// 安全规则/名单的写侧门与前端单源对表：
//   A. 自定义规则条件数 64 / pattern 4KiB（UTF-8 字节）——前端两值必须与 Go 常量同值
//   B. 名单详情失败态：保存与条目增删/导入同门；重试覆盖前须确认未保存条目
//   C. 内置自动封禁名单全量 PUT 前的新鲜度差集（期间新增条目点名）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  CUSTOM_RULE_MAX_CONDITIONS,
  CUSTOM_RULE_MAX_PATTERN_BYTES,
  canAddCondition,
  patternByteLength,
  patternOverLimit,
} from '../src/utils/customRuleLimits.ts'
import { entriesMissingFromPayload } from '../src/utils/ipListSaveGuard.ts'
import { code, repoCode, section } from './_helpers.ts'

const securityGo = repoCode('internal/services/security.go')
const page = code('src/views/security/SecurityRules.vue')

test('条件数/pattern 上限与 Go 写侧门同值（改门即红）', () => {
  const conditions = /customRuleMaxConditions = (\d+)/.exec(securityGo)
  assert.ok(conditions, '后端缺 customRuleMaxConditions')
  assert.equal(CUSTOM_RULE_MAX_CONDITIONS, Number(conditions[1]), '条件数上限漂移')

  const patternBytes = /customRuleMaxPatternBytes = (\d+) << (\d+)/.exec(securityGo)
  assert.ok(patternBytes, '后端缺 customRuleMaxPatternBytes')
  assert.equal(CUSTOM_RULE_MAX_PATTERN_BYTES, Number(patternBytes[1]) * 2 ** Number(patternBytes[2]), 'pattern 字节上限漂移')
})

test('pattern 上限按 UTF-8 字节求值（字符计数看不出中文超限）', () => {
  assert.equal(patternByteLength('abc'), 3)
  assert.equal(patternByteLength('中'), 3, '中日韩字符 3 字节')
  assert.equal(patternByteLength(''), 0)

  assert.equal(patternOverLimit('a'.repeat(CUSTOM_RULE_MAX_PATTERN_BYTES)), false, '恰好到上限放行')
  assert.equal(patternOverLimit('a'.repeat(CUSTOM_RULE_MAX_PATTERN_BYTES + 1)), true)
  // 字符数远小于上限、字节数超限：只有字节口径能拦住
  const cjk = '中'.repeat(Math.ceil(CUSTOM_RULE_MAX_PATTERN_BYTES / 3) + 1)
  assert.ok(cjk.length < CUSTOM_RULE_MAX_PATTERN_BYTES, '前提：字符数没超')
  assert.equal(patternOverLimit(cjk), true, '字节超限必须拦截')

  assert.equal(canAddCondition(CUSTOM_RULE_MAX_CONDITIONS - 1), true)
  assert.equal(canAddCondition(CUSTOM_RULE_MAX_CONDITIONS), false, '满额后不得再加')
})

test('自定义规则弹框消费同一上限（加条件按钮/字段级字节提示/保存前拦截）', () => {
  assert.match(page, /import \{ CUSTOM_RULE_MAX_CONDITIONS, CUSTOM_RULE_MAX_PATTERN_BYTES, canAddCondition, patternByteLength, patternOverLimit \} from '@\/utils\/customRuleLimits'/)
  assert.match(page, /:disabled="!canAddCondition\(ruleForm\.conditions\.length\)"/, '满额必须禁用「+ 添加条件」')
  assert.match(page, /\{\{ ruleForm\.conditions\.length \}\}\/\{\{ CUSTOM_RULE_MAX_CONDITIONS \}\}/, '条件行数须可见')
  const patternRow = section(page, 'class="pattern-col"', 'cond.target === \'user_agent\'')
  assert.match(patternRow, /patternOverLimit\(cond\.pattern\)/, '字段级字节提示与红框同谓词')

  const save = section(page, 'const saveCustomRule = async', 'const deletingCustomRuleId')
  const countGate = save.indexOf('ruleForm.value.conditions.length > CUSTOM_RULE_MAX_CONDITIONS')
  const loop = save.indexOf('for (const cond of ruleForm.value.conditions)')
  assert.ok(countGate > 0 && countGate < loop, '条件数门必须先于逐条校验')
  assert.match(save, /if \(patternOverLimit\(cond\.pattern\)\) \{/, '保存前必须有字节门（后端 400 前置）')
})

test('名单详情失败态与保存同门：条目录入/导入一并禁用', () => {
  assert.match(page, /:disabled="ipListDetailFailed" @click="addIpListEntry"/, '失败态仍可加条目会被重试覆盖')
  assert.match(page, /:disabled="ipListDetailFailed" @click="triggerImportEntries"/, '失败态导入同样会被重试覆盖')
  assert.match(page, /保存与条目增删\/导入已禁用/, '横幅必须说明禁用范围')
})

test('名单重试覆盖前确认未保存条目，成功后提示已加载', () => {
  const reload = section(page, 'const reloadIpListDetail = async', 'const saveIpList = async')
  const confirm = reload.indexOf('重新加载将用服务端条目覆盖当前')
  const assign = reload.indexOf('ipListForm.value.entries = (res.data?.entries')
  assert.ok(confirm > 0 && assign > confirm, '覆盖前必须确认（含未保存条目）')
  assert.match(reload, /ElMessage\.success\('已加载最新条目'\)/)
})

test('自动封禁名单保存前做新鲜度差集（期间新增条目不得被静默解封）', () => {
  // 差集行为：服务端有、载荷无 → 列出；大小写/空白归一；重复只报一次
  assert.deepEqual(
    entriesMissingFromPayload(['1.1.1.1', '2.2.2.2', '3.3.3.3'], [' 1.1.1.1 ', '3.3.3.3']),
    ['2.2.2.2'],
  )
  assert.deepEqual(entriesMissingFromPayload(['::1'], []), ['::1'])
  assert.deepEqual(entriesMissingFromPayload(['1.1.1.1', '1.1.1.1'], []), ['1.1.1.1'], '重复值只报一次')
  assert.deepEqual(entriesMissingFromPayload(['1.1.1.1'], ['1.1.1.1', '9.9.9.9']), [], '载荷多出的条目不算移除')

  // 接线：仅内置名单、仅已有 id；重取详情失败也要确认（不能假装安全）
  const save = section(page, 'const saveIpList = async', 'const deletingIpListId')
  assert.match(save, /if \(editingIpListPreset\.value && editingIpListId\.value\) \{/)
  assert.match(save, /confirmAutobanFreshness\(editingIpListId\.value, entries\.map\(\(e\) => e\.value\)\)/)
  const helper = section(page, 'const confirmAutobanFreshness', 'const saveIpList = async')
  assert.match(helper, /entriesMissingFromPayload\(/)
  assert.match(helper, /会将这些新条目一并移除（即刻解封）/, '确认文案必须点名后果')
  assert.match(helper, /无法核对打开弹框后是否有任务新增封禁条目/, '核对失败同样要确认')
})
