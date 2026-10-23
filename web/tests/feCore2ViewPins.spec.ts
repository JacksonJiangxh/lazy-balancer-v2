// 首页/任务监控的三处视图缺陷：
//   - 状态码列注释承诺「超高换行兜底」，样式却是 nowrap + overflow:hidden，
//     百万级流量时末尾 Block badge 被静默裁掉（安全拦截看起来为 0）；
//   - 「24h 失败」KPI 在只读态挂 Lock 图标，被读成「失败数被锁定」；
//   - 规则健康查询用布尔门直接丢弃在途期间的新版本需求，旧响应又被版本守卫
//     丢弃 → 新规则集整轮健康列陈旧且无提示。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

test('状态码列超高时换行，不裁掉 Block badge', () => {
  const page = source('src/views/Dashboard.vue')
  const rules = section(page, '.status-codes {', '}')
  assert.match(rules, /flex-wrap: wrap/, '必须与列注释承诺的换行兜底一致')
  assert.doesNotMatch(rules, /nowrap/, 'nowrap 会让 flex-shrink:0 的 badge 溢出')
  assert.doesNotMatch(rules, /overflow: hidden/, 'overflow:hidden 静默裁掉末尾 badge（含 title 不可达）')
  assert.match(page, /class="status-code status-blocked"/, 'Block badge 必须仍在列内')
})

test('24h 失败 KPI 不再挂只读锁图标', () => {
  const page = source('src/views/settings/TaskMonitor.vue')
  const label = section(page, '<div class="tm-kpi-num" :class="{ \'tm-kpi-bad\': fail24h > 0 }">', '</el-card>')
  assert.doesNotMatch(label, /Lock/, '只读语义由操作列禁用与错误横幅承载，不在单个 KPI 上暗示数据受限')
  assert.doesNotMatch(page, /tm-kpi-lock/, '配套样式属死样式')
  // Lock 仍被证书队列横幅与详情图标消费——不得连带删除 import
  assert.match(page, /<el-icon class="title-icon"><Lock \/><\/el-icon>/)
  assert.match(page, /category === '证书' \? Lock/)
})

test('规则健康查询在途时记录新版本需求并在收尾补跑', () => {
  const page = source('src/views/Dashboard.vue')
  assert.match(page, /let ruleHealthInFlight = false/)
  assert.doesNotMatch(page, /isFetchingRuleHealth/, '布尔门已退役')
  const fetchHealth = section(page, 'const fetchRuleHealth = async', 'const controlCaddy')
  assert.doesNotMatch(
    fetchHealth.split('\n')[1] ?? '',
    /isFetchingRuleHealth/,
    '入口不得再以在途标记直接丢弃需求',
  )
  assert.match(fetchHealth, /if \(ruleHealthInFlight\) \{/, '在途分支必须显式处理新需求')
  assert.match(fetchHealth, /pendingRuleHealth = \{ rules: currentRules, version \}/, '只保留最新需求')
  assert.match(fetchHealth, /pendingRuleHealth\.version < version/, '更旧的需求不得覆盖更新版本')
  const replay = section(fetchHealth, '} finally {', '\n  }\n}')
  assert.match(replay, /await fetchRuleHealth\(pending\.rules, pending\.version\)/, '收尾补跑被丢弃的版本')
  assert.match(replay, /pending\.version !== version/, '同一版本无需重跑（在途那轮已覆盖）')
  // 补跑不得沿用旧轮次 signal（上一轮可能已 abort）
  assert.doesNotMatch(replay, /roundSignal/, '补跑必须回落页级永久 signal')
})
