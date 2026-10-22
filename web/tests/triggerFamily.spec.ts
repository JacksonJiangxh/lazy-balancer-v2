// 触发 id → 阶段族映射行为验收：逐项对照后端 v2.3.8 权威分类
//   internal/handlers/security.go attackFamilyClassOf（ID 形态）
//   internal/handlers/security_threat_screen.go triggerTypeForRule（数值段）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { detectionModeExplains, triggerStageFamily, type TriggerStageFamily } from '../src/utils/securityStages.ts'
import { repoSource, section } from './_helpers.ts'

const cases: ReadonlyArray<readonly [string, TriggerStageFamily]> = [
  // 空 / 请求体异常 / 威胁情报 / 信任
  ['', 'other'],
  ['11', 'body'],
  ['14', 'threat'],
  ['3', 'trust'],
  ['12', 'trust'],
  // 自定义规则：5 位任意（含 9 开头——5 位恒自定义，CRS 恒 6 位）
  ['10000', 'wafCustom'],
  ['12345', 'wafCustom'],
  ['92000', 'wafCustom'],
  ['99999', 'wafCustom'],
  // 自定义规则：6 位 1-7 开头（DB id 10000-789999 发射 id+10000）——原实现落 other
  ['100000', 'wafCustom'],
  ['499999', 'wafCustom'],
  ['700000', 'wafCustom'],
  ['799999', 'wafCustom'],
  // 自定义规则：≥7 位 1 开头（无 id 规则合成 1000000+n）
  ['1000000', 'wafCustom'],
  ['1999999', 'wafCustom'],
  // CRS：6 位 9 开头
  ['900000', 'wafCrs'],
  ['942100', 'wafCrs'],
  ['959999', 'wafCrs'],
  // 地域 [800000,810000)
  ['800000', 'geoip'],
  ['800012', 'geoip'],
  ['809999', 'geoip'],
  // 爬虫两族 [810000,900000)：豁免 / 伪装——原实现误归 geoip
  ['810000', 'crawler'],
  ['825000', 'crawler'],
  ['849999', 'crawler'],
  ['850000', 'crawler'],
  ['899999', 'crawler'],
  // IP 访问控制
  // （有意设计登记）：'8' 与后端 attackFamilyClassOf（8→GeoIP）不同——
  // 历史共享 id，现代引擎地域事件改发 800xxx，本例外无现实影响且被刻意钉住。
  ['2', 'ipAcl'],
  ['4', 'ipAcl'],
  ['5', 'ipAcl'],
  ['7', 'ipAcl'],
  ['8', 'ipAcl'],
  // 其他（429 限流在列表层单独处理，非阶段族）
  ['429', 'other'],
  ['abc', 'other'],
]

test('triggerStageFamily 与后端权威分类逐项一致', () => {
  for (const [id, expected] of cases) {
    assert.equal(triggerStageFamily(id), expected, `id=${JSON.stringify(id)}`)
  }
})

test('爬虫段与地域段互斥（不重叠）', () => {
  // 边界：809999 地域 / 810000 爬虫 / 899999 爬虫 / 900000 CRS
  assert.equal(triggerStageFamily('809999'), 'geoip')
  assert.equal(triggerStageFamily('810000'), 'crawler')
  assert.equal(triggerStageFamily('899999'), 'crawler')
  assert.equal(triggerStageFamily('900000'), 'wafCrs')
})

test('首尾空白归一（事件字段可能带导入残留空白）', () => {
  assert.equal(triggerStageFamily(' 11 '), 'body')
  assert.equal(triggerStageFamily(' 850123 '), 'crawler')
})

// 「所属策略为检测模式：命中只记录」的文案归因门：DetectionOnly
// （id:6）在 ACL/黑名单/自定义规则之后、CRS 与请求体规则之前发射——只有 WAF 族
// 的 logged 可由检测模式解释；阶段 1 族的 logged 成因是信任保留检测（id:3/12），
// 归因「检测模式」会掩盖真正的豁免策略。
test('检测模式归因：仅 WAF 族（CRS/自定义含 body 目标）', () => {
  for (const kind of ['waf-crs', 'waf-custom']) assert.equal(detectionModeExplains(kind), true, kind)
  for (const kind of ['acl', 'geo', 'crawler', 'threat', 'trust', 'body', 'other', '']) {
    assert.equal(detectionModeExplains(kind), false, kind)
  }
})

test('段界与 ID 集合跨栈对表（后端段界/分支调整必须红）', () => {
  // 段界单一事实源 = services/security.go 段基址常量；attackFamilyClassOf 是
  // if-链无法纯文本全量对表——钉住段界常量 + 关键形态分支锚（msg 关键词分支
  // 为 Go 侧表达力超集，人工同步，豁免机械钉）。
  const svc = repoSource('internal/services/security.go')
  for (const anchor of [
    'geoipPrecheckRuleBase     = 800000',
    'geoipCrawlerRuleBase      = 810000',
    'geoipCrawlerSpoofRuleBase = 850000',
  ]) {
    assert.ok(svc.includes(anchor), `段界常量漂移：${anchor}`)
  }
  const handler = repoSource('internal/handlers/security.go')
  const fn = section(handler, 'func attackFamilyClassOf(', '\n}')
  for (const anchor of [
    'len(ruleTriggered) == 5',
    "ruleTriggered[0] >= '1' && ruleTriggered[0] <= '7'",
    'len(ruleTriggered) >= 7',
    'ruleTriggered == "11"',
    'ruleTriggered == "14"',
    'ruleTriggered == "3" || ruleTriggered == "12"',
    'ruleTriggered == "2" || ruleTriggered == "4" || ruleTriggered == "5" || ruleTriggered == "7"',
  ]) {
    assert.ok(fn.includes(anchor), `attackFamilyClassOf 分支锚漂移：${anchor}`)
  }
  // 「8」前端归 ipAcl vs 后端归 GeoIP——有意设计例外（见上方用例注释），不钉。
})
