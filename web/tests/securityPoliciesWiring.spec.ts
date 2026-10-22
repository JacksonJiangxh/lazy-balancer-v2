// 策略页接线钉：引用名单共享缓存（self + 共绑 peer）、迁移预演第二类跳过风险、
// G3 判定单源、状态码选项单源、CRS 文件名解析单源、爬虫引擎空集语义、注释口径。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { section, source, stripComments } from './_helpers.ts'
import { STAGE_BLOCK_STATUS_OPTIONS, hasStage3Features, parseCrsFilename, parseUnknownStrings } from '../src/utils/securityStages.ts'

const page = source('src/views/security/SecurityPolicies.vue')

test('G3 谓词：mode 三态 ∪ 自定义规则引用非空（与后端 PolicyTypeFeatures 同口径）', () => {
  for (const mode of ['blocking', 'detection', 'custom_only']) {
    assert.equal(hasStage3Features(mode, 0), true, `${mode} 恒产生阶段 3`)
  }
  assert.equal(hasStage3Features('off', 1), true, '关闭模式但仍有自定义规则引用')
  assert.equal(hasStage3Features('off', 0), false)
})

test('阶段 3 chip 消费 G3 单源谓词（引用数口径，含禁用规则）', () => {
  const chip = section(page, 'const stage3ChipOn', '\n\n')
  assert.match(chip, /hasStage3Features\(row\.mode, row\.custom_rules_ref_count/, '判定必须用引用数（与后端 G3 逐字对齐）')
  assert.match(chip, /custom_rules_ref_count \?\? row\.custom_rules_count/, '旧后端缺摘要字段时回退启用计数')
  const code = stripComments(chip)
  assert.doesNotMatch(code, /row\.has_waf/)
})

test('CRS 文件名解析单源：四位解析点全部改引 parseCrsFilename', () => {
  assert.deepEqual(parseCrsFilename('REQUEST-942-100-APPLICATION-ATTACK-SQLI.conf'), { phase: '请求', code: '42' })
  assert.deepEqual(parseCrsFilename('RESPONSE-955-100-X.conf'), { phase: '响应', code: '55' })
  assert.equal(parseCrsFilename('not-a-crs-file.conf'), null)

  for (const name of ['crsOptionCode', 'crsOptionPhase', 'crsGroupCodeOfFile', 'normalizeCrsGroups']) {
    const at = page.indexOf(`const ${name} = `)
    assert.ok(at > 0, `missing ${name}`)
    const body = page.slice(at, at + 400)
    assert.match(body, /parseCrsFilename\(/, `${name} 未走单源解析`)
    assert.doesNotMatch(stripComments(body), /REQUEST\|RESPONSE/, `${name} 仍内联文件名正则`)
  }
  // 组选项构建（两处）同样不得再内联文件名正则
  assert.doesNotMatch(page, /\/\^\(\?:REQUEST\|RESPONSE\)-9\(\\d\{2\}\)-/i, '文件名正则不得留在视图层')
})

test('未知字符串数组解析单源（本地副本已删）', () => {
  assert.deepEqual(parseUnknownStrings(['a', ' ', 'b']), ['a', 'b'])
  assert.deepEqual(parseUnknownStrings('["a","b"]'), ['a', 'b'])
  assert.deepEqual(parseUnknownStrings(null), [])
  assert.doesNotMatch(page, /const parseUnknownStringList/, '本地同构实现不得回流')
  assert.match(page, /parseUnknownStrings\(p\.crs_rule_groups\)/)
})

test('引用名单取数走跨组件共享缓存（self + 共绑 peer，不再清空重下）', () => {
  assert.match(page, /import \{[^}]*ensureSharedEntries[^}]*sharedEntriesCache[^}]*subscribeSharedEntriesCache[^}]*\} from '@\/utils\/securityStages'/)
  assert.doesNotMatch(page, /ipListDetails/, '本地条目缓存不得回流')
  assert.doesNotMatch(page, /ensureIpListDetails/, '本地补齐函数不得回流')

  const watchBlock = section(page, 'watch([currentStep, ipACLList', 'void ensureIpListEntries')
  assert.match(watchBlock, /const coIds = coBoundPeerIds\.value/)
  assert.match(watchBlock, /if \(!coIds\.has\(p\.id\)\) continue/, 'peer refs 必须收敛为共绑集合')
  assert.doesNotMatch(watchBlock, /for \(const p of policies\.value\) \{\n\s*ids\.push/, '不得再全量汇总全部策略 refs')

  const ensure = section(page, 'const ensureIpListEntries', '\n}\n')
  assert.match(ensure, /ensureSharedEntries\(ids/)
  assert.match(ensure, /ipListEntries\.value = \{ \.\.\.sharedEntriesCache \}/, '落地后须同步本地响应式镜像')
  assert.match(page, /onUnmounted\(unregisterIpListEntries\)/, '订阅必须随组件卸载摘除')
})

test('迁移预演补「已有其他限流策略 → 将跳过」风险组', () => {
  const risk = section(page, 'const migrateStage2SkipRisk', '\n})\n')
  assert.match(risk, /migrateChildTypes\.value\.includes\('stage2'\)/, '未产出 stage2 子策略时无该风险')
  assert.match(risk, /type === 'stage2'/)
  assert.match(risk, /b\.rate_limit_enabled/, '摘要缺类型时按 binding 能力回退')
  // 模板：两处呈现（逐行标注 + 汇总横幅）
  assert.match(page, /将跳过（已有 stage2）/)
  assert.match(page, /限流唯一风险/)
})

test('规则级阶段页状态码选项由共享清单派生', () => {
  const overrideSelect = section(page, 'stage-override-status-select', '</el-select>')
  assert.match(overrideSelect, /v-for="opt in STAGE_BLOCK_STATUS_OPTIONS"/)
  const code = stripComments(overrideSelect)
  assert.doesNotMatch(code, /<el-option :value="40[134]"/, '硬编码状态码不得回流')
  assert.deepEqual(STAGE_BLOCK_STATUS_OPTIONS.map((o) => o.value), [400, 401, 403, 404, 503])
})

test('爬虫引擎：字段缺失→默认三项，显式 "[]" 原样保留（全部引擎语义）', () => {
  const detailBlock = section(page, 'geoip_crawler_engines: d.geoip_crawler_engines', 'waf_check_response:')
  assert.match(detailBlock, /d\.geoip_crawler_engines === undefined \|\| d\.geoip_crawler_engines === ''/)
  assert.match(detailBlock, /\['googlebot', 'bingbot', 'baiduspider'\]/)
  assert.doesNotMatch(detailBlock, /length > 0 \?/, '空数组不得再被三引擎兜底改写')
})

test('保存语义注释与批量端点实现同源（不得再写逐规则 PUT）', () => {
  assert.doesNotMatch(page, /收尾逐规则 PUT/, '注释不得回退为逐规则 PUT 口径')
  assert.doesNotMatch(page, /在策略落库后逐规则 PUT/)
  assert.match(page, /batch-block-pages/)
})
