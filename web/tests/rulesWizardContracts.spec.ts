// 规则向导提交/展示口径单源验收：
//   A. 策略卡片集与提交白名单同源派生（含 random/first，TCP 剔除 cookie）
//   B. 提交路径镜像步进 host 门（跳步直达预览不得静默剔除空 host 行）
//   C. 辅助端点（更新者/DNS 配置/CA 提供商）失败显性化并带重试
//   D. 数值控件边界与后端写侧门同源（不再写死并静默夹紧合法库值）
//   E. CA 选择器选项=启用 ∪ 当前值（已禁用项回显且不可新选）
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { section, source } from './_helpers.ts'
import { STRATEGY_CARD_OPTIONS, strategyCardsForProtocol, strategyValuesForProtocol } from '../src/utils/strategyLabels.ts'
import { RULE_NUMERIC_LIMITS } from '../src/utils/ruleValidation.ts'

const page = source('src/views/Rules.vue')

test('A 策略卡片集与提交白名单同源：含 random/first，TCP 无 cookie', () => {
  const http = strategyValuesForProtocol('http')
  const tcp = strategyValuesForProtocol('tcp')
  assert.deepEqual([...http].sort(), ['cookie', 'first', 'ip_hash', 'least_conn', 'random', 'weighted_round_robin'])
  assert.ok(!tcp.includes('cookie'), 'cookie 仅 HTTP')
  assert.ok(tcp.includes('random') && tcp.includes('first'), '后端 tcpStrategies 放行 random/first')
  assert.deepEqual([...tcp].sort(), [...http.filter((v) => v !== 'cookie')].sort())
  // 每张卡片都有展示文案（value/title/desc 一一对应，避免空卡）
  for (const card of STRATEGY_CARD_OPTIONS) {
    assert.ok(card.title.length > 0 && card.desc.length > 0, `${card.value} 缺文案`)
  }
  assert.equal(strategyCardsForProtocol('tcp').length, tcp.length)
})

test('A 向导不再自带第二份策略字面量，卡片与白名单均由共享常量派生', () => {
  assert.match(page, /strategyCardsForProtocol\(wizardForm\.protocol\)/)
  assert.match(page, /strategyValuesForProtocol\(wizardForm\.protocol\)/)
  assert.doesNotMatch(page, /'weighted_round_robin', 'ip_hash', 'least_conn'/, '白名单字面量数组不得回流')
  assert.doesNotMatch(page, /\{ value: 'least_conn', title:/, '卡片文案不得回流到视图')
})

test('B 提交路径镜像步进 host 门（跳步保存不得静默剔除空 host 行）', () => {
  const body = section(page, 'const submitWizard = async', 'const data: UpdateRuleRequest')
  assert.match(
    body,
    /upstreamTouched\.value = wizardForm\.upstreams\.map\(\(\) => true\)/,
    '提交门须与步进门同口径（先全量置 touched 再判定）',
  )
  assert.match(
    body,
    /if \(wizardForm\.upstreams\.some\(\(u, i\) => upstreamRowNeedsHost\(u, i\)\)\) \{\s*ElMessage\.warning\('请填写所有已启用上游服务器的主机地址'\)/,
    '缺 host 门时空 host 行会被载荷过滤静默剔除，保存「成功」但规则少了上游',
  )
  // 载荷侧静默剔除仍在（host+port 身份过滤），但门必须在其之前拦截
  const gateAt = body.indexOf('upstreamRowNeedsHost(u, i)')
  const filterAt = body.indexOf('filter(u => u.host && u.port)')
  assert.ok(gateAt >= 0 && filterAt > gateAt, 'host 门必须先于载荷过滤')
})

test('C 三个辅助端点失败有错误态 + 横幅重试（不再仅 console）', () => {
  for (const refName of ['usersLoadError', 'certConfigsLoadError', 'caProvidersLoadError']) {
    assert.match(page, new RegExp(`const ${refName} = ref\\(false\\)`), `${refName} 错误态缺失`)
  }
  assert.match(page, /const auxDataLoadFailed = computed\(/, '失败合入单条横幅')
  const alert = section(page, 'v-if="auxDataLoadFailed"', '</el-alert>')
  assert.match(alert, /retryAuxData/, '横幅必须带重试')
  // 字段级：ACME 步骤的 DNS 配置下拉失败与「未配置」区分
  assert.match(
    page,
    /v-if="certConfigsLoadError" class="form-tip-line port-warning">DNS 提供商配置加载失败/,
  )
  for (const fetchName of ['fetchUsers', 'fetchCertConfigs', 'fetchCAProviders']) {
    const fn = section(page, `const ${fetchName} = async`, '\n}\n')
    assert.match(fn, /LoadError\.value = true/, `${fetchName} 失败须置错误态`)
  }
})

test('D 数值控件边界引用共享常量（写侧门单源）', () => {
  assert.equal(RULE_NUMERIC_LIMITS.healthCheckIntervalMin, 1, '后端间隔门 ≥1（原控件 min=5 夹紧合法值 3）')
  assert.equal(RULE_NUMERIC_LIMITS.healthCheckTimeoutMin, 1)
  assert.equal(RULE_NUMERIC_LIMITS.tcpTryIntervalMax, 60000, '后端重试间隔上界 60000（原控件 10000）')
  assert.equal(RULE_NUMERIC_LIMITS.maxConnectionsMin, 0)
  // 按 el-input-number 开标签取属性集判定：不依赖属性书写顺序。此前三条否定
  // 断言把 `:max="30"` 写在字段名之前，而模板恒为「字段名在前」——真回归（重新
  // 加 :max）时空转（死断言）。标签提取必须跳过引号内的 `>`（`:min="a > b ? …"`
  // 形态），否则会在属性值中途截断。
  const inputTags = [...page.matchAll(/<el-input-number\b(?:[^>"']|"[^"]*"|'[^']*')*>/g)].map((m) => m[0])
  const wizardTags = (field: string): string[] => {
    const matcher = new RegExp(`\\.${field}"`)
    return inputTags.filter((tag) => matcher.test(tag))
  }

  const timeoutTags = wizardTags('health_check_timeout')
  assert.equal(timeoutTags.length, 2, '超时输入框应有两处（HTTP 主动检查与 TCP 探测）')
  for (const tag of timeoutTags) {
    assert.match(tag, /:min="RULE_NUMERIC_LIMITS\.healthCheckTimeoutMin"/)
    // 与写侧无上限对齐：不得写死上限（否则合法库值被 spinner 静默夹回）
    assert.doesNotMatch(tag, /:max=/, '超时无后端上限')
  }

  const intervalTags = wizardTags('health_check_interval')
  assert.ok(intervalTags.length > 0)
  for (const tag of intervalTags) {
    assert.match(tag, /:min="RULE_NUMERIC_LIMITS\.healthCheckIntervalMin"/)
    assert.doesNotMatch(tag, /:min="5"/, '间隔下限不得写死 5')
  }

  const maxConnTags = wizardTags('max_connections')
  assert.ok(maxConnTags.length > 0)
  for (const tag of maxConnTags) {
    assert.match(tag, /:min="RULE_NUMERIC_LIMITS\.maxConnectionsMin"/)
    assert.doesNotMatch(tag, /:max=/, '最大连接无后端上限')
  }

  const tcpTryTags = wizardTags('tcp_try_interval')
  assert.ok(tcpTryTags.length > 0)
  for (const tag of tcpTryTags) {
    assert.match(tag, /:max="RULE_NUMERIC_LIMITS\.tcpTryIntervalMax"/)
    assert.doesNotMatch(tag, /:max="10000"/, '重试间隔上界不得写死 10000')
  }
})

test('E CA 选择器选项包含当前值（已禁用回显不可新选）', () => {
  // 选项构造函数与标签函数单源在 utils/caProviderOptions（selectableReferencedOptions /
  // referencedOptionLabel）：视图只做取值，不得内联过滤。
  assert.match(page, /const wizardCAProviderOptions = computed\(\(\) => selectableReferencedOptions\(/)
  assert.match(page, /v-for="p in wizardCAProviderOptions"/)
  assert.match(page, /:label="referencedOptionLabel\(p\)"/)
  assert.match(page, /:disabled="!p\.enabled"/)
  assert.doesNotMatch(page, /enabledCAProviders/, '裸 enabled 过滤会让已禁用引用显示成裸 id')
})

test('F 证书任务视图类型收敛共享定义（不再自带第二份字段清单）', () => {
  assert.match(page, /type CertJob = Pick<CertJobListItem,/)
  assert.doesNotMatch(page, /interface CertJob \{/, '字段清单不得回流视图')
})
