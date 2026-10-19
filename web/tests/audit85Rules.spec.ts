import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'
import { clampPassiveHealthCheckTimeout } from '../src/utils/ruleWizard.ts'

const page = source('src/views/Rules.vue')

// 审计 87 WEBT-09④：模板标记定位改为「容错正则 + 显式失败」——原实现把 el-divider
// 的完整 class 串（含属性顺序）当起点，纯样式调整即假红/截错段。
const markerIndex = (text: string, pattern: RegExp, what: string): number => {
  const at = text.search(pattern)
  assert.ok(at >= 0, `missing ${what}`)
  return at
}

/** 以正则定位起点、以字符串定位终点（终点必须晚于起点）。 */
const sectionFrom = (startPattern: RegExp, endMarker: string, what: string): string => {
  const start = markerIndex(page, startPattern, what)
  const end = page.indexOf(endMarker, start + 1)
  assert.ok(end > start, `missing end marker ${endMarker} after ${what}`)
  return page.slice(start, end)
}

test('A85历史问题-1：健康检查超时只属于主动探测（HTTP/TCP 均隐藏在被动模式）', () => {
  // W87-15：TCP 段起点必须从「健康检查」分隔符之后取首个 TCP 标记——原实现
  // 从页面头 indexOf，命中的是上游表协议列（:549），随后 enable_active 标记又
  // 命中 HTTP 段（:698），断言对象整体错位（钉空转）。
  const healthStart = markerIndex(page, /<el-divider[^>]*>健康检查<\/el-divider>/, '健康检查分隔符')
  const healthEnd = page.indexOf('<!-- Step 3: 自定义路由', healthStart)
  assert.ok(healthEnd > healthStart, 'missing custom routes step marker')
  const healthBlock = page.slice(healthStart, healthEnd)
  const activeMarker = '<template v-if="wizardForm.enable_active_health_check">'
  const tcpRel = markerIndex(healthBlock, /<template\s+v-if="wizardForm\.protocol === 'tcp'">/, 'TCP 健康检查段')
  assert.ok(tcpRel > 0, 'TCP 健康检查段必须在健康检查分隔符之后')

  const httpHealth = healthBlock.slice(0, tcpRel)
  const httpActiveAt = httpHealth.indexOf(activeMarker)
  assert.ok(httpActiveAt > 0, 'missing HTTP active health section')
  const httpActive = httpHealth.slice(httpActiveAt)
  assert.match(httpActive, /健康检查超时时间|health_check_timeout/)
  const beforeHttpActive = httpHealth.slice(0, httpActiveAt)
  assert.doesNotMatch(beforeHttpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(httpActive, /主动探测超时/)

  const tcpHealth = healthBlock.slice(tcpRel)
  const tcpActiveStart = tcpHealth.indexOf(activeMarker)
  assert.ok(tcpActiveStart > 0, 'missing TCP active health section')
  const tcpActive = tcpHealth.slice(tcpActiveStart)
  const beforeTcpActive = tcpHealth.slice(0, tcpActiveStart)
  // 独立断言：TCP 被动段（开关 + 提示）不得出现超时输入。
  assert.doesNotMatch(beforeTcpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(tcpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(tcpActive, /主动探测超时/)
  // 锚点自证：TCP 主动段必须含 TCP 专属的检查端口字段（HTTP 主动段没有），
  // 否则说明切段又错位到 HTTP。
  assert.match(tcpActive, /tcp_health_check_port/)
})

test('A85历史问题-1：被动健康检查预览不再宣称超时语义', () => {
  const wizardPreview = sectionFrom(
    /<el-descriptions-item[^>]*label="健康检查"[^>]*>/,
    '<el-descriptions-item label="连接重试"',
    '向导预览健康检查描述项',
  )
  const passiveLines = wizardPreview.match(/被动检查 \([^\n]*/g) ?? []
  assert.ok(passiveLines.length >= 2, 'missing passive preview lines')
  for (const line of passiveLines) {
    assert.doesNotMatch(line, /超时/, `passive preview must not claim timeout: ${line}`)
    assert.match(line, /恢复窗口/)
  }
  const configPassive = page.slice(page.indexOf('<el-descriptions-item label="被动健康检查"'))
  const passiveConfigLine = configPassive.slice(0, configPassive.indexOf('</el-descriptions-item>'))
  assert.doesNotMatch(passiveConfigLine, /超时/)
  assert.match(passiveConfigLine, /恢复窗口/)
})

test('A85历史问题-2：配置预览的主动健康检查判据是 enable_active_health_check', () => {
  const preview = sectionFrom(
    /<el-descriptions-item[^>]*label="主动健康检查"[^>]*>/,
    '被动健康检查',
    '配置预览主动健康检查描述项',
  )
  assert.match(preview, /ruleConfig\.enable_active_health_check/)
  assert.doesNotMatch(preview, /v-if="ruleConfig\.protocol === 'http' && ruleConfig\.health_check_path"/)
  assert.doesNotMatch(preview, /!ruleConfig\.health_check_path/)
  assert.match(preview, /ruleConfig\.health_check_path \|\| '\/'/)
  assert.match(preview, /!ruleConfig\.enable_active_health_check/)
})

test('A85历史问题-6：开启 TCP 主动检查不再自动写首上游端口（0=按各上游自身端口）', () => {
  const watcher = section(page, 'watch(() => wizardForm.enable_active_health_check', 'const adminPorts')
  assert.doesNotMatch(watcher, /tcp_health_check_port = firstUpstream\.port/)
  assert.doesNotMatch(watcher, /firstUpstream/)
  assert.match(watcher, /health_check_path = '\/'/)
})

test('WEBT-10：被动模式下隐藏的超时字段越界时保存前钳到合法值', () => {
  // 值域：后端 validateRuleFeatures 要求 0<timeout<interval（不区分主动/被动），
  // 而被动模式不渲染 timeout 输入（A85历史问题-1）——存量越界值原本会撞上无处修改
  // 的校验提示。钳制只处理被动模式能自解的区间，其余形态交回原校验。
  assert.deepEqual(clampPassiveHealthCheckTimeout(10, 10), { timeout: 9, clamped: true })
  assert.deepEqual(clampPassiveHealthCheckTimeout(10, 30), { timeout: 9, clamped: true })
  assert.deepEqual(clampPassiveHealthCheckTimeout(5, 2), { timeout: 2, clamped: false }, '合法值不得改动')
  assert.deepEqual(clampPassiveHealthCheckTimeout(1, 1), { timeout: 1, clamped: false }, '无合法解时不得代改')
  assert.deepEqual(clampPassiveHealthCheckTimeout(Number.NaN, 5), { timeout: 5, clamped: false })
  // 生产接线：submitWizard 在 历史 (timeout>=interval) 校验之前、仅被动模式钳制。
  const submit = section(page, 'const submitWizard = async', 'const allowedProtocols')
  const passiveAt = submit.indexOf('if (!wizardForm.enable_active_health_check) {')
  const clampAt = submit.indexOf('clampPassiveHealthCheckTimeout(wizardForm.health_check_interval, wizardForm.health_check_timeout)')
  const timeoutRuleAt = submit.indexOf('wizardForm.health_check_timeout >= wizardForm.health_check_interval')
  assert.ok(passiveAt > 0, '缺被动模式分支')
  assert.ok(clampAt > passiveAt, '被动模式分支必须调用钳制')
  assert.ok(timeoutRuleAt > clampAt, '钳制必须先于 timeout>=interval 校验（否则仍被拦下）')
  assert.match(submit.slice(clampAt, timeoutRuleAt), /wizardForm\.health_check_timeout = clampedTimeout\.timeout/)
})
