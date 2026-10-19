import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const page = readFileSync(new URL('../src/views/Rules.vue', import.meta.url), 'utf8')
const section = (startMarker: string, endMarker: string): string => {
  const start = page.indexOf(startMarker)
  assert.ok(start >= 0, `missing start marker ${startMarker}`)
  const end = page.indexOf(endMarker, start + startMarker.length)
  assert.ok(end > start, `missing end marker ${endMarker}`)
  return page.slice(start, end)
}

test('A85历史问题-1：健康检查超时只属于主动探测（HTTP/TCP 均隐藏在被动模式）', () => {
  const httpHealth = section('<el-divider content-position="left" class="compact-divider">健康检查</el-divider>', '<template v-if="wizardForm.protocol === \'tcp\'">')
  const httpActive = httpHealth.slice(httpHealth.indexOf('<template v-if="wizardForm.enable_active_health_check">'))
  assert.match(httpActive, /健康检查超时时间|health_check_timeout/)
  const beforeHttpActive = httpHealth.slice(0, httpHealth.indexOf('<template v-if="wizardForm.enable_active_health_check">'))
  assert.doesNotMatch(beforeHttpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(httpActive, /主动探测超时/)

  const tcpHealth = section('<template v-if="wizardForm.protocol === \'tcp\'">', '</template>\n            </template>\n          </el-form>')
  const tcpActive = tcpHealth.slice(tcpHealth.indexOf('<template v-if="wizardForm.enable_active_health_check">'))
  const beforeTcpActive = tcpHealth.slice(0, tcpHealth.indexOf('<template v-if="wizardForm.enable_active_health_check">'))
  assert.doesNotMatch(beforeTcpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(tcpActive, /v-model="wizardForm\.health_check_timeout"/)
  assert.match(tcpActive, /主动探测超时/)
})

test('A85历史问题-1：被动健康检查预览不再宣称超时语义', () => {
  const wizardPreview = section('<el-descriptions-item label="健康检查" v-if="wizardForm.protocol === \'http\'">', '<el-descriptions-item label="连接重试"')
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
  const preview = section('<el-descriptions-item label="主动健康检查" v-if="ruleConfig.protocol === \'http\'', '被动健康检查')
  assert.match(preview, /ruleConfig\.enable_active_health_check/)
  assert.doesNotMatch(preview, /v-if="ruleConfig\.protocol === 'http' && ruleConfig\.health_check_path"/)
  assert.doesNotMatch(preview, /!ruleConfig\.health_check_path/)
  assert.match(preview, /ruleConfig\.health_check_path \|\| '\/'/)
  assert.match(preview, /!ruleConfig\.enable_active_health_check/)
})

test('A85历史问题-6：开启 TCP 主动检查不再自动写首上游端口（0=按各上游自身端口）', () => {
  const watcher = section('watch(() => wizardForm.enable_active_health_check', 'const adminPorts')
  assert.doesNotMatch(watcher, /tcp_health_check_port = firstUpstream\.port/)
  assert.doesNotMatch(watcher, /firstUpstream/)
  assert.match(watcher, /health_check_path = '\/'/)
})
