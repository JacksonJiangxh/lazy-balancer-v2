import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, member, section } from './_helpers.ts'

// 设置/仪表盘配置面的「呈现与真实消费者一致」守卫：
// - 全局 DNS 提供商是无消费者的死配置（签发链按证书配置行读 provider），
//   不得继续呈现为可改并承诺「创建规则时默认使用」；
// - Dashboard 规则列表刷新失败但保留缓存时，必须明示「展示上次结果」；
// - OIDC 配置读取的回填必须只接受最新一轮请求（迟到的旧响应不得回滚表单）。

test('全局 DNS 提供商：表单入口与过度承诺文案已移除，键仍按库值回传', () => {
  // 「不得回流」断言走剥注释视图：注释里写一句历史说明不得把用例改红。
  const page = code('src/views/settings/FreeCertificates.vue')
  assert.doesNotMatch(page, /v-model="global\.dns_provider"/, '死配置不得继续呈现为可改')
  assert.doesNotMatch(page, /创建规则时默认使用/, '文案不得承诺不存在的全局默认机制')
  const save = member(page, 'const handleSave = async')
  assert.match(save, /dns_provider: global\.value\.dns_provider/, '保存仍按库值回传，避免静默改写存量列')
})

test('Dashboard 规则卡：刷新失败且有缓存时明示陈旧，首轮失败仍报「采集失败」', () => {
  const page = code('src/views/Dashboard.vue')
  assert.match(page, /<el-tag v-if="rulesUnavailable && rules\.length > 0"[^>]*>规则列表刷新失败：展示上次结果<\/el-tag>/)
  const card = section(page, 'class="rules-card"', '</el-card>')
  const badgeAt = card.indexOf('规则列表刷新失败')
  const tableAt = card.indexOf('<el-table')
  assert.ok(badgeAt > 0, '缺陈旧徽标')
  assert.ok(tableAt > badgeAt, '徽标必须在规则表之前的卡头，不能落到表尾')
  const empty = section(page, 'const rulesEmptyText', 'const hasRuleRequests')
  assert.match(empty, /采集失败/, '无缓存时（首轮失败）仍走采集失败空态')
})

test('OIDC 配置读取带请求序号守卫：成功回填、失败清空与状态通知都只落最新轮次', () => {
  const page = code('src/views/settings/OIDCSettings.vue')
  const load = member(page, 'const load = async')
  assert.match(load, /const seq = \+\+loadSeq/, '每次 load 必须自增序号')
  assert.equal((load.match(/seq !== loadSeq/g) ?? []).length, 3, '成功/失败/notify 三处都必须比对')
  const firstGuard = load.indexOf('if (seq !== loadSeq) return')
  const fillAt = load.indexOf('enabled.value = !!res.data.enabled')
  assert.ok(firstGuard > 0 && fillAt > firstGuard, '回填必须晚于最新轮次判定')
  const notifyAt = load.lastIndexOf('notify()')
  const lastGuard = load.lastIndexOf('if (seq !== loadSeq) return')
  assert.ok(notifyAt > lastGuard, '迟到的旧响应不得再通知父级状态')
})
