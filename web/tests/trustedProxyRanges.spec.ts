// 受信代理网段行内校验：判据必须与后端单源，且只在后端必然拒绝
// 的形态上报错（前端误拒会挡住合法配置，故放宽方向一律交给后端兜底）。
//
// 后端：internal/services/caddy.go TrustedProxyMinPrefixBits / PrefixAllSpace、
// internal/handlers/config_trustedproxy.go normalizeTrustedProxyRanges。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  TRUSTED_PROXY_MAX_HEADERS,
  TRUSTED_PROXY_MAX_INLINE_ENTRIES,
  TRUSTED_PROXY_MAX_TOTAL_ENTRIES,
  TRUSTED_PROXY_MIN_PREFIX_BITS,
  trustedProxyHeaderError,
  trustedProxyHeadersError,
  trustedProxyRangeError,
  trustedProxyRangesError,
  trustedProxyTotalError,
} from '../src/utils/trustedProxyRanges.ts'
import { repoSource, section, source } from './_helpers.ts'

test('合法条目零报错（含裸 IP 与 IPv6 官方回源段）', () => {
  for (const value of ['203.0.113.0/24', '1.2.3.4', '  10.0.0.0/8  ', '2001:db8::/32', '2a06:98c0::/29']) {
    assert.equal(trustedProxyRangeError(value), '', `${value} 应被放行`)
  }
})

test('非法形态立即报错', () => {
  assert.match(trustedProxyRangeError('not-a-cidr'), /不是合法的 IP 或 CIDR/)
  assert.match(trustedProxyRangeError('1.2.3.4/33'), /不是合法的 IP 或 CIDR/)
  assert.match(trustedProxyRangeError(''), /不能为空/)
  assert.match(trustedProxyRangeError('   '), /不能为空/)
})

test('过宽网段与后端最小前缀判据一致', () => {
  assert.match(trustedProxyRangeError('10.0.0.0/4'), /最小允许 \/8/)
  assert.match(trustedProxyRangeError('2001:db8::/28'), /\/29（IPv6）/)
  // 全空间形态优先按「覆盖全部地址空间」报（与后端两条判据同序）
  assert.match(trustedProxyRangeError('0.0.0.0/0'), /全部地址空间/)
  assert.match(trustedProxyRangeError('::/0'), /全部地址空间/)
})

test('内联网段条数上限与后端 inline 上限一致', () => {
  const atLimit = Array.from({ length: TRUSTED_PROXY_MAX_INLINE_ENTRIES }, (_, i) => `10.${i}.0.0/16`)
  assert.equal(trustedProxyRangesError(atLimit), '')
  const overLimit = [...atLimit, '192.168.0.0/16']
  assert.match(trustedProxyRangesError(overLimit), /最多 64 条/)
})

test('汇总文案逐条点名非法值（用户可定位是哪一条）', () => {
  const message = trustedProxyRangesError(['203.0.113.0/24', '0.0.0.0/0', '10.0.0.0/4'])
  assert.match(message, /0\.0\.0\.0\/0（/)
  assert.match(message, /10\.0\.0\.0\/4（/)
  assert.doesNotMatch(message, /203\.0\.113\.0\/24/)
})

test('跨栈对表：Go 侧判据与前端常量同值', () => {
  const caddy = repoSource('internal/services/caddy.go')
  const minBits = section(caddy, 'func TrustedProxyMinPrefixBits', 'func TrustedProxyPrefixAllSpace')
  assert.match(minBits, /return 29/)
  assert.match(minBits, /return 8/)
  const allSpace = section(caddy, 'func TrustedProxyPrefixAllSpace', 'func TrustedProxyPrefixTooWide')
  // 双向集合法（不是单向包含）：后端新增第 6 个全空间形态而前端不同步时，
  // 用户会在面板写入等同 0.0.0.0/0 的配置且前端零提示（保存后整组被拒）。
  const goForms = [...allSpace.matchAll(/"([^"]+)"/g)].map((match) => match[1]).sort()
  const tsArray = section(source('src/utils/trustedProxyRanges.ts'), 'const ALL_SPACE_PREFIXES: readonly string[] = [', ']')
  const tsForms = [...tsArray.matchAll(/'([^']+)'/g)].map((match) => match[1]).sort()
  assert.deepEqual(tsForms, goForms, '前端 ALL_SPACE_PREFIXES 必须与 Go case 列表逐值相等')
  const handler = repoSource('internal/handlers/config_trustedproxy.go')
  assert.match(handler, /len\(entries\) > 64/, '内联网段条目上限须与常量对表')
  assert.equal(TRUSTED_PROXY_MIN_PREFIX_BITS.ipv4, 8)
  assert.equal(TRUSTED_PROXY_MIN_PREFIX_BITS.ipv6, 29)
  assert.equal(TRUSTED_PROXY_MAX_INLINE_ENTRIES, 64)
})

test('组件接线：行内标红 + 保存门（不再等到 PUT 才被整组拒绝）', () => {
  const card = source('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(card, /const trustedRangesError = computed\(\(\) => trustedProxyRangesError\(trustedRanges\.value\)\)/)
  assert.match(card, /v-if="trustedRangesError"/, '非法条目必须就地呈现')
  const save = section(card, 'const handleSave = async', 'const preview = await request.post')
  assert.match(save, /if \(trustedRangesError\.value\)/)
  assert.ok(
    save.indexOf('trustedRangesError.value') < save.indexOf('buildCaddyConfigPayload'),
    '校验必须早于载荷组装与任何写请求',
  )
})

// —— 请求头：条数 ≤8、字符集（后端 normalizeTrustedProxyHeaders 逐条对齐） ——

test('请求头合法形态零报错（含 8 条上限与连字符名）', () => {
  for (const value of ['X-Forwarded-For', 'CF-Connecting-IP', 'X-Real-IP', 'True-Client-IP', 'A1']) {
    assert.equal(trustedProxyHeaderError(value), '', `${value} 应被放行`)
  }
  const atLimit = Array.from({ length: TRUSTED_PROXY_MAX_HEADERS }, (_, i) => `X-Forwarded-${i}`)
  assert.equal(trustedProxyHeadersError(atLimit), '')
})

test('请求头非法形态立即报错（空格/下划线/空/超长，与后端字符集一致）', () => {
  assert.match(trustedProxyHeaderError('X-Forwarded-For '), /非法请求头名/)
  assert.match(trustedProxyHeaderError('X_Forwarded_For'), /非法请求头名/)
  assert.match(trustedProxyHeaderError(''), /非法请求头名/)
  assert.match(trustedProxyHeaderError(`X-${'a'.repeat(63)}`), /非法请求头名/, '超 64 字符必须拒绝')
  assert.match(trustedProxyHeaderError('X Forwarded For'), /非法请求头名/)
})

test('请求头条数上限按原始条数计（重复项也计入，与后端去重前判定一致）', () => {
  const nine = Array.from({ length: TRUSTED_PROXY_MAX_HEADERS + 1 }, (_, i) => `X-Forwarded-${i}`)
  assert.match(trustedProxyHeadersError(nine), /最多 8 条/)
  const duplicateNine = ['X-Forwarded-For', 'X-Forwarded-For', 'X-Real-IP', 'A', 'B', 'C', 'D', 'E', 'F']
  assert.match(trustedProxyHeadersError(duplicateNine), /最多 8 条/, '去重前 9 条后端必然拒绝')
})

test('请求头汇总文案逐条点名非法值', () => {
  const message = trustedProxyHeadersError(['CF-Connecting-IP', 'X_Forwarded_For'])
  assert.match(message, /X_Forwarded_For（/)
  assert.doesNotMatch(message, /CF-Connecting-IP（/)
})

// —— 总量门：内联 + 引用展开 ≤2000（后端 trustedProxyMaxTotalCIDRs） ——

test('总量门只拦「已知合计」超限的形态，未知引用条数交给后端兜底', () => {
  assert.equal(trustedProxyTotalError(60, 1940), '', '合计 2000 恰好等于上限应放行')
  assert.match(trustedProxyTotalError(60, 1950), /超过 2000 上限/)
  assert.match(trustedProxyTotalError(60, 1950), /内联 60 \+ 引用展开 1950/, '文案要点名两个分量')
  assert.equal(trustedProxyTotalError(64, 0), '', '未引用名单时内联上限由网段判据单独承担')
})

test('跨栈对表：请求头与总量判据与 Go 侧同值', () => {
  const handler = repoSource('internal/handlers/config_trustedproxy.go')
  assert.match(handler, /len\(entries\) > 8/, '请求头条数上限须对表')
  assert.match(handler, /\^\[A-Za-z0-9-\]\{1,64\}\$/, '请求头字符集须对表')
  assert.match(handler, /trustedProxyMaxTotalCIDRs = 2000/, '总量上限须对表')
  assert.equal(TRUSTED_PROXY_MAX_HEADERS, 8)
  assert.equal(TRUSTED_PROXY_MAX_TOTAL_ENTRIES, 2000)
})

test('组件接线：请求头与总量行内提示 + 保存门', () => {
  const card = source('src/views/settings/CaddyGlobalSettings.vue')
  assert.match(card, /const trustedHeadersError = computed\(\(\) => trustedProxyHeadersError\(trustedHeaders\.value\)\)/)
  assert.match(card, /const trustedTotalError = computed\(\(\) => trustedProxyTotalError\(/)
  assert.match(card, /v-if="trustedHeadersError"/, '非法请求头必须就地呈现')
  assert.match(card, /v-if="trustedTotalError"/, '合计超限必须就地呈现')
  assert.match(card, /上限 \{\{ TRUSTED_PROXY_MAX_TOTAL_ENTRIES \}\}/, '展示上限与判据常量同源')
  const save = section(card, 'const handleSave = async', 'const preview = await request.post')
  assert.ok(save.indexOf('trustedHeadersError.value') > 0, '保存门必须拦非法请求头')
  assert.ok(save.indexOf('trustedTotalError.value') > 0, '保存门必须拦总量超限')
  assert.ok(
    save.indexOf('trustedTotalError.value') < save.indexOf('buildCaddyConfigPayload'),
    '校验必须早于载荷组装与任何写请求',
  )
})
