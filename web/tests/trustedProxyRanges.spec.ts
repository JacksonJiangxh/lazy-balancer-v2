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
  TRUSTED_PROXY_MAX_INLINE_ENTRIES,
  TRUSTED_PROXY_MIN_PREFIX_BITS,
  trustedProxyRangeError,
  trustedProxyRangesError,
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
  for (const form of ['0.0.0.0/8', '0.0.0.0/0', '::/0', '::ffff:0.0.0.0/96', '::ffff:0:0/96']) {
    assert.ok(allSpace.includes(`"${form}"`), `全空间形态 ${form} 必须逐条对齐`)
  }
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
