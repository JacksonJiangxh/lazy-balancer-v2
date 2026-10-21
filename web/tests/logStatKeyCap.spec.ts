// 规则日志统计的键上限判定必须是 O(1)：原实现在每次遇到新键时用
// Object.keys(map).length 数整表（500 键上限下全量摄入要重复数数百次）。
// 现实现为每个统计桶维护 keyCounts 计数。SFC 内私有实现无法在 node 下求值，
// 沿用本仓「源码钉」形态（限段 + 边界）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

const rules = source('src/views/Rules.vue')

test('统计键上限 O(1)：计数随新增键自增，不再数整表', () => {
  assert.match(rules, /keyCounts: \{ ip: 0, ua: 0, uri: 0 \}/, '统计桶自带键数计数')

  const increment = section(rules, 'const incrementCappedStat = (', '\n}\n')
  assert.match(increment, /if \(buckets\.keyCounts\[bucket\] < MAX_LOG_STAT_KEYS - 1\)/)
  assert.match(increment, /buckets\.keyCounts\[bucket\] \+= 1/, '新增键时同步计数')
  assert.doesNotMatch(increment, /Object\.keys\(/, '不得再数整表')

  const consume = section(rules, 'const consumeLogLine = (', '\n}\n')
  assert.match(consume, /incrementCappedStat\(maps, 'ip', ip\)/)
  assert.match(consume, /incrementCappedStat\(maps, 'uri', uri\)/)
  assert.match(consume, /incrementCappedStat\(maps, 'ua', g\)/)
})

// 敌意键形态：统计键来自请求日志（攻击者可控）。原型链键 `__proto__` 在普通对象
// 上赋值会命中 Object.prototype 的 setter——键静默不落库，但 keyCounts 已自增
// （计数侵蚀：容量被幽灵键吃满），且永远不会归入「其他」。`constructor`/
// `toString` 同样只能靠 own-property 守卫侥幸正确，容器本身必须是原型安全的
// （Object.create(null) 或 Map）才不依赖守卫细节。
//
// 本钉依赖生产侧修复（跨批次依赖）：当前实现仍用 `{}` 桶，预期红；生产改为
// 原型安全容器后转绿——不 skip，避免修复前后都"通过"。
test('统计键：原型链敌意键不得侵蚀计数，满表回落「其他」', () => {
  const createBuckets = section(rules, 'const createLogStatBuckets = (', '\n})')
  const increment = section(rules, 'const incrementCappedStat = (', '\n}\n')
  assert.match(
    createBuckets,
    /Object\.create\(null\)|new Map/,
    '统计桶必须使用无原型容器，否则 __proto__/constructor/toString 会被原型链吞掉或依赖守卫细节',
  )
  assert.match(increment, /OTHER_LOG_STAT_KEY/, '满表必须回落「其他」，不得丢弃计数')
})
