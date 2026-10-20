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
