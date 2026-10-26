// 键盘可达性的家族收敛钉：手写键盘激活一律经 activateOnce（过滤系统重复键），
// 自定义单选组按 APG 走 roving tabindex + 方向键，侧栏折叠入口暴露展开状态。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { activateOnce } from '../src/utils/keyboardActivate.ts'
import { nextRadioValue, rovingTabindex } from '../src/utils/rovingRadio.ts'
import { code, section, webFiles } from './_helpers.ts'

const keydown = (repeat: boolean): KeyboardEvent => ({ repeat } as KeyboardEvent)

test('activateOnce：系统重复键不触发动作（长按不再按重复率反复执行）', () => {
  let calls = 0
  const act = (): void => { calls += 1 }
  activateOnce(keydown(true), act)
  assert.equal(calls, 0, 'repeat=true 必须被丢弃')
  activateOnce(keydown(false), act)
  assert.equal(calls, 1)
})

test('全仓手写键盘激活均经 activateOnce（AccessibleLink 自带守卫除外）', () => {
  const files = webFiles('src', ['.vue'])
  assert.ok(files.length > 40, `扫描面异常（仅 ${files.length} 个 .vue）`)
  const offenders: string[] = []
  for (const file of files) {
    if (file === 'src/components/common/AccessibleLink.vue') continue // 自带 event.repeat 守卫
    for (const match of code(file).matchAll(/@keydown\.(?:enter|space)\.prevent="([^"]*)"/g)) {
      if (!match[1]!.includes('activateOnce(')) offenders.push(`${file}: ${match[0].slice(0, 90)}`)
    }
  }
  assert.deepEqual(offenders, [], '长按 Enter/Space 会按系统重复率反复触发业务动作')
})

test('AccessibleLink 仍保留自身 repeat 守卫（范式源头不得退化）', () => {
  const wrapper = code('src/components/common/AccessibleLink.vue')
  assert.match(wrapper, /if \(event\.repeat\) return/)
})

test('rovingTabindex：选中项是唯一 tab stop，选中项不可用时退到首个可用项', () => {
  const values = ['a', 'b', 'c']
  const none = (): boolean => false
  assert.equal(rovingTabindex(values, 'b', none, 'b'), 0)
  assert.equal(rovingTabindex(values, 'b', none, 'a'), -1)
  // 选中项被锁定 → 首个可用项接管 tab stop（整组不得不可 Tab 进入）
  const lockedB = (value: string): boolean => value === 'b'
  assert.equal(rovingTabindex(values, 'b', lockedB, 'a'), 0)
  assert.equal(rovingTabindex(values, 'b', lockedB, 'c'), -1)
  assert.equal(rovingTabindex(['a'], 'a', () => true, 'a'), -1, '无可用项时全组 -1')
})

test('nextRadioValue：方向键循环移动、跳过锁定项、Home/End 落首尾', () => {
  const values = ['a', 'b', 'c', 'd']
  const lockedB = (value: string): boolean => value === 'b'
  assert.equal(nextRadioValue(values, 'a', lockedB, 'ArrowRight'), 'c')
  assert.equal(nextRadioValue(values, 'd', lockedB, 'ArrowRight'), 'a', '右向循环回头')
  assert.equal(nextRadioValue(values, 'a', lockedB, 'ArrowLeft'), 'd', '左向循环到尾')
  assert.equal(nextRadioValue(values, 'c', lockedB, 'ArrowUp'), 'a', '上=左（跳过锁定）')
  assert.equal(nextRadioValue(values, 'c', lockedB, 'ArrowDown'), 'd')
  assert.equal(nextRadioValue(values, 'b', lockedB, 'ArrowRight'), 'a', '当前值不可用时前向从可用首项起算')
  assert.equal(nextRadioValue(values, 'b', lockedB, 'ArrowLeft'), 'd', '当前值不可用时后向从可用末项起算')
  assert.equal(nextRadioValue(values, 'c', lockedB, 'Home'), 'a')
  assert.equal(nextRadioValue(values, 'a', lockedB, 'End'), 'd')
  assert.equal(nextRadioValue(values, 'a', lockedB, 'Tab'), null, '非组内按键不处理')
  assert.equal(nextRadioValue(['a'], 'a', () => true, 'ArrowRight'), null)
})

test('负载策略卡：roving + 方向键 + 锁定项排除在可用集外', () => {
  const page = code('src/views/Rules.vue')
  const cards = section(page, 'class="strategy-cards"', '</el-tooltip>')
  assert.match(cards, /:tabindex="strategyTabindex\(card\.value\)"/)
  assert.match(cards, /@keydown="onStrategyKeydown\(\$event\)"/)
  assert.match(cards, /@keydown\.enter\.prevent="activateOnce\(\$event, \(\) => selectStrategy\(card\.value\)\)"/)
  const roving = section(page, 'const strategyLocked = ', 'const selectStrategy = ')
  assert.match(roving, /: boolean => ntlmOn\.value && value !== 'cookie'/, 'NTLM 接管时仅 cookie 可选')
  assert.match(roving, /rovingTabindex\(/)
  assert.match(roving, /nextRadioValue\(/)
})

test('服务控制卡：roving + 方向键 + 焦点跟进（四张卡片不再逐个 Tab）', () => {
  const page = code('src/views/settings/ClusterSettings.vue')
  const grid = section(page, 'class="service-control-grid"', '</div>\n      </div>')
  assert.match(grid, /role="radiogroup"/)
  assert.match(grid, /role="radio"/)
  assert.match(grid, /:aria-checked="serviceControlAction === item\.value"/)
  assert.match(grid, /:tabindex="serviceControlTabindex\(item\.value\)"/)
  assert.match(grid, /@keydown="onServiceCardKeydown\(\$event\)"/)
  assert.match(grid, /@keydown\.enter\.prevent="activateOnce\(\$event, \(\) => selectServiceAction\(item\.value\)\)"/)
  assert.doesNotMatch(grid, /tabindex="0"/, '不得每张卡片都是 tab stop')
  const handlers = section(page, 'const serviceCardRefs = new Map', 'const openServiceControlDialog')
  assert.match(handlers, /rovingTabindex\(serviceControlOptions\.map\(\(item\) => item\.value\), serviceControlAction\.value, \(\) => false, value\)/)
  assert.match(handlers, /nextRadioValue\(/)
  assert.match(handlers, /serviceCardRefs\.get\(next\)\?\.focus\(\)/)
})

test('威胁大屏 TOP 维度：APG roving、方向键与 tabpanel 关联', () => {
  const page = code('src/views/security/ThreatScreen.vue')
  const tabs = section(page, 'class="stat-tabs"', '</div>')
  assert.match(tabs, /role="tablist"/)
  assert.match(tabs, /@keydown="onStatTabKeydown"/)
  assert.match(tabs, /:tabindex="statTabindex\('targets'\)"/)
  assert.match(tabs, /:tabindex="statTabindex\('rules'\)"/)
  for (const value of ['targets', 'rules']) {
    assert.match(page, new RegExp(`id="threat-stat-tab-${value}"[^>]*aria-controls="threat-stat-panel-${value}"`))
    assert.match(page, new RegExp(`id="threat-stat-panel-${value}"[^>]*role="tabpanel"[^>]*aria-labelledby="threat-stat-tab-${value}"`))
  }
  const handlers = section(page, 'const statTabRefs = ', 'const peakSlot')
  assert.match(handlers, /rovingTabindex\(/)
  assert.match(handlers, /nextRadioValue\(/)
  assert.match(handlers, /statTabRefs\.get\(next\)\?\.focus\(\)/)
})

test('侧栏折叠入口：aria-expanded + aria-controls 指向导航，长按不反复切换', () => {
  const page = code('src/components/layout/AppLayout.vue')
  const logo = section(page, '<div class="logo-area"', '<AppLogo')
  assert.match(logo, /role="button"/)
  assert.match(logo, /:aria-expanded="!effectiveCollapsed"/, '读屏必须知道当前是否折叠')
  assert.match(logo, /aria-controls="app-sidebar-nav"/)
  assert.match(logo, /@keydown\.enter\.prevent="activateOnce\(\$event, toggleSidebar\)"/)
  assert.match(logo, /@click="toggleSidebar"/)
  assert.match(page, /<el-menu\s+id="app-sidebar-nav"/, 'aria-controls 目标必须存在')
  assert.match(page, /const toggleSidebar = \(\): void => \{ collapsed\.value = !collapsed\.value \}/)
})
