// 威胁大屏全屏布局与隐藏停摆的组件接线钉：App.vue 全屏分支不进布局壳、
// 大屏页把三类定时器交给 createVisibilityIntervals 纳管（行为求值见
// visibilityIntervals.spec.ts），以及死选择器/空态文案清理。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { section, source } from './_helpers.ts'

test('大屏全屏分支不进 AppLayout（侧栏顶栏不得渲染）', () => {
  const app = source('src/App.vue')
  // 终点用「顶层 template 收尾 + script 起点」而非首个 `</template>`——当前
  // App.vue 无嵌套 template，但模板一引入嵌套（el-table 插槽等）首标记即截断，
  // 断言对象会悄悄变短。
  const template = section(app, '<template>', '\n</template>\n\n<script')
  const threatIdx = template.indexOf(`<ThreatScreen v-else-if="currentPage === 'threat-screen'" />`)
  assert.ok(threatIdx > 0, '缺大屏全屏分支')
  const layoutIdx = template.indexOf('<AppLayout')
  assert.ok(threatIdx < layoutIdx, '大屏分支必须先于 AppLayout（v-else-if 短路）')
  assert.match(template.slice(layoutIdx), /^<AppLayout v-else>/, 'AppLayout 必须是 v-else——大屏页不得套布局壳')
  assert.ok(!section(template, '<AppLayout', '</AppLayout>').includes('ThreatScreen'), '大屏不得在 AppLayout 内部渲染')
  // 页面键唯一事实源含 threat-screen（抽取真实数组求值）
  const auth = source('src/stores/auth.ts')
  const pagesBlock = section(auth, 'const pages = [', '] as const').slice('const pages = ['.length)
  const pages = new Function(`return [${pagesBlock}]`)() as string[]
  assert.ok(pages.includes('threat-screen'), 'auth 页面键缺 threat-screen（深链/刷新恢复会失效）')
})

// ---- 组件接线钉（间隔调度行为见 visibilityIntervals.spec.ts） ----
test('ThreatScreen 经 createVisibilityIntervals 接管 hidden 停摆', () => {
  const page = source('src/views/security/ThreatScreen.vue')
  assert.match(page, /import \{ createVisibilityIntervals \} from '@\/composables\/useVisibilityIntervals'/)
  const loopBlock = section(page, 'const screenLoop = createVisibilityIntervals({', '})')
  // 三类间隔全部纳管：时钟(1s, immediate)/弧光冲刷(ARC_FLUSH_MS)/采集租约心跳(immediate)
  assert.match(loopBlock, /\{ tick: tickClock, ms: 1000, immediate: true \}/)
  assert.match(loopBlock, /\{ tick: flushArcs, ms: ARC_FLUSH_MS \}/)
  assert.match(loopBlock, /\{ tick: acquireCollector, ms: COLLECTOR_HEARTBEAT_MS, immediate: true \}/)
  // hidden 回调必须释放租约；visible 回调必须重置流量游标
  const onHidden = section(page, 'onHidden: () => {', 'onVisible: () => {')
  assert.match(onHidden, /releaseCollector\(\)/, 'hidden 不释放租约=Caddy 后台空计数')
  const onVisible = section(page, 'onVisible: () => {', '\n})')
  assert.match(onVisible, /flowCursorEpoch\+\+/)
  assert.match(onVisible, /applyMapPause\(\)/)
  // SFC 内不得再直挂 visibilitychange（单源在 composable）
  assert.doesNotMatch(page, /document\.(add|remove)EventListener\('visibilitychange'/)
  // 渲染暂停判据=手动暂停 ∨ 页面隐藏
  const pauseBlock = section(page, 'function applyMapPause(): void {', '}')
  assert.match(pauseBlock, /setPaused\(paused\.value \|\| screenHidden\)/)
  // 卸载收尾：停 loop + 释放租约
  const unmountBlock = section(page, 'onBeforeUnmount(() => {', '})')
  assert.match(unmountBlock, /screenLoop\.stop\(\)/)
  assert.match(unmountBlock, /releaseCollector\(\)/)
})

test('威胁大屏死选择器清理与「被攻击目标」空态文案', () => {
  const page = source('src/views/security/ThreatScreen.vue')
  assert.doesNotMatch(page, /\.ev-icon svg/)
  assert.doesNotMatch(page, /\.scanline/)
  assert.doesNotMatch(page, /\.viewport-grid/)
  assert.match(page, /<div v-else class="empty">暂无目标数据<\/div>/)
})
