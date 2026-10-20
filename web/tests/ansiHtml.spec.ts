// 任务日志 ANSI SGR → HTML 的行为测试：颜色/样式栈、256 色与真彩、边界码位、
// 转义与未闭合样式的收尾。CSV/log 输出直接进 v-html，转义缺失即注入面。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { registerModuleHooks } from './_helpers.ts'

// ansi.ts 经 `@/utils/escape` 别名取共享转义实现，node 不认别名——先注册解析钩子。
// 静态 import 会先于钩子注册执行，故此处必须动态 import。
registerModuleHooks()
const { ansiToHtml } = await import('../src/utils/ansi.ts')

const ESC = '\u001b'
const color = (hex: string): string => `<span style="color:${hex}">`
const background = (hex: string): string => `<span style="background-color:${hex}">`

test('无转义序列原样返回，HTML 特殊字符全部转义', () => {
  assert.equal(ansiToHtml('hello'), 'hello')
  assert.equal(ansiToHtml('<b>&"x"\'</b>'), '&lt;b&gt;&amp;&quot;x&quot;&#39;&lt;/b&gt;')
})

test('基本前景色开合：着色段独立成 span，0 复位后不再包裹', () => {
  assert.equal(ansiToHtml(`${ESC}[31mred${ESC}[0m`), `${color('#ef4444')}red</span>`)
  assert.equal(ansiToHtml(`${ESC}[31ma${ESC}[0mb`), `${color('#ef4444')}a</span>b`)
})

test('组合码按顺序生效，样式串按 粗/斜/下划线/前景/背景 排列', () => {
  assert.equal(ansiToHtml(`${ESC}[1;31mx${ESC}[0m`), '<span style="font-weight:bold;color:#ef4444">x</span>')
  assert.equal(ansiToHtml(`${ESC}[3;4mx${ESC}[0m`), '<span style="font-style:italic;text-decoration:underline">x</span>')
  assert.equal(
    ansiToHtml(`${ESC}[31;41mx${ESC}[0m`),
    '<span style="color:#ef4444;background-color:#ef4444">x</span>',
  )
})

test('换色时先闭合上一段（不嵌套 span），未闭合样式在尾部自动收尾', () => {
  assert.equal(
    ansiToHtml(`${ESC}[31ma${ESC}[32mb${ESC}[0m`),
    `${color('#ef4444')}a</span>${color('#22c55e')}b</span>`,
  )
  assert.equal(ansiToHtml(`${ESC}[1mbold`), '<span style="font-weight:bold">bold</span>')
})

test('39/49 只清各自通道，另一通道保持', () => {
  assert.equal(ansiToHtml(`${ESC}[31ma${ESC}[39mb${ESC}[0m`), `${color('#ef4444')}a</span>b`)
  assert.equal(ansiToHtml(`${ESC}[41ma${ESC}[49mb${ESC}[0m`), `${background('#ef4444')}a</span>b`)
})

test('22/23/24 逐个关闭对应样式，其余样式保留', () => {
  assert.equal(
    ansiToHtml(`${ESC}[1;3mx${ESC}[22my${ESC}[0m`),
    '<span style="font-weight:bold;font-style:italic">x</span><span style="font-style:italic">y</span>',
  )
})

test('256 色：16-231 走 6×6×6 立方，232-255 走灰阶', () => {
  assert.equal(ansiToHtml(`${ESC}[38;5;196mx${ESC}[0m`), `${color('rgb(255,0,0)')}x</span>`)
  // 196 = 16 + 180 → r=levels[5]=255, g=levels[0]=0, b=levels[0]=0
  assert.equal(ansiToHtml(`${ESC}[48;5;232mx${ESC}[0m`), `${background('rgb(8,8,8)')}x</span>`)
  // 232 起灰阶：8 + (232-232)*10 = 8
  assert.equal(ansiToHtml(`${ESC}[38;5;300mx${ESC}[0m`), 'x', '越界索引不得产出颜色')
})

test('真彩 38;2 取值区间钳到 0-255', () => {
  assert.equal(ansiToHtml(`${ESC}[38;2;10;20;30mx${ESC}[0m`), `${color('rgb(10,20,30)')}x</span>`)
  assert.equal(ansiToHtml(`${ESC}[38;2;300;20;30mx${ESC}[0m`), `${color('rgb(255,20,30)')}x</span>`)
})

test('未知码位丢弃序列本身但不吞正文', () => {
  assert.equal(ansiToHtml(`${ESC}[99mx${ESC}[0m`), 'x')
  assert.equal(ansiToHtml(`before${ESC}[99mafter`), 'beforeafter')
})

test('空参数等价 0（复位）', () => {
  assert.equal(ansiToHtml(`${ESC}[31ma${ESC}[mb`), `${color('#ef4444')}a</span>b`)
})
