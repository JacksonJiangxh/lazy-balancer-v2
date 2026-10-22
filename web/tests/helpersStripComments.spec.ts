// _helpers.stripComments 自测：注释剥离必须保留字符串与正则字面量——
// 正则里的 `//`/`/*` 被误当注释会吞掉其后的真实引用（死代码扫描假绿/假红）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { stripComments } from './_helpers.ts'

test('行注释与块注释被剥离，字符串字面量保留', () => {
  const src = "const a = 1 // trailing\n/* block */ const b = '// not comment'\nconst c = `/* tpl */`"
  const out = stripComments(src)
  assert.doesNotMatch(out, /trailing|block/)
  assert.match(out, /'\/\/ not comment'/)
  assert.match(out, /`\/\* tpl \*\/`/)
})

test('正则字面量内的注释记号不触发剥离', () => {
  // 关键：代码与正则同行——`//`/`/*` 被误当注释会吞掉同行后续真实引用
  const src = "const re = /\\/\\//; afterCall(re)\nconst re2 = /\\/\\*/g; secondCall(re2)"
  const out = stripComments(src)
  assert.match(out, /\/\\\/\\\/\/; afterCall\(re\)/, '正则后的同行代码不得被当行注释吞掉')
  assert.match(out, /g; secondCall\(re2\)/, '正则内的 /* 不得吞掉同行后续代码')
})

test('关键字后的斜杠按正则处理（return/typeof/case）', () => {
  const src = 'function f() { return /a\\/\\/b/.test(x) }\nf()'
  const out = stripComments(src)
  assert.match(out, /f\(\)\s*$/, 'return 后的正则不得截断后续代码')
})

test('除法语义不误判为正则（操作数为标识符/数字/闭括号）', () => {
  const src = 'const q = a / b\nconst r = x / 2 // note\nconst s = (1 + 2) / 3'
  const out = stripComments(src)
  assert.match(out, /a \/ b/)
  assert.match(out, /x \/ 2/)
  assert.doesNotMatch(out, /note/)
  assert.match(out, /\(1 \+ 2\) \/ 3/)
})

test('Vue 模板注释剥离', () => {
  const out = stripComments('<div><!-- hidden --><span>ok</span></div>')
  assert.doesNotMatch(out, /hidden/)
  assert.match(out, /<span>ok<\/span>/)
})
