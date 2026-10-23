// _helpers.stripComments 自测：注释剥离必须保留字符串与正则字面量——
// 正则里的 `//`/`/*` 被误当注释会吞掉其后的真实引用（死代码扫描假绿/假红）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { member, section, stripComments } from './_helpers.ts'

test('section：缺 start / 缺 end / 顺序倒置一律抛错（边界不得空转）', () => {
  assert.throws(() => section('abc', 'x', 'c'), /missing start marker/)
  assert.throws(() => section('abc', 'a', 'x'), /missing end marker/)
  // end 只出现在 start 之前：不得返回倒置切片，必须抛错
  assert.throws(() => section('ba', 'a', 'b'), /missing end marker/)
  assert.equal(section('abc', 'a', 'c'), 'ab')
})

test('member：缺 marker / 无函数体 / 括号不平衡一律抛错', () => {
  assert.throws(() => member('const a = 1\n', 'const b'), /missing member/)
  assert.throws(() => member('const a = 1\n', 'const a'), /member has no body/)
  // 花括号未闭合：若 helper 改成「容错返回剩余文本」，数百条文本钉会同时空转，
  // 必须硬失败。
  assert.throws(() => member('function f() {\n  if (x) {\n', 'function f'), /unbalanced braces/)
})

test('member：单表达式箭头体不得顺延到下一个成员（越界切片）', () => {
  const src = 'const h = () => ({ a: 1 })\nconst k = () => {\n  return 9\n}\n'
  // 切片若顺延到 const k，match 可被邻接成员满足（假绿）、doesNotMatch 假红
  assert.throws(() => member(src, 'const h = '), /member has no block body/)
  // 块体成员仍正常切到自身收尾
  const k = member(src, 'const k = ')
  assert.match(k, /return 9/)
  assert.doesNotMatch(k, /const h/, '切片不得回吞前一个成员')
})

test('member：模板量 ${} 内嵌对象既不提前收尾也不越界', () => {
  const src = 'const f = () => {\n  const s = `a${ { b: 1 } }c`\n  return s\n}\nconst g = () => {\n  return 2\n}\n'
  const slice = member(src, 'const f = ')
  assert.match(slice, /return s/)
  assert.doesNotMatch(slice, /return 2/, '切片不得吞下下一个成员')
})

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
