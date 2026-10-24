// _helpers.stripComments 自测：注释剥离必须保留字符串与正则字面量——
// 正则里的 `//`/`/*` 被误当注释会吞掉其后的真实引用（死代码扫描假绿/假红）。
//
// 运行：cd web && npm test

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

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

// 多行返回类型：`): {\n … } => {` 里首个 `{\n` 是类型注解。若把它当函数体，切片在
// 类型块收尾处结束，函数体整段不进切片——后续所有 doesNotMatch 恒真。
test('member：多行返回类型不得被当函数体（切片必须进入真实块体）', () => {
  const src = [
    'const f = (',
    '  x: number,',
    '): {',
    '  a: number',
    '} => {',
    '  return x',
    '}',
    'const g = () => {',
    '  return 2',
    '}',
    '',
  ].join('\n')
  const slice = member(src, 'const f = ')
  assert.match(slice, /return x/, '切片必须进入真实函数体')
  assert.doesNotMatch(slice, /return 2/, '切片不得吞下下一个成员')
  assert.doesNotMatch(slice, /const g/, '切片不得越界到下一个成员')
})

test('member：参数表内多行对象类型与函数声明返回类型同样跳过', () => {
  const paramType = 'function f(opts: {\n  a: number\n}): string {\n  return String(opts.a)\n}\n'
  assert.match(member(paramType, 'function f('), /return String/)
  const returnType = 'function g(): {\n  a: number\n} {\n  return 1\n}\nfunction h() {\n  return 2\n}\n'
  const slice = member(returnType, 'function g(')
  assert.match(slice, /return 1/)
  assert.doesNotMatch(slice, /function h/, '返回类型块后的函数体才算收尾')
})

test('section/member：注释里的同名 marker 不得命中（切片落进注释=假绿）', () => {
  const src = [
    'const k = 1',
    '// 说明：const k2 与 const k9 的旧形态如下，return 语义无关',
    'const k2 = (): string => {',
    "  return 'k'",
    '}',
    '',
  ].join('\n')
  // 注释里出现 marker：跳过注释，切到真实声明
  const seg = section(src, 'const k2', 'return')
  assert.doesNotMatch(seg, /说明/, 'section 起点不得落在注释中段')
  assert.match(seg, /const k2 = /)
  const slice = member(src, 'const k2')
  assert.match(slice, /return 'k'/)
  assert.doesNotMatch(slice, /说明/)
  // 只存在于注释里的 marker：代码里没有 → 硬失败（不得切到注释中段）
  assert.throws(() => section(src, 'const k9', 'x'), /missing start marker/)
  // 文档钉（断言对象本就是注释）仍按字面命中
  assert.match(section(src, '// 说明：', 'const k2'), /return 语义无关/)
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

test('脚本存在性断言文件禁止裸 source()/repoSource() 回流', () => {
  // 这些 spec 的断言对象是「脚本/Go 里某段实现仍在」：注释化实现是最常见的
  // 临时停用手段，raw 视图下注释里的代码仍满足断言（假绿）。已全量改走
  // code()/repoCode()，此门禁止把裸导入加回来（新增文件按同一判别表处理：
  // 模板文案/注释钉用 raw，代码存在性用 code）。
  const locked = [
    'viewsWiringGuards.spec.ts',
    'rulesUi.spec.ts',
    'securityBulk.spec.ts',
    'securityPoliciesWiring.spec.ts',
    'authRole.spec.ts',
    // 断言对象全是脚本/Go 实现（无模板文案钉），已全量改走 code()/repoCode()。
    'ingestionHealth.spec.ts',
    'autobanStatus.spec.ts',
    'certJobStatus.spec.ts',
    'countUpTween.spec.ts',
    'importFailure.spec.ts',
    'importPreview.spec.ts',
  ]
  for (const name of locked) {
    const text = readFileSync(new URL(`./${name}`, import.meta.url), 'utf8')
    assert.doesNotMatch(
      text,
      /import \{[^}]*\b(?:source|repoSource)\b[^}]*\} from '\.\/_helpers\.ts'/,
      `${name} 不得导入裸 source/repoSource`,
    )
    assert.doesNotMatch(text, /(^|[^A-Za-z_.])(?:source|repoSource)\(/m, `${name} 仍有裸取源调用`)
  }
})
