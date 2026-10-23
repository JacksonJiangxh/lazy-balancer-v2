// 测试侧 helper 单源：源码读取/限段/成员切片 + 假 DOM 宿主 + 模块解析钩子。
// SFC 源码钉 spec 共用 source()/section()/member()，不复刻各自的切片实现——缺
// marker 时 indexOf 返回 -1，切片会变空或倒置、断言空转（假绿）。此处所有边界
// 检查都是硬失败。
//
// 非 spec 文件（不以 .spec.ts 结尾），node --test tests/*.spec.ts 不会把它当用例。
//
// 导入风格约束（隐性 → 显式）：被 node --test 直接 import 的 src 模块链必须
// 使用相对路径 + .ts 扩展名（如 './x.ts'）——node 直跑 TS 无打包器别名/扩展名
// 解析（tsconfig allowImportingTsExtensions 仅为类型层面放行）；仅经打包器
// 消费的模块保持无扩展名风格。

import { readFileSync } from 'node:fs'
import { registerHooks } from 'node:module'
import { createRenderer } from 'vue'

const webRoot = new URL('../', import.meta.url)

// 源码读取缓存：同一文件（SecurityPolicies.vue / Rules.vue 等）被跨 spec 反复
// 读取数十次；测试只读源文件、无「读取前/后对比」用法，缓存安全。若未来出现
// 「写文件后重读」的用例，须绕开本 helper。
const sourceCache = new Map<string, string>()
const readCached = (url: URL): string => {
  const key = url.href
  const hit = sourceCache.get(key)
  if (hit !== undefined) return hit
  const text = readFileSync(url, 'utf8')
  sourceCache.set(key, text)
  return text
}

/** 读取相对 `web/` 的源文件（如 `'src/views/Rules.vue'`）。 */
export const source = (relative: string): string => readCached(new URL(relative, webRoot))

/** 读取相对仓库根的源文件（跨栈对表读 Go 声明用，如 `'internal/db/db.go'`）。 */
export const repoSource = (relative: string): string => readCached(new URL(`../${relative}`, webRoot))

/**
 * 剥注释视图的源文件读取。**代码存在性**正断言（`assert.match`/`includes` 找
 * 符号、调用、分支）应默认走本函数：注释掉实现是常见的临时手段，raw 视图下
 * 断言仍绿（假绿）。文案/模板文字断言（用户可见字符串）保留 raw。
 *
 * 例外只允许「文档钉」——断言的对象本就是注释文字时，用例名必须显式标注
 * 「文档钉」，避免被误认为行为覆盖。
 */
export const code = (relative: string): string => stripComments(source(relative))

/** 同 code，但读取相对仓库根的路径（跨栈 Go 源码存在性断言用）。 */
export const repoCode = (relative: string): string => stripComments(repoSource(relative))

/**
 * 从 startMarker 切到其后的 endMarker（endMarker 必须在 startMarker 之后）。
 * 缺任一 marker 或顺序倒置 → 抛错（而非返回空/倒置切片）；这是「限段钉」的统一边界。
 */
export const section = (text: string, startMarker: string, endMarker: string): string => {
  const start = text.indexOf(startMarker)
  if (start < 0) throw new Error(`missing start marker: ${startMarker}`)
  const end = text.indexOf(endMarker, start + startMarker.length)
  if (end <= start) throw new Error(`missing end marker: ${endMarker} after ${startMarker}`)
  return text.slice(start, end)
}

/**
 * 去掉注释（`//`、`/* *\/`、Vue 模板 `<!-- -->`），保留字符串字面量与正则字面量。
 * 死代码扫描必须先剥注释：注释里提到退役符号不构成生产消费，否则维护者被迫
 * 改写历史说明或放宽正则。
 *
 * 正则字面量（`/…/`）必须识别——否则 `/\/\//` 之后的真实引用会被当行注释吞掉
 * （假绿），正则里的 `/*` 会吞掉大段代码（假红）。判定规则（词法启发）：
 * `/` 前一非空白字符是标识符/数字/`)`/`]` 时按除法处理，否则进入正则态；
 * 正则态内遇未转义 `/` 或换行退出（字符类 `[...]` 内的 `/` 不退出）。
 */
export const stripComments = (text: string): string => {
  let out = ''
  let i = 0
  // 前一输出字符（跳过空白）+ 当前累积的标识符词——正则/除法歧义判定用：
  // `/` 前是标识符/数字/`)`/`]` 通常按除法，但标识符为关键字
  //（return/typeof/case 等不能作操作数）时仍按正则。
  let prevSignificant = ''
  let prevWord = ''
  const REGEX_PRECEDING_KEYWORDS: Record<string, true> = {
    return: true, typeof: true, case: true, in: true, of: true, new: true,
    delete: true, void: true, instanceof: true, yield: true, await: true, else: true, do: true,
  }
  const regexAllowedAfter = (): boolean => {
    if (prevSignificant === '') return true
    if (/[\w]/.test(prevSignificant)) return REGEX_PRECEDING_KEYWORDS[prevWord] === true
    return !/[)\]]/.test(prevSignificant)
  }
  while (i < text.length) {
    const ch = text[i]
    const next = text[i + 1]
    if (ch === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') i++
      continue
    }
    if (ch === '/' && next === '*') {
      i += 2
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++
      i += 2
      continue
    }
    if (ch === '<' && text.startsWith('<!--', i)) {
      const end = text.indexOf('-->', i + 4)
      i = end < 0 ? text.length : end + 3
      continue
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch
      out += ch
      i++
      while (i < text.length) {
        const c = text[i]
        out += c
        if (c === '\\' && i + 1 < text.length) {
          out += text[i + 1]
          i += 2
          continue
        }
        i++
        if (c === quote) break
      }
      prevSignificant = quote
      prevWord = ''
      continue
    }
    if (ch === '/' && regexAllowedAfter()) {
      // 正则字面量：原样保留到未转义的结束 `/`（字符类内的 / 不算结束）
      out += ch
      i++
      let inClass = false
      while (i < text.length) {
        const c = text[i]
        out += c
        i++
        if (c === '\\' && i < text.length) {
          out += text[i]
          i++
          continue
        }
        if (c === '[') inClass = true
        else if (c === ']') inClass = false
        else if (c === '/' && !inClass) break
        else if (c === '\n') break
      }
      prevSignificant = '/'
      prevWord = ''
      continue
    }
    out += ch
    if (/\s/.test(ch)) {
      // 空白不改词/字符状态
    } else if (/[\w]/.test(ch)) {
      prevWord = /[\w]/.test(prevSignificant) ? prevWord + ch : ch
      prevSignificant = ch
    } else {
      prevSignificant = ch
      prevWord = ''
    }
    i++
  }
  return out
}

/**
 * 成员体起点：marker 之后首个 `{` + 换行。
 *
 * 单表达式成员（`const h = () => ({ a: 1 })`）没有块体，`{\n` 会顺延到**下一个
 * 成员**的块体，切片因此越界（match 可被邻接代码满足=假绿，doesNotMatch 假红）。
 * 声明在候选 `{` 之前已结束——顶层 `;`，或行尾（顶层）`)`/`}`——一律硬失败：
 * 说明该 marker 指向的不是块体成员，唯一正确的修法是换一个可切片的成员。
 */
const memberBlockOpen = (text: string, start: number, marker: string): number => {
  const open = text.indexOf('{\n', start)
  if (open < 0) throw new Error(`member has no body: ${marker}`)
  type Mode = 'code' | 'line' | 'block' | 'single' | 'double' | 'template'
  let mode: Mode = 'code'
  let paren = 0
  let bracket = 0
  // 声明头里的顶层 `{...}` 只可能是类型/对象字面量（真正的函数体从 `{\n` 起算，
  // 不在扫描范围内）——其内的 `;`（返回类型对象的属性分隔）不构成声明结束。
  let typeBraces = 0
  let lastSignificant = ''
  for (let i = start; i < open; i++) {
    const ch = text[i]
    const next = text[i + 1]
    if (mode === 'line') {
      if (ch === '\n') mode = 'code'
      continue
    }
    if (mode === 'block') {
      if (ch === '*' && next === '/') { mode = 'code'; i++ }
      continue
    }
    if (mode === 'single' || mode === 'double') {
      const quote = mode === 'single' ? "'" : '"'
      if (ch === '\\') i++
      else if (ch === quote) mode = 'code'
      continue
    }
    if (mode === 'template') {
      if (ch === '\\') i++
      else if (ch === '`') mode = 'code'
      continue
    }
    if (ch === '/' && next === '/') { mode = 'line'; i++; continue }
    if (ch === '/' && next === '*') { mode = 'block'; i++; continue }
    if (ch === '"') { mode = 'double'; lastSignificant = ch; continue }
    if (ch === "'") { mode = 'single'; lastSignificant = ch; continue }
    if (ch === '`') { mode = 'template'; lastSignificant = ch; continue }
    if (ch === '(') { paren++; lastSignificant = ch; continue }
    if (ch === ')') { paren--; lastSignificant = ch; continue }
    if (ch === '[') { bracket++; lastSignificant = ch; continue }
    if (ch === ']') { bracket--; lastSignificant = ch; continue }
    if (ch === '{') {
      if (paren <= 0 && bracket <= 0) typeBraces++
      lastSignificant = ch
      continue
    }
    if (ch === '}') {
      if (paren <= 0 && bracket <= 0 && typeBraces > 0) typeBraces--
      lastSignificant = ch
      continue
    }
    if (ch === '\n') {
      // 顶层行尾落在 `)`/`}` = 声明已结束（单表达式箭头体 / 对象字面量成员）；
      // 缩进内的续行（参数表/类型注解）不在此列。
      if (paren <= 0 && bracket <= 0 && typeBraces === 0 && (lastSignificant === ')' || lastSignificant === '}')) {
        throw new Error(`member has no block body: ${marker}`)
      }
      continue
    }
    if (ch === ';' && paren <= 0 && bracket <= 0 && typeBraces === 0) {
      throw new Error(`member has no block body: ${marker}`)
    }
    if (!/\s/.test(ch)) lastSignificant = ch
  }
  return open
}

/**
 * 截取成员体：从 marker 处的函数/方法声明花括号配对到收尾。
 *
 * 必须按花括号配对——固定缩进启发式（找第一个 `\n    }`）会在函数内第一个内层
 * 块收尾处截断，块内文本的 doesNotMatch 断言因此空转（假绿）。
 *
 * 配对必须跳过字符串/模板量/注释里的括号：`const s = '}'` 或注释里的孤立 `}`
 * 会让切片提前收尾（后续 doesNotMatch 假绿）；孤立 `{` 则越界吞下相邻函数
 * （match 假绿）。模板量里的 `${...}` 是表达式，其内部括号按代码计。
 *
 * 函数体起点取 marker 之后首个 `{\n`：参数表里的对象类型字面量
 * （`opts?: { a: 1 }`）后面不跟换行，不会被误认。
 */
export const member = (text: string, marker: string): string => {
  const start = text.indexOf(marker)
  if (start < 0) throw new Error(`missing member: ${marker}`)
  const open = memberBlockOpen(text, start, marker)
  type Mode = 'code' | 'line' | 'block' | 'single' | 'double' | 'template'
  let mode: Mode = 'code'
  let depth = 0
  // 进入模板量 `${` 时记录当前 depth；同 depth 的 `}` 返回模板量文本。
  const templateExprDepths: number[] = []
  for (let i = open; i < text.length; i++) {
    const ch = text[i]
    const next = text[i + 1]
    if (mode === 'line') {
      if (ch === '\n') mode = 'code'
      continue
    }
    if (mode === 'block') {
      if (ch === '*' && next === '/') { mode = 'code'; i++ }
      continue
    }
    if (mode === 'single' || mode === 'double') {
      const quote = mode === 'single' ? "'" : '"'
      if (ch === '\\') i++
      else if (ch === quote) mode = 'code'
      continue
    }
    if (mode === 'template') {
      if (ch === '\\') i++
      else if (ch === '`') mode = 'code'
      else if (ch === '$' && next === '{') { templateExprDepths.push(depth); mode = 'code'; i++ }
      continue
    }
    if (ch === '/' && next === '/') { mode = 'line'; i++; continue }
    if (ch === '/' && next === '*') { mode = 'block'; i++; continue }
    if (ch === '"') { mode = 'double'; continue }
    if (ch === "'") { mode = 'single'; continue }
    if (ch === '`') { mode = 'template'; continue }
    if (ch === '{') { depth++; continue }
    if (ch === '}') {
      if (templateExprDepths.length > 0 && templateExprDepths[templateExprDepths.length - 1] === depth) {
        templateExprDepths.pop()
        mode = 'template'
        continue
      }
      depth--
      if (depth === 0) return text.slice(start, i + 1)
    }
  }
  throw new Error(`unbalanced braces in member: ${marker}`)
}

/** 最小 document 宿主：只提供 hidden + visibilitychange 监听（composable 消费面）。 */
export class FakeDocument {
  hidden = false
  private readonly listeners = new Set<() => void>()
  addEventListener(_type: 'visibilitychange', listener: () => void): void { this.listeners.add(listener) }
  removeEventListener(_type: 'visibilitychange', listener: () => void): void { this.listeners.delete(listener) }
  dispatch(): void { for (const listener of [...this.listeners]) listener() }
  get listenerCount(): number { return this.listeners.size }
}

/** 最小 window 宿主：只提供 setInterval/clearInterval 与手动点火。 */
export class FakeWindow {
  private nextId = 1
  private readonly timers = new Map<number, () => void>()
  setInterval(callback: () => void): number {
    const id = this.nextId++
    this.timers.set(id, callback)
    return id
  }
  clearInterval(id: number): void { this.timers.delete(id) }
  fire(): void { for (const callback of [...this.timers.values()]) callback() }
  get size(): number { return this.timers.size }
}

/**
 * 无 DOM 的组件宿主：`setup()` 在真实组件实例内执行，`unmount()` 触发
 * `onUnmounted`。SSR 渲染（renderToString）不执行卸载钩子——卸载清理（停定时器/
 * 取消帧/摘监听）只能用真实 mount + unmount 覆盖，否则钩子被删也全绿。
 */
export const mountForLifecycle = (setup: () => void): { unmount: () => void } => {
  const app = createRenderer<object, object>({
    createElement: (): object => ({}),
    createText: (): object => ({}),
    createComment: (): object => ({}),
    setText: (): void => {},
    setElementText: (): void => {},
    insert: (): void => {},
    remove: (): void => {},
    parentNode: (): null => null,
    nextSibling: (): null => null,
    patchProp: (): void => {},
  }).createApp({ setup, render: () => null })
  app.mount({})
  return { unmount: () => app.unmount() }
}

const srcRoot = new URL('../src/', import.meta.url)

/**
 * 让 `node --test` 直接加载 src 模块：解析 `@/…` 别名，并把 replacements 里的
 * 规格符替换为给定模块（测试替身 / 失败模块）。字节级依赖（element-plus 的
 * CSS 导入、1.9MB 省界表）不进测试进程。
 *
 * 必须在 `await import(...)` 之前调用——静态 import 先于本模块代码执行。
 * replacement 为函数时按次求值（可表达「首次失败、重试成功」）。
 */
// 模块解析钩子：`@/x` → src/x.ts。仅当 specifier 没有扩展名时补 `.ts`——
// 无条件拼接会把 `@/views/X.vue` 解析成 `X.vue.ts` 而失败。钩子是进程级、
// 只能累积（registerHooks 无注销面）：单个 spec 文件只注册一次、不支持 .vue
// 装载（模板级行为测试需另行方案，见 viewsCore 的静态 import 自检守卫）。
export const registerModuleHooks = (replacements: Record<string, string | (() => string)> = {}): void => {
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const replacement = replacements[specifier]
      if (replacement) return { url: typeof replacement === 'function' ? replacement() : replacement, shortCircuit: true }
      if (specifier.startsWith('@/')) {
        const target = specifier.slice(2)
        const withExtension = /\.[a-z0-9]+$/i.test(target) ? target : `${target}.ts`
        return nextResolve(new URL(withExtension, srcRoot).href, context)
      }
      return nextResolve(specifier, context)
    },
  })
}
