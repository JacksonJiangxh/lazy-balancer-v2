// 测试侧 helper 单源：源码读取/限段/成员切片 + 假 DOM 宿主 + 模块解析钩子。
// SFC 源码钉 spec 共用 source()/section()/member()，不复刻各自的切片实现——缺
// marker 时 indexOf 返回 -1，切片会变空或倒置、断言空转（假绿）。此处所有边界
// 检查都是硬失败。
//
// 非 spec 文件（不以 .spec.ts 结尾），node --test tests/*.spec.ts 不会把它当用例。

import { readFileSync } from 'node:fs'
import { registerHooks } from 'node:module'

const webRoot = new URL('../', import.meta.url)

/** 读取相对 `web/` 的源文件（如 `'src/views/Rules.vue'`）。 */
export const source = (relative: string): string => readFileSync(new URL(relative, webRoot), 'utf8')

/** 读取相对仓库根的源文件（跨栈对表读 Go 声明用，如 `'internal/db/db.go'`）。 */
export const repoSource = (relative: string): string => readFileSync(new URL(`../${relative}`, webRoot), 'utf8')

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
 * 截取成员体：从 marker 处的函数/方法声明花括号配对到收尾。
 *
 * 必须按花括号配对——固定缩进启发式（找第一个 `\n    }`）会在函数内第一个内层
 * 块收尾处截断，块内文本的 doesNotMatch 断言因此空转（假绿）。
 *
 * 函数体起点取 marker 之后首个 `{\n`：参数表里的对象类型字面量
 * （`opts?: { a: 1 }`）后面不跟换行，不会被误认。
 */
export const member = (text: string, marker: string): string => {
  const start = text.indexOf(marker)
  if (start < 0) throw new Error(`missing member: ${marker}`)
  const open = text.indexOf('{\n', start)
  if (open < 0) throw new Error(`member has no body: ${marker}`)
  let depth = 0
  for (let i = open; i < text.length; i++) {
    if (text[i] === '{') depth++
    else if (text[i] === '}' && --depth === 0) return text.slice(start, i + 1)
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

const srcRoot = new URL('../src/', import.meta.url)

/**
 * 让 `node --test` 直接加载 src 模块：解析 `@/…` 别名，并把 replacements 里的
 * 规格符替换为给定模块（测试替身 / 失败模块）。字节级依赖（element-plus 的
 * CSS 导入、1.9MB 省界表）不进测试进程。
 *
 * 必须在 `await import(...)` 之前调用——静态 import 先于本模块代码执行。
 * replacement 为函数时按次求值（可表达「首次失败、重试成功」）。
 */
export const registerModuleHooks = (replacements: Record<string, string | (() => string)> = {}): void => {
  registerHooks({
    resolve(specifier, context, nextResolve) {
      const replacement = replacements[specifier]
      if (replacement) return { url: typeof replacement === 'function' ? replacement() : replacement, shortCircuit: true }
      if (specifier.startsWith('@/')) return nextResolve(new URL(`${specifier.slice(2)}.ts`, srcRoot).href, context)
      return nextResolve(specifier, context)
    },
  })
}
