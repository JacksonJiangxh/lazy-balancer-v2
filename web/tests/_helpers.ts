// 测试侧 helper 单源：源码读取/限段 + 模块解析钩子（`@/` 别名与重型依赖替身）。
// SFC 源码钉 spec 共用 source()/section()，不复刻各自的切片实现——缺 marker 时
// indexOf 返回 -1，切片会变空或倒置、断言空转（假绿）。此处把两个边界检查都做成硬失败。
//
// 非 spec 文件（不以 .spec.ts 结尾），node --test tests/*.spec.ts 不会把它当用例。

import { readFileSync } from 'node:fs'
import { registerHooks } from 'node:module'

/** 读取相对 `web/` 的源文件（如 `'src/views/Rules.vue'`）。 */
export const source = (relative: string): string => readFileSync(new URL(`../${relative}`, import.meta.url), 'utf8')

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
