// 测试侧源码读取/限段 helper 单源（审计 87 WEBT-06）：
// 5 个 SFC 源码钉 spec 此前各自复制 source()/section()/sectionBetween()，且实现
// 已漂移（audit85Rules 无 end>start 检查）——缺 marker 时 indexOf 返回 -1，切片
// 变空、断言空转（假绿）。此处统一实现并把两个边界检查都做成硬失败。
//
// 非 spec 文件（不以 .spec.ts 结尾），node --test tests/*.spec.ts 不会把它当用例。

import { readFileSync } from 'node:fs'

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
