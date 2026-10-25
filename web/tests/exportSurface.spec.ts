// 导出面 ≤ 消费面门禁：定义目录里的具名导出必须存在「定义文件之外」的消费方，
// 否则它就是模块内私有物（export 会让读者误以为它是跨模块稳定契约，进而绕开
// 单源直接构造内部形状）。
//
// 为什么落成门禁：这类残留反复出现——人工 grep 收口每次都能收敛一部分却从未
// 归零，而且新增文件（如本单元的动作映射单源）本身就会又一次带出同族导出。
// 判据机械化后，新增残留会在测试门禁上直接失败。
//
// 口径（与全仓 grep 的消费面扫描一致）：
// - 定义面 = src/utils、src/composables、src/stores、src/types 下的 .ts/.vue；
// - 消费面 = src/**.ts/.vue + tests/**.ts（含用例对符号的按名引用）；
// - 两侧都走注释剥离视图：注释掉的 export 不算符号，注释里的引用不算消费
//   （否则注释掉用法会让死导出永远留在门槛内）；
// - 同名符号跨模块冲突时，任一文件的消费都会算作命中——本门禁是下限，不做
//   逐模块消歧。
//
// 无需白名单：`Pick<>`/`Omit<>`/`typeof` 等跨文件引用本身就带符号名，自然计入
// 消费面；真正零消费的导出只应改为模块私有（确需跨模块时先有消费方）。

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { code, webFiles } from './_helpers.ts'

const DEFINITION_DIRS = ['src/utils', 'src/composables', 'src/stores', 'src/types'] as const
const SOURCE_EXTENSIONS = ['.ts', '.vue'] as const

// `export const X` / `export async function X` / `export declare const X` …；
// `export default` 与 `export * from` 不是具名导出，不参与判定。
const DECLARATION = /^export\s+(?:(?:declare|abstract)\s+)*(?:(?:async)\s+)?(?:const|let|var|function|class|interface|type|enum)\s+([A-Za-z_$][\w$]*)/
// `export { a, b as c }` / `export type { A }`：导出名取 `as` 右侧。
const NAMED_EXPORT = /^export\s+(?:type\s+)?\{([^}]*)\}/

/** 源文件里的具名导出名（单行形态；含 `as` 别名取右侧）。 */
const exportedNames = (text: string): string[] => {
  const names: string[] = []
  for (const line of text.split('\n')) {
    const declaration = DECLARATION.exec(line)
    if (declaration) {
      names.push(declaration[1])
      continue
    }
    const named = NAMED_EXPORT.exec(line)
    if (!named) continue
    for (const part of named[1].split(',')) {
      const exported = part.trim().split(/\s+as\s+/).pop()?.trim()
      if (exported) names.push(exported)
    }
  }
  return names
}

/** token → 出现过该 token 的文件集合（消费面索引，供逐符号查外部命中）。 */
const buildTokenIndex = (files: readonly string[]): Map<string, Set<string>> => {
  const index = new Map<string, Set<string>>()
  for (const file of files) {
    for (const [token] of code(file).matchAll(/[A-Za-z_$][\w$]*/g)) {
      const holders = index.get(token)
      if (holders) holders.add(file)
      else index.set(token, new Set([file]))
    }
  }
  return index
}

/**
 * 零外部消费的导出清单。`definitions` = 文件名 → 注释剥离视图（便于用合成源码
 * 直接验证判据）；`tokenIndex` = 消费面的 token 索引。
 */
const findUnusedExports = (
  definitions: ReadonlyMap<string, string>,
  tokenIndex: ReadonlyMap<string, ReadonlySet<string>>,
): { checked: number; unused: string[] } => {
  const unused: string[] = []
  let checked = 0
  for (const [file, text] of definitions) {
    for (const name of exportedNames(text)) {
      checked++
      const holders = tokenIndex.get(name)
      const consumedOutside = holders !== undefined
        && [...holders].some((holder) => holder !== file)
      if (!consumedOutside) unused.push(`${file} → ${name}`)
    }
  }
  return { checked, unused }
}

const definitionFiles = DEFINITION_DIRS.flatMap((dir) => webFiles(dir, SOURCE_EXTENSIONS))
const definitionSources = new Map(definitionFiles.map((file) => [file, code(file)] as const))
const consumerFiles = [...webFiles('src', SOURCE_EXTENSIONS), ...webFiles('tests', ['.ts'])]

test('定义目录的每个具名导出都有定义文件之外的消费方', () => {
  const { checked, unused } = findUnusedExports(definitionSources, buildTokenIndex(consumerFiles))
  // 扫描面自检：解析器失效（正则不再匹配）会让清单恒空——那是最容易发生的假绿。
  assert.ok(definitionFiles.length >= 100, `定义面文件数异常偏少（${definitionFiles.length}），扫描目录配置已失效`)
  assert.ok(checked >= 400, `解析到的具名导出异常偏少（${checked}），导出声明正则已失效`)
  assert.deepEqual(
    unused,
    [],
    '零外部消费的导出必须改为模块私有（确需跨模块导出时先落消费方）：\n' + unused.join('\n'),
  )
})

test('判据不是空转：外部消费 / 仅本文件自用 / 无任何引用 三种形态区分得开', () => {
  const definitions = new Map([
    ['src/utils/a.ts', 'export const consumed = 1\nexport const selfOnly = 2\nexport const orphan = 3'],
  ])
  const tokenIndex = new Map([
    ['consumed', new Set(['src/utils/a.ts', 'src/views/Use.vue'])],
    ['selfOnly', new Set(['src/utils/a.ts'])],
  ])
  assert.deepEqual(findUnusedExports(definitions, tokenIndex), {
    checked: 3,
    unused: ['src/utils/a.ts → selfOnly', 'src/utils/a.ts → orphan'],
  })
})

test('导出名解析覆盖声明形态与 as 别名（正则退化会静默漏检）', () => {
  assert.deepEqual(
    exportedNames([
      'export const a = 1',
      'export async function b() {}',
      'export interface C {}',
      'export type D = string',
      'export declare const e: number',
      'export { f, g as h }',
      'export type { I }',
      'export * from "./x"',
      'export default {}',
      '// export const commented = 1',
    ].join('\n')),
    ['a', 'b', 'C', 'D', 'e', 'f', 'h', 'I'],
  )
})
