/**
 * 自定义单选组（role="radiogroup" + 逐卡片 role="radio"）的键盘语义：
 * roving tabindex（整组只有一个 tab stop）+ 方向键移动选择。
 *
 * 卡片组的既有实现是所有卡片 tabindex=0、且只认 Enter/Space——与原生单选组
 * （APG：Tab 进组一次，方向键在选项间移动并切换）不一致，四张服务控制卡片
 * 要逐个 Tab。这里只放纯计算，DOM 焦点由调用方在同一次按键里跟进。
 */

/** 方向键/Home/End 在「可选项」之间循环移动；返回 null 表示该键不归单选组处理。 */
export function nextRadioValue(
  values: readonly string[],
  selected: string,
  disabled: (value: string) => boolean,
  key: string,
): string | null {
  const enabled = values.filter((value) => !disabled(value))
  if (enabled.length === 0) return null
  const current = enabled.indexOf(selected)
  switch (key) {
    case 'ArrowRight':
    case 'ArrowDown':
      // 选中项不在可选项内（或未选）时，向下一步从组首开始
      return current < 0 ? enabled[0]! : enabled[(current + 1) % enabled.length]!
    case 'ArrowLeft':
    case 'ArrowUp':
      return current < 0 ? enabled[enabled.length - 1]! : enabled[(current - 1 + enabled.length) % enabled.length]!
    case 'Home':
      return enabled[0]!
    case 'End':
      return enabled[enabled.length - 1]!
    default:
      return null
  }
}

/**
 * roving tabindex：选中项是唯一 tab stop；选中项不可用（或未选）时退到首个
 * 可选项——否则整组不可 Tab 进入。无可用项时全组 -1。
 */
export function rovingTabindex(
  values: readonly string[],
  selected: string,
  disabled: (value: string) => boolean,
  value: string,
): number {
  const enabled = values.filter((item) => !disabled(item))
  if (enabled.length === 0) return -1
  const target = enabled.includes(selected) ? selected : enabled[0]!
  return value === target ? 0 : -1
}
