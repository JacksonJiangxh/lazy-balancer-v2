/**
 * 原型安全的自有属性判定（单源小函数）。
 *
 * 展示层/状态层有多张「普通对象字面量 + 外部字符串键」查表：直接下标会把
 * 原型链上的 constructor / toString / __proto__ 当成命中，返回 Object.prototype
 * 上的函数——`??`/`||` 兜底被绕过（模板渲染出函数源码），或把「无值」判成
 * 「有值」。凡是以任意字符串为键查映射的地方都必须先经本守卫。
 */
export const hasOwn = (table: object, key: PropertyKey): boolean =>
  Object.prototype.hasOwnProperty.call(table, key)
