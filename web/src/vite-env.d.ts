/// <reference types="vite/client" />

// *.vue 模块声明垫片已移除（vite/client 的 shim 也仅在模块解析失败时命中，
// 会把拼错的 .vue 导入静默当成 DefineComponent<{},{},any>，丢失 props/emits
// 类型检查）。vue-tsc 对真实 SFC 走实体解析，缺失导入会报 Cannot find module。
