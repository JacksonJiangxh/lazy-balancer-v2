// 站内字节格式化单源（1024 进制、最多两位小数并去掉尾零、量级到 TB）。
//
// 原实现挂在 utils/api.ts 上，仅因它最先被日志占用条使用；采集健康位
// （ingestionHealth）另写了一版私有 humanBytes（一位小数、上限 GB）——同一份
// 1,500,000 字节在日志占用条显示 1.43 MB、在摄取告警显示 1.5 MB，运维对账要
// 二次换算。格式化与取数无关，下沉到零依赖模块：
//   - 本模块**不得**从 utils/api.ts 导入（api.ts 顶层引 axios/element-plus，
//     会把整条 UI 依赖链带进威胁大屏/安全事件等纯数据 chunk）；
//   - 所有字节展示（日志占用、备份大小、内存/磁盘、WAF 文件、摄取丢失量）
//     一律经此函数，不得再出现第二份精度。
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.min(Math.max(Math.floor(Math.log(bytes) / Math.log(k)), 0), sizes.length - 1)
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}
