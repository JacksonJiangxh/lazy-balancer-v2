package services

// 日志轮转保留份数的跨包契约（历史修复，历史）。
//
// 背景：handlers 的 logRotatedBackups（展示层「保留 N 份」）与写侧保留份数
// 必须同源同值。此前该契约仅靠 handlers 测试读取本包源码文本钉住
// （`const maxRotatedFiles = 5` 与两处 `"roll_keep": 5` 字面量计数）——常量
// 改类型/加注释/第三个 writer 出现时会误红或漏验，且「文本出现两次」不证明
// 写入端真的按 N 轮转。
//
// 现约定：Caddy 日志 writer（全局 logging + 规则级 logger_names）的 roll_keep
// 从 caddyLogRollKeep 取值，读取侧测试断言导出值与 handlers 展示常量相等。
const caddyLogRollKeep = 5

// CaddyLogRollKeep 导出 Caddy 日志 writer 的保留份数（与
// CertJobLogMaxRotatedFiles 同格的数值契约，供 handlers 展示层钉住）。
func CaddyLogRollKeep() int { return caddyLogRollKeep }
