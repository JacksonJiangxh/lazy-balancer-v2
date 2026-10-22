package services

// 日志轮转保留份数的跨包契约。
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
//
// 生产调用方为零是设计如此（Ruling：接受）。caddy.go 直接消费包内常量
// caddyLogRollKeep；本导出 getter 的唯一消费方是 handlers 侧数值契约测试
// （logRotatedBackups 展示值 == 写侧 roll_keep）——跨包无法读取未导出常量，
// 删除它等于删除该契约的唯一机器检查。新增生产调用方前请先确认语义：展示层
// 数值必须与写侧同源，禁止在 handlers 另写一份常量。
func CaddyLogRollKeep() int { return caddyLogRollKeep }
