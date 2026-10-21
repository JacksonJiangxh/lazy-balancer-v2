package services

import "lazy-balancer-v2/internal/services/dnsproviders"

// 历史问题：dnsproviders 包位于 services 之下且不可反向导入 services（包边界），
// 其告警默认落标准库 log；本文件在 services 初始化时注入分级 Logf，使该告警
// 与全局日志级别过滤/JSON 输出形态一致（此前 dnspod 清理失败告警在 warn 以上
// 过滤或 JSON 输出场景会丢失/形态分叉）。services 是日志分级的所有者，注入点
// 放在这里避免 handlers/main 各自重复接线。
func init() {
	dnsproviders.SetWarnLogger(func(format string, args ...any) {
		Logf("warn", format, args...)
	})
}
