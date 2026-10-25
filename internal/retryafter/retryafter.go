// Package retryafter 提供 Retry-After 头的唯一解析实现。
//
// 两个消费方（services 的 CA 限流冷却、dnsprovider/internal/retry 的 DNS API
// 重试）曾各写一份同语义实现，靠注释互相约束「任一侧变更 MUST 同步」——这类
// 约束没有机器拦截，一侧支持新形态（毫秒、负值处理）后另一侧会静默分叉，最终
// 表现为同一份 429 响应在证书域与 DNS 域得到不同退避时长。收敛为单源后两侧
// 只保留委托。
//
// 语义口径（改动此处即同时改变两个域）：接受 delay-seconds 与 HTTP-date；
// 空串、不可解析、非正值（零/负数秒、已过去的日期）一律归零。
package retryafter

import (
	"net/http"
	"strconv"
	"time"
)

// Parse 把 Retry-After 头值解析为等待时长；now 是 HTTP-date 分支的基准时刻
// （生产传 time.Now()，测试可注入固定时刻）。
func Parse(header string, now time.Time) time.Duration {
	if header == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(header); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	if date, err := http.ParseTime(header); err == nil {
		if until := date.Sub(now); until > 0 {
			return until
		}
	}
	return 0
}
