package middleware

import (
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/services"
)

// 请求日志格式串曾传入两次 param.Method——每行输出
// 形如「| GET | GET "/path"」，method 重复且占用了其他字段的列。钉死：
// method 与 path 各出现一次，列结构为 [time] status | latency | ip | METHOD "path"。
func TestRequestLogFormatterPrintsMethodAndPathOnce(t *testing.T) {
	line := requestLogFormatter(gin.LogFormatterParams{
		TimeStamp:  time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC),
		Method:     "POST",
		StatusCode: 200,
		Latency:    1500 * time.Microsecond,
		ClientIP:   "192.0.2.1",
		Path:       "/api/v1/rules",
	})
	if n := strings.Count(line, "POST"); n != 1 {
		t.Fatalf("method 出现 %d 次，want 1（不得重复输出）: %q", n, line)
	}
	if n := strings.Count(line, `"/api/v1/rules"`); n != 1 {
		t.Fatalf("path 出现 %d 次，want 1: %q", n, line)
	}
	for _, column := range []string{" 200 ", "1.5ms", "192.0.2.1"} {
		if !strings.Contains(line, column) {
			t.Fatalf("缺少列 %q: %q", column, line)
		}
	}
}

func TestShouldLogRequestAppliesConfiguredThreshold(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		status  int
		latency time.Duration
		want    bool
	}{
		{name: "info records successful request", level: "info", status: 200, want: true},
		{name: "warn filters routine success", level: "warn", status: 200, want: false},
		{name: "warn records client error", level: "warn", status: 404, want: true},
		{name: "warn records slow success", level: "warn", status: 200, latency: time.Second, want: true},
		{name: "error filters client error", level: "error", status: 404, want: false},
		{name: "error records server error", level: "error", status: 500, want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			if err := services.ConfigureLogLevel(test.level); err != nil {
				t.Fatal(err)
			}

			// When
			got := shouldLogRequest(test.status, test.latency)

			// Then
			if got != test.want {
				t.Fatalf("shouldLogRequest(%d,%v)=%v, want %v", test.status, test.latency, got, test.want)
			}
		})
	}
	t.Cleanup(func() { _ = services.ConfigureLogLevel("info") })
}
