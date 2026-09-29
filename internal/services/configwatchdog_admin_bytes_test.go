package services

// U8-P4-2（Round 62 审计）：看门狗读取 Caddy 运行配置的解码上限须与 caddy.go
// 家族口径对齐（32MB，LB44-4 同源：caddy.go:210/565/780）。原 4MB 上限下
// >4MB 配置解码失败→漂移检测永久静默而 apply 仍工作至 32MB——大部署静默
// 单点失效。本测试钉：>4MB（<32MB）的运行配置仍可提取规则路由 @id。

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunningRuleRouteIDs_configAbove4MBStillDecoded(t *testing.T) {
	// 5MB 填充键：>4MB 旧上限、<32MB 家族口径。
	body := fmt.Sprintf(`{"_pad":%q,"apps":{"http":{"servers":{"s":{"routes":[{"@id":"lb_probe"},{"@id":"other"}]}}}}}`,
		strings.Repeat("p", 5<<20))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write fake admin config: %v", err)
		}
	}))
	defer srv.Close()

	ids, err := runningRuleRouteIDs(srv.URL)
	if err != nil {
		t.Fatalf("runningRuleRouteIDs on >4MB config: %v", err)
	}
	if len(ids) != 1 || !ids["lb_probe"] {
		t.Fatalf("ids=%v, want exactly {lb_probe}", ids)
	}
}
