package handlers

// U6-F-L1（第 66 轮审计 U6 报告 P2）基线钉：审计判定「UpdateConfig 是配置/
// 规则/安全写族中唯一不持 caddyOpMu 的 Caddy 写者（caddy.go:405-635 无锁）」
// ——亲验不成立：UpdateConfig 在请求体校验后、全部业务逻辑前即取锁
// （caddy.go:323-325，R11 统一锁序时引入，defer 覆盖函数全程，:405-635 位于
// 锁内）。本钉测试以 caddy_test.go 生命周期探针同款模式锁行为：预持
// caddyOpMu 期间 UpdateConfig 必须阻塞，释放后完成——证明取锁在位。
// 基线钉测试（钉既有正确行为），按 R-1 豁免 RED，判定变更披露见修复报告。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Given caddyOpMu 被预持（模拟并发的规则/安全写临界区）。
// When UpdateConfig 处理请求。
// Then 必须阻塞至锁释放（取锁点=请求校验后函数顶部），释放后完成并 200。
func TestUpdateConfig_holds_rule_operation_lock(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := gin.New()
	router.POST("/config", h.UpdateConfig)

	h.caddyOpMu.Lock()
	done := make(chan int, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/config", strings.NewReader(`{"timezone":"Asia/Shanghai"}`)))
		done <- response.Code
	}()
	select {
	case code := <-done:
		h.caddyOpMu.Unlock()
		t.Fatalf("UpdateConfig 在 caddyOpMu 被预持期间完成（status=%d）——写路径未持锁", code)
	case <-time.After(300 * time.Millisecond):
	}
	h.caddyOpMu.Unlock()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("锁释放后 UpdateConfig status=%d, want 200", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("锁释放后 UpdateConfig 10s 内未完成")
	}
}
