package handlers

//
// caddyOpMu——与 UpdateRule 改域迁移（rules.go 2380-2428）/DeleteRule 排空
// 交错时，迁移已把任务行改到新域后本次仍按旧域 INSERT 新行并入队，对旧域
// 实际发起 CA 签发（部署期域不匹配拒绝，job 滞留 downloaded 至 6h sweep）。
// 手工签发入口必须与规则写/删除/改域共用 caddyOpMu 临界区。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Given caddyOpMu 被预持（模拟并发的规则改域/删除临界区）。
// When 定向手工签发请求到达。
// Then 必须阻塞至锁释放（规则读取与 upsert/入队全程持锁），释放后完成并 200。
func TestIssueCertificate_directedHoldsCaddyOpMu(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_a86_lock", "a86-lock.example.test")
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	h.caddyOpMu.Lock()
	done := make(chan int, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_a86_lock"}`)))
		done <- response.Code
	}()
	select {
	case code := <-done:
		h.caddyOpMu.Unlock()
		t.Fatalf("定向手工签发在 caddyOpMu 被预持期间完成（status=%d）——规则读取/upsert 未与规则写临界区互斥", code)
	case <-time.After(300 * time.Millisecond):
	}
	h.caddyOpMu.Unlock()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("释放锁后定向签发 status=%d, want 200", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("释放锁后定向签发未完成（疑似死锁）")
	}
}

// Given caddyOpMu 被预持（模拟并发的规则改域/删除临界区）。
// When 批量手工签发请求（{"all": true}）到达。
// Then 必须阻塞至锁释放——IssueCertificate 的定向/批量两分支同处一个
// caddyOpMu 临界区（handlers/certjobs.go 锁不变量注释：手工签发不再是无锁
// 调用方）。
func TestIssueCertificate_batchHoldsCaddyOpMu(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_a86_batch_lock", "a86-batch-lock.example.test")
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	h.caddyOpMu.Lock()
	done := make(chan int, 1)
	go func() {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"all":true}`)))
		done <- response.Code
	}()
	select {
	case code := <-done:
		h.caddyOpMu.Unlock()
		t.Fatalf("批量手工签发在 caddyOpMu 被预持期间完成（status=%d）——批量分支未与规则写临界区互斥", code)
	case <-time.After(300 * time.Millisecond):
	}
	h.caddyOpMu.Unlock()
	select {
	case code := <-done:
		if code != http.StatusOK {
			t.Fatalf("释放锁后批量签发 status=%d, want 200", code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("释放锁后批量签发未完成（疑似死锁）")
	}
}
