package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestApplyConfigFromTx_degradationDoesNotBlockOnOpenWriteTx(t *testing.T) {
	setLastRenderDegradation("")
	t.Cleanup(func() { setLastRenderDegradation("") })
	_, database := newClusterTestService(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	done := make(chan error, 1)
	go func() {
		done <- service.applyConfigLockedOpt(map[string]interface{}{
			caddyConfigDegradationKey: "受信代理渲染降级",
		}, true, false)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("degraded transactional apply: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("transactional apply must not write caddy_apply_error on a second connection while tx holds the write lock")
	}
	// 事务内 apply 必须收敛降级状态并标记待落审计（commit 后补落），否则
	// 「降级但无横幅」的可观测性缺陷无法被发现；主库横幅此时不得写。
	if got := LastRenderDegradation(); !strings.Contains(got, "受信代理") {
		t.Fatalf("事务内 apply 必须记录降级状态，got %q", got)
	}
	if pending := TakePendingRenderDegradationAudit(); pending == "" {
		t.Fatal("事务内 apply 必须标记待落降级审计")
	}
	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if strings.Contains(banner, "受信代理") {
		t.Fatalf("事务内 apply 不得写降级横幅: %q", banner)
	}
}
