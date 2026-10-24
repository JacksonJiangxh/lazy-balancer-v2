package services

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
)

// 集群拉取的大体积传输（快照 256MB / 规则包 64MB）不得受 http.Client 总超时
// 约束：30s 总超时（含读 body）在慢链路下会让从端同步永久失败，仓内 CRS
// 下载路径已因同一原因取消 Client.Timeout。截止只由每次尝试的 ctx 承担。

func TestClusterClient_hasNoTotalTimeout(t *testing.T) {
	svc := NewSyncService(nil, &config.Config{}, nil)
	if svc.client == nil {
		t.Fatal("sync client must be initialized")
	}
	if svc.client.Timeout != 0 {
		t.Fatalf("cluster client must not set a total timeout (got %s): 30s 总超时与 256MB/64MB 上限不相容", svc.client.Timeout)
	}
}

func TestNewClusterTransferContext_honorsBudgetInsteadOfClientTimeout(t *testing.T) {
	// 慢 body：先写头并 flush，再延迟写正文。旧形态（Client.Timeout=30s）不会
	// 在这里失败，但同一份 budget 机制一旦失效（例如预算被写死 30s 之外的
	// 地方）本测试即红——预算是唯一截止来源。
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
		_, _ = w.Write([]byte(`{"data":{}}`))
	}))
	defer server.Close()
	defer close(release)

	svc := NewSyncService(nil, &config.Config{}, nil)
	old := clusterLargeTransferTimeout
	clusterLargeTransferTimeout = 2 * time.Second
	t.Cleanup(func() { clusterLargeTransferTimeout = old })

	ctx, cancel := newClusterTransferContext(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	// 释放后能读完 body：预算内的大响应不被 30s 级客户端超时切断。
	done := make(chan error, 1)
	go func() {
		resp, err := svc.client.Do(req)
		if err != nil {
			done <- err
			return
		}
		defer resp.Body.Close()
		_, err = io.ReadAll(resp.Body)
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("slow response finished before body was released: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	release <- struct{}{}
	if err := <-done; err != nil {
		t.Fatalf("slow body read must succeed within the attempt budget: %v", err)
	}
}

func TestNewClusterTransferContext_expiresAtBudget(t *testing.T) {
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		<-release
	}))
	defer server.Close()
	defer close(release)

	svc := NewSyncService(nil, &config.Config{}, nil)
	old := clusterLargeTransferTimeout
	clusterLargeTransferTimeout = 80 * time.Millisecond
	t.Cleanup(func() { clusterLargeTransferTimeout = old })

	ctx, cancel := newClusterTransferContext(context.Background())
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	resp, err := svc.client.Do(req)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		resp.Body.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("attempt budget must cut a hanging body, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("deadline applied too late: %s", elapsed)
	}
}
