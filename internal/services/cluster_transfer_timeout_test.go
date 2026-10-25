package services

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// 小请求族（注册、上报、注册状态轮询、注册确认）此前只有注册带 10s ctx：
// 其余三处沿用 daemon ctx，对端「接受连接但永不响应」会让同步循环永久停在
// 首字节之前——不拉取、不上报、不写 last_sync_error、零日志。以下用例以
// 「挂起服务 + 收窄预算」钉住截止生效，避免 10s 级实测等待。

func shortenClusterSmallRequestTimeout(t *testing.T) {
	t.Helper()
	previous := clusterSmallRequestTimeout
	clusterSmallRequestTimeout = 120 * time.Millisecond
	t.Cleanup(func() { clusterSmallRequestTimeout = previous })
}

// hangingMasterServer 接受连接后永不写响应头。handler 在收尾时经 release
// 通道显式放行——只等 request.Context().Done() 时，服务端可能直到 handler
// 返回才感知连接已关闭，httptest.Server.Close 会永久等待。
func hangingMasterServer(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		select {
		case <-release:
		case <-request.Context().Done():
		}
	}))
	t.Cleanup(func() {
		close(release)
		server.Close()
	})
	return server
}

func TestClusterClients_smallRequestTransportCarriesHeaderTimeout(t *testing.T) {
	service := NewSyncService(nil, &config.Config{}, nil)

	smallTransport, ok := service.smallClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("small client transport=%T, want *http.Transport", service.smallClient.Transport)
	}
	if smallTransport.ResponseHeaderTimeout != clusterSmallResponseHeaderTimeout {
		t.Fatalf("small transport ResponseHeaderTimeout=%s, want %s", smallTransport.ResponseHeaderTimeout, clusterSmallResponseHeaderTimeout)
	}
	if service.smallClient.Timeout != 0 {
		t.Fatalf("small client must not set a total timeout (got %s)", service.smallClient.Timeout)
	}

	// 大传输客户端刻意不设首字节时限：快照响应头在主节点同步构建（全树哈希）
	// 之后才写出，时限会把「慢但有效」的大响应误判为挂死。
	largeTransport, ok := service.client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("large client transport=%T, want *http.Transport", service.client.Transport)
	}
	if largeTransport.ResponseHeaderTimeout != 0 {
		t.Fatalf("large-transfer transport must not bound time-to-first-byte (got %s)", largeTransport.ResponseHeaderTimeout)
	}
}

func TestSyncService_Report_returnsAtSmallRequestBudgetAgainstHangingMaster(t *testing.T) {
	_, database := newClusterTestService(t)
	master := hangingMasterServer(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	shortenClusterSmallRequestTimeout(t)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	started := time.Now()
	err := service.Report(context.Background())

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("report error=%v, want context.DeadlineExceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("report deadline applied too late: %s", elapsed)
	}
}

func TestSyncService_pollRegistration_returnsAtSmallRequestBudgetAgainstHangingMaster(t *testing.T) {
	_, database := newClusterTestService(t)
	master := hangingMasterServer(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, registration_id=7, registration_secret='secret' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	shortenClusterSmallRequestTimeout(t)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	done := make(chan struct{})
	go func() {
		service.pollRegistration(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("注册状态轮询未在预算内返回：对端挂起会永久卡死注册流程")
	}

	var syncError string
	if err := database.QueryRow("SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1").Scan(&syncError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(syncError, "查询注册状态失败") {
		t.Fatalf("last_sync_error=%q, want 挂起失败可见（不得零留痕轮询）", syncError)
	}
}

func TestSyncService_redeemRegistrationConfirm_returnsAtSmallRequestBudgetAgainstHangingMaster(t *testing.T) {
	_, database := newClusterTestService(t)
	master := hangingMasterServer(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, cluster_token='cluster-token' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	shortenClusterSmallRequestTimeout(t)
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)

	started := time.Now()
	terminated := service.redeemRegistrationConfirm(context.Background(), master.URL, "cluster-token")

	if terminated {
		t.Fatal("网络挂起属可重试失败，不得推进终止轨道")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("confirm deadline applied too late: %s", elapsed)
	}
}
