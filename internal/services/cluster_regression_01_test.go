package services

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestPromote_DrainFailureReopensPullAdmission(t *testing.T) {
	_, database := newClusterTestService(t)
	StopTaskEngine()
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url='', cluster_token='' WHERE id=1`); err != nil {
		t.Fatalf("set slave role: %v", err)
	}
	// 模拟永不退出的在途 Pull，使 DrainPulls 超时。
	syncService.pullWG.Add(1)
	cluster := NewClusterService(database, "")

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := cluster.Promote(ctx); err == nil {
		t.Fatal("Promote 应在排干超时时失败")
	}
	if err := syncService.beginPull(); err != nil {
		t.Fatalf("排干失败后准入必须重开，beginPull err=%v", err)
	}
	// 清掉模拟在途计数与本次 beginPull 的计数。
	syncService.pullWG.Done()
	syncService.pullWG.Done()
}

func TestNodeBookkeepingWrites_RejectAfterDemotion(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if _, err := database.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,protocol,status,is_approved,registration_secret)
		VALUES (1,'node-1','slave','10.0.0.5',8000,'http','pending',0,'secret')`); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	// 先生成一个注册令牌（主节点态），稍后验证降级后不会被消费。
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate register token: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("demote: %v", err)
	}

	if err := service.ApproveNode(context.Background(), 1, time.Now()); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("ApproveNode err=%v, want ErrNotMasterNode", err)
	}
	reportErr := service.ReportNode(context.Background(), 1, models.ClusterReport{AppliedVersion: 1}, now)
	if !errors.Is(reportErr, ErrNotMasterNode) {
		t.Fatalf("ReportNode err=%v, want ErrNotMasterNode", reportErr)
	}
	if err := service.UpdateNodeAccessURL(context.Background(), 1, "https://10.0.0.5:9000"); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("UpdateNodeAccessURL err=%v, want ErrNotMasterNode", err)
	}
	if err := service.DeleteNode(context.Background(), 1); !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("DeleteNode err=%v, want ErrNotMasterNode", err)
	}
	var nodeCount int
	if err := database.QueryRow("SELECT COUNT(*) FROM nodes WHERE id=1").Scan(&nodeCount); err != nil || nodeCount != 1 {
		t.Fatalf("降级后的写必须不生效：nodes=%d err=%v", nodeCount, err)
	}

	_, regErr := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: token, Name: "node-2", IPAddress: "10.0.0.9", Port: 8000,
	}, now)
	if !errors.Is(regErr, ErrNotMasterNode) {
		t.Fatalf("RegisterNode err=%v, want ErrNotMasterNode", regErr)
	}
	var consumed int
	if err := database.QueryRow("SELECT COUNT(*) FROM cluster_register_tokens WHERE used_at IS NOT NULL").Scan(&consumed); err != nil || consumed != 0 {
		t.Fatalf("降级后注册令牌不得被消费：used=%d err=%v", consumed, err)
	}

	// 恢复主节点态后同一操作正常（守卫只拦竞态窗口）。
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if err := service.ApproveNode(context.Background(), 1, time.Now()); err != nil {
		t.Fatalf("主节点态审批应成功: %v", err)
	}
}

func TestResolveNodeAccessURL(t *testing.T) {
	cases := []struct {
		ip, protocol, accessURL, want string
		port                          int
	}{
		{ip: "10.0.0.1", port: 8000, protocol: "", want: "http://10.0.0.1:8000"},
		{ip: "10.0.0.1", port: 8443, protocol: "https", want: "https://10.0.0.1:8443"},
		{ip: "10.0.0.1", port: 8443, protocol: "HTTPS", want: "http://10.0.0.1:8443"}, // 仅精确 https 生效
		{ip: "10.0.0.1", port: 8000, protocol: "http", accessURL: "https://lb.example:9443", want: "https://lb.example:9443"},
		{ip: "fd00::1", port: 8000, protocol: "http", want: "http://[fd00::1]:8000"},
	}
	for _, tt := range cases {
		if got := resolveNodeAccessURL(tt.ip, tt.port, tt.protocol, tt.accessURL); got != tt.want {
			t.Errorf("resolveNodeAccessURL(%q,%d,%q,%q)=%q, want %q", tt.ip, tt.port, tt.protocol, tt.accessURL, got, tt.want)
		}
	}
}

func TestSnapshot_SingleConnPoolDoesNotDeadlock(t *testing.T) {
	cluster, database := newClusterTestService(t)
	database.SetMaxOpenConns(1)

	done := make(chan error, 1)
	go func() {
		_, _, err := cluster.Snapshot(context.Background(), 0, "", "")
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("单连接池下快照自锁：开关读取必须走快照事务")
	}
}

func TestReport_NilCaddyServiceDegrades(t *testing.T) {
	_, database := newClusterTestService(t)
	reports := make(chan models.ClusterReport, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var report models.ClusterReport
		_ = json.Unmarshal(body, &report)
		reports <- report
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0}`))
	}))
	t.Cleanup(server.Close)
	if _, err := database.Exec(`UPDATE global_config SET master_url=?, cluster_token='token' WHERE id=1`, server.URL); err != nil {
		t.Fatalf("seed master url: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, nil)
	if err := syncService.Report(context.Background()); err != nil {
		t.Fatalf("Report with nil caddy: %v", err)
	}
	select {
	case report := <-reports:
		if report.ServiceStatus != "degraded" {
			t.Fatalf("service_status=%q, want degraded", report.ServiceStatus)
		}
		if report.Health.CaddyOK {
			t.Fatal("nil CaddyService 必须上报 CaddyOK=false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("未收到上报载荷")
	}
}
