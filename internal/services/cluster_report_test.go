package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"encoding/json"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// 历史问题-1(D1):主节点启用管理 HTTPS 后,跨主机/未跟随的 3xx 会以空 body
// 落到既有分支——Report 此前把 3xx 当成功静默吞掉,RegisterWithMaster 则报
// 「解析注册响应: unexpected end of JSON input」让运维无从下手。两处都须
// 在读 body 前给可行动错误(仿 Pull 的 3xx 分支文案)。
func TestSyncService_Report_returnsActionableErrorOnUnfollowedRedirect(t *testing.T) {
	// Given:主节点上报端点 301 指向另一主机(同主机 https 升级会被
	// doWithTLSUpgradeRedirect 自动重放,跨主机不跟随)。
	_, database := newClusterTestService(t)
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://master-elsewhere.example.com/api/v1/cluster/nodes/report")
		response.WriteHeader(http.StatusMovedPermanently)
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='cluster-token' WHERE id=1", master.URL); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))

	// When
	err := service.Report(context.Background())

	// Then:错误含「重定向」与 https 修正指引(不再是静默成功)。
	if err == nil {
		t.Fatal("report unexpectedly succeeded on 3xx response")
	}
	if !strings.Contains(err.Error(), "重定向") || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("report error=%q, want actionable redirect guidance", err)
	}
}

// 同款判定也须覆盖注册链:读 body 前拦截,防「unexpected end of JSON input」。
func TestSyncService_RegisterWithMaster_returnsActionableErrorOnUnfollowedRedirect(t *testing.T) {
	// Given:主节点注册端点 301 跨主机。
	master := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Location", "https://master-elsewhere.example.com/api/v1/cluster/register")
		response.WriteHeader(http.StatusMovedPermanently)
	}))
	defer master.Close()
	service := NewSyncService(nil, &config.Config{DataDir: t.TempDir()}, nil)

	// When
	_, err := service.RegisterWithMaster(context.Background(), master.URL, models.ClusterRegisterRequest{})

	// Then
	if err == nil {
		t.Fatal("registration unexpectedly succeeded on 3xx response")
	}
	if !strings.Contains(err.Error(), "重定向") || !strings.Contains(err.Error(), "https://") {
		t.Fatalf("registration error=%q, want actionable redirect guidance", err)
	}
	if strings.Contains(err.Error(), "unexpected end of JSON input") {
		t.Fatalf("registration error=%q leaked raw JSON parse failure instead of guidance", err)
	}
}

// 历史问题：临期统计覆盖仍可能代表当前证书材料的 downloaded/failed 行，
// 不只 issued；waiting_ca 不属于部署完成/待部署证书材料口径。
// D2-历史问题（历史）：部署生命周期 cleanup_dns/cleanup_warning（材料已落库、
// 待部署）同样必须计入——此前与规则页/任务页到期口径分叉。
func TestSyncService_Report_countsExpiringCertificatesAcrossDeployableStates(t *testing.T) {
	_, database := newClusterTestService(t)
	reported := make(chan models.ClusterReport, 1)
	master := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var report models.ClusterReport
		if err := json.NewDecoder(r.Body).Decode(&report); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		reported <- report
		w.WriteHeader(http.StatusOK)
	}))
	defer master.Close()
	caddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer caddy.Close()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0,master_url=?,cluster_token='cluster-token' WHERE id=1`, master.URL); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at) VALUES
		('lb_issued','issued.example.test','issued',datetime('now','+2 days')),
		('lb_downloaded','downloaded.example.test','downloaded',datetime('now','+3 days')),
		('lb_failed','failed.example.test','failed',datetime('now','+4 days')),
		('lb_waiting','waiting.example.test','waiting_ca',datetime('now','+5 days')),
		('lb_cleanup_dns','cleanup-dns.example.test','cleanup_dns',datetime('now','+6 days')),
		('lb_cleanup_warning','cleanup-warning.example.test','cleanup_warning',datetime('now','+7 days')),
		('lb_future','future.example.test','issued',datetime('now','+90 days'))`); err != nil {
		t.Fatal(err)
	}
	service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
	if err := service.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-reported:
		if report.Health.CertsExpiring30d != 5 {
			t.Fatalf("expiring count=%d, want issued/downloaded/failed/cleanup_dns/cleanup_warning = 5", report.Health.CertsExpiring30d)
		}
	default:
		t.Fatal("master did not receive cluster report")
	}

	// 带外/旧主端脏值不得把所有 90 天证书都误判为临期；读侧回退默认 30 天。
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=100000 WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if err := service.Report(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case report := <-reported:
		if report.Health.CertsExpiring30d != 5 {
			t.Fatalf("expiring count with excessive threshold=%d, want default-threshold count 5", report.Health.CertsExpiring30d)
		}
	default:
		t.Fatal("master did not receive second cluster report")
	}
}
