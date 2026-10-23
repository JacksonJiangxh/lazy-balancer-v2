package services

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func TestClusterService_Nodes_degrades_bad_health_json_per_node(t *testing.T) {
	// Given：一个节点 health_json 损坏，另一个节点正常
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO nodes (name,ip_address,is_approved,status,health_json) VALUES ('bad-health','10.0.0.2',1,'online','not-json{')`); err != nil {
		t.Fatalf("seed broken node: %v", err)
	}
	validHealth, err := json.Marshal(models.ClusterHealth{CaddyOK: true, RulesCount: 3})
	if err != nil {
		t.Fatalf("encode valid health: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (name,ip_address,is_approved,status,health_json) VALUES ('good-health','10.0.0.3',1,'online',?)`, string(validHealth)); err != nil {
		t.Fatalf("seed healthy node: %v", err)
	}

	// When
	nodes, err := service.Nodes(context.Background(), time.Now())

	// Then：列表不因单节点损坏而整体失败，损坏节点 Health=nil
	if err != nil {
		t.Fatalf("nodes list failed on single bad health_json: %v", err)
	}
	byName := map[string]*models.ClusterNodeView{}
	for i := range nodes {
		byName[nodes[i].Name] = &nodes[i]
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes count=%d, want 2", len(nodes))
	}
	if bad := byName["bad-health"]; bad == nil || bad.Health != nil {
		t.Fatalf("bad-health node present=%v, want present with nil Health", byName["bad-health"] != nil)
	}
	if good := byName["good-health"]; good == nil || good.Health == nil || good.Health.RulesCount != 3 {
		t.Fatalf("good-health node health=%v, want decoded health", nodeHealth(byName["good-health"]))
	}
}

func nodeHealth(node *models.ClusterNodeView) *models.ClusterHealth {
	if node == nil {
		return nil
	}
	return node.Health
}

// （TestAutoProvisionZeroSSLEAB_email_is_url_encoded /
// TestAutoProvisionZeroSSLEAB_cas_loses_memory_follows_db 及
// overrideZeroSSLEABURL helper）原寄居本文件，已迁证书域 caproviders_test.go
// （AutoProvisionZeroSSLEAB 实现于 caproviders.go）。

// 同一「失败→重复→恢复→再失败」场景的两种失败类别（传输类连接失败 /
// HTTP 403）合并为表驱动——此前与 cluster_regression_02_test.go 的同名用例
// 逐段重复 ~40 行且断言同为 COUNT=1/1/2。
func TestSyncService_Report_failure_audit_throttles_and_resets_on_recovery(t *testing.T) {
	for _, tc := range []struct {
		name        string
		httpFailure bool // true=主节点返回 403；false=连接失败（传输类）
	}{
		{"transport_error", false},
		{"http_403", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Given
			_, database := newClusterTestService(t)
			deadURL := deadServerURL(t)
			var mode atomic.Int32 // 0=403, 1=200
			master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				if tc.httpFailure && mode.Load() == 0 {
					response.WriteHeader(http.StatusForbidden)
					return
				}
				_, _ = response.Write([]byte(`{"code":0,"message":"ok"}`))
			}))
			defer master.Close()
			caddy := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) { response.WriteHeader(http.StatusOK) }))
			defer caddy.Close()
			initialURL := master.URL
			if !tc.httpFailure {
				initialURL = deadURL
			}
			if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='tok-1' WHERE id=1", initialURL); err != nil {
				t.Fatalf("seed slave state: %v", err)
			}
			service := NewSyncService(database, &config.Config{DataDir: t.TempDir()}, NewCaddyService(caddy.URL))
			countAudit := func() int {
				var count int
				if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='上报失败'").Scan(&count); err != nil {
					t.Fatalf("count audit rows: %v", err)
				}
				return count
			}
			fail := func() {
				t.Helper()
				if tc.httpFailure {
					mode.Store(0)
				} else if _, err := database.Exec("UPDATE global_config SET master_url=? WHERE id=1", deadURL); err != nil {
					t.Fatalf("point to dead master: %v", err)
				}
				if err := service.Report(context.Background()); err == nil {
					t.Fatal("report to failing master unexpectedly succeeded")
				}
			}
			recoverReport := func() {
				t.Helper()
				if tc.httpFailure {
					mode.Store(1)
				} else if _, err := database.Exec("UPDATE global_config SET master_url=? WHERE id=1", master.URL); err != nil {
					t.Fatalf("point to live master: %v", err)
				}
				if err := service.Report(context.Background()); err != nil {
					t.Fatalf("report to live master: %v", err)
				}
			}

			// When/Then：首次失败记录审计，重复同样失败被节流
			fail()
			if got := countAudit(); got != 1 {
				t.Fatalf("audit rows after first failure=%d, want 1", got)
			}
			fail()
			if got := countAudit(); got != 1 {
				t.Fatalf("audit rows after repeated failure=%d, want 1 (throttled)", got)
			}

			// When/Then：恢复后节流状态重置，再次失败重新记录一次
			recoverReport()
			if got := countAudit(); got != 1 {
				t.Fatalf("audit rows after recovery=%d, want 1", got)
			}
			fail()
			if got := countAudit(); got != 2 {
				t.Fatalf("audit rows after post-recovery failure=%d, want 2", got)
			}
		})
	}
}
