package handlers

// 指标读路径的共享快照契约：规则/主机/Caddy/面板四个消费面读同一
// CaddyMetricsURL，抓取结果在短 TTL 内共享、并发 miss 合并为一趟（一次最多
// 16MB 文本不再被 N 个客户端重复拉取）；失败短负缓存，客户端取消不写负缓存
// （否则一次断开会让同窗内其余请求拿到伪造的上游失败）。

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestMetricsEndpoints_shareOneScrapeSnapshotAcrossConsumers(t *testing.T) {
	newMetricsTestDatabase(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_snapshot','snap','http','snap.example.test',80,1)`); err != nil {
		t.Fatal(err)
	}
	resetMetricsDashboardCacheForTest()
	t.Cleanup(resetMetricsDashboardCacheForTest)

	var fetches atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		fetches.Add(1)
		return []byte("caddy_http_requests_total{host=\"snap.example.test\",server=\"http_80\"} 7\n"), nil
	})
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: "http://127.0.0.1:9/metrics"}}
	router := gin.New()
	router.GET("/metrics", h.GetCaddyMetrics)
	router.GET("/metrics/hosts", h.GetHostMetrics)
	router.GET("/rules/:caddy_id/metrics", h.GetRuleMetrics)

	// When：三个端点依次命中（同一 CaddyMetricsURL）。
	for _, path := range []string{"/metrics", "/metrics/hosts", "/rules/lb_snapshot/metrics"} {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s, want 200", path, rec.Code, rec.Body.String())
		}
	}

	// Then：只抓取一次（快照共享），不是每端点各拉一次。
	if got := fetches.Load(); got != 1 {
		t.Fatalf("三端点抓取 %d 次, want 1（共享快照未生效，每端点重复拉取大文本）", got)
	}

	// When：8 个并发请求同时到达（TTL 内）。
	var wg sync.WaitGroup
	wg.Add(8)
	for range 8 {
		go func() {
			defer wg.Done()
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		}()
	}
	wg.Wait()

	// Then：仍是一次抓取。
	if got := fetches.Load(); got != 1 {
		t.Fatalf("并发请求后抓取 %d 次, want 1", got)
	}
}

func TestLoadCaddyMetricsSnapshot_negativeCacheAndCancelNotCached(t *testing.T) {
	resetCaddyMetricsSnapshotCacheForTest()
	t.Cleanup(resetCaddyMetricsSnapshotCacheForTest)
	oldNeg := caddyMetricsSnapshotNegativeTTL
	caddyMetricsSnapshotNegativeTTL = 40 * time.Millisecond
	t.Cleanup(func() { caddyMetricsSnapshotNegativeTTL = oldNeg })

	// Given：抓取失败。
	var calls atomic.Int32
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		return nil, context.DeadlineExceeded
	})
	if _, err := loadCaddyMetricsSnapshot(context.Background(), "http://snap.invalid/metrics", true); err == nil {
		t.Fatal("抓取失败必须返回 error")
	}
	// Then：负缓存窗口内不重复击穿。
	if _, err := loadCaddyMetricsSnapshot(context.Background(), "http://snap.invalid/metrics", true); err == nil {
		t.Fatal("负缓存命中仍须返回失败")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("负缓存窗口内抓取 %d 次, want 1", got)
	}

	// Given：客户端已取消的请求触发的抓取失败。
	resetCaddyMetricsSnapshotCacheForTest()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	overrideDashboardFetch(t, func(ctx context.Context, _ string) ([]byte, error) {
		calls.Add(1)
		return nil, ctx.Err()
	})
	if _, err := loadCaddyMetricsSnapshot(canceled, "http://snap.invalid/metrics", true); err == nil {
		t.Fatal("取消请求必须返回 error")
	}
	// Then：取消不写负缓存——下一次健康请求立刻重新抓取。
	overrideDashboardFetch(t, func(context.Context, string) ([]byte, error) {
		calls.Add(1)
		return []byte("ok 1\n"), nil
	})
	body, err := loadCaddyMetricsSnapshot(context.Background(), "http://snap.invalid/metrics", true)
	if err != nil || string(body) != "ok 1\n" {
		t.Fatalf("取消后健康请求 body=%q err=%v, want 立即重新抓取成功", string(body), err)
	}
}

func TestGetRuleMetrics_unknownRuleUsesFamilyNotFoundShape(t *testing.T) {
	newMetricsTestDatabase(t)
	h := &Handlers{cfg: &config.Config{CaddyMetricsURL: "http://127.0.0.1:9/metrics"}}
	router := gin.New()
	router.GET("/rules/:caddy_id/metrics", h.GetRuleMetrics)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/rules/lb_missing/metrics", nil))

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", rec.Code, rec.Body.String())
	}
	var payload struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 与规则历史/证书任务同族口径（中文且不把「规则已删」当服务故障）。
	if payload.Code != 404 || payload.Message != "规则不存在" {
		t.Fatalf("payload=%+v, want 404/规则不存在（dbQueryNotFound 单源）", payload)
	}
}
