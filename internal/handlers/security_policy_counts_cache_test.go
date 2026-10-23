package handlers

// 策略列表「24h 拦截/触发」列出聚合缓存：同一窗口锚点内复用近 24h 聚合
// （不重复扫描 metrics 库），过期后重查；失败不缓存。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func listPolicies24hCounts(t *testing.T, h *Handlers) (blocked, trigger map[int]int, raw string) {
	t.Helper()
	router := gin.New()
	router.GET("/policies", h.ListSecurityPolicies)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/policies", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data []struct {
			ID         int `json:"id"`
			Blocked24h int `json:"blocked_24h"`
			Trigger24h int `json:"trigger_24h"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	blocked, trigger = map[int]int{}, map[int]int{}
	for _, p := range resp.Data {
		blocked[p.ID] = p.Blocked24h
		trigger[p.ID] = p.Trigger24h
	}
	return blocked, trigger, rec.Body.String()
}

func TestListSecurityPolicies_24hCountsCachedWithinWindow(t *testing.T) {
	h := newBackupTestHandlers(t)
	resetSecurityPolicy24hCountsCacheForTest()
	oldTTL := securityPolicy24hCountsCacheTTL
	securityPolicy24hCountsCacheTTL = time.Minute
	t.Cleanup(func() { securityPolicy24hCountsCacheTTL = oldTTL; resetSecurityPolicy24hCountsCacheForTest() })

	if _, err := db.DB.Exec(`INSERT INTO security_policies (id, name, mode) VALUES (7, '缓存策略', 'blocking')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (policy_id, action) VALUES (7,'blocked'),(7,'logged')`); err != nil {
		t.Fatal(err)
	}

	// 缓存键含分钟锚点：显式传同一个 now 直调 loader，跨分钟边界不再随机
	// 假红（端点只作接线断言）。
	now := time.Now()
	readCounts := func() (int, int) {
		t.Helper()
		counts, err := loadSecurityPolicy24hCounts(db.MetricsDB, now)
		if err != nil {
			t.Fatalf("load 24h counts: %v", err)
		}
		return counts.blocked[7], counts.trigger[7]
	}

	// Given 首次调用（缓存未命中）→ 真实计数。
	if blocked, trigger := readCounts(); blocked != 1 || trigger != 2 {
		t.Fatalf("首次 blocked=%d trigger=%d, want 1/2", blocked, trigger)
	}

	// When 事件表新增 5 条拦截行后立刻再取。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (policy_id, action)
		VALUES (7,'blocked'),(7,'blocked'),(7,'blocked'),(7,'blocked'),(7,'blocked')`); err != nil {
		t.Fatal(err)
	}
	// Then TTL 内命中缓存，不得重查（仍返回旧计数）。
	if blocked, trigger := readCounts(); blocked != 1 || trigger != 2 {
		t.Fatalf("TTL 内 blocked=%d trigger=%d, want 1/2（缓存命中时不得重查）", blocked, trigger)
	}

	// When 缓存禁用（等价 TTL 过期）后请求。
	securityPolicy24hCountsCacheTTL = 0
	// Then 必须重查并拿到新计数。
	if blocked, trigger := readCounts(); blocked != 6 || trigger != 7 {
		t.Fatalf("失效后 blocked=%d trigger=%d, want 6/7（过期必须重查）", blocked, trigger)
	}

	// 端点接线：列表返回的列与 loader 同源。
	blocked, trigger, _ := listPolicies24hCounts(t, h)
	if blocked[7] != 6 || trigger[7] != 7 {
		t.Fatalf("列表端点 blocked=%d trigger=%d, want 6/7（与 loader 同源）", blocked[7], trigger[7])
	}
}

// 退避形状（失败不缓存）：缓存仍应保持空表——错误不落缓存，下一请求重试。
func TestLoadSecurityPolicy24hCounts_failureNotCached(t *testing.T) {
	newBackupTestHandlers(t)
	resetSecurityPolicy24hCountsCacheForTest()
	t.Cleanup(resetSecurityPolicy24hCountsCacheForTest)
	oldTTL := securityPolicy24hCountsCacheTTL
	securityPolicy24hCountsCacheTTL = time.Minute
	t.Cleanup(func() { securityPolicy24hCountsCacheTTL = oldTTL })

	// Given 指标库被关闭（查询必失败）。
	closed := db.MetricsDB
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecurityPolicy24hCounts(closed, time.Now()); err == nil {
		t.Fatal("关闭的指标库必须显式报错（不得静默空计数）")
	}
	securityPolicy24hCountsMu.Lock()
	cached := len(securityPolicy24hCountsCache)
	securityPolicy24hCountsMu.Unlock()
	if cached != 0 {
		t.Fatalf("失败结果被缓存（%d 条），下一请求不会重试", cached)
	}
}
