package handlers

// 通配符转义、深翻页超阈值 400（阈值 auditLogDeepPageLimit=500）、options
// 三条 GROUP BY 进程内缓存 60s。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestAuditLogs_likeEscaping(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	for _, u := range []string{"lit_100%", "wild_100abc"} {
		if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES (?, '登录', '用户认证', '', '1.1.1.1')`, u); err != nil {
			t.Fatalf("seed %s: %v", u, err)
		}
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs?username=100%25", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("search: %d %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			List []struct {
				Username string `json:"username"`
			} `json:"list"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Data.List) != 1 || resp.Data.List[0].Username != "lit_100%" {
		t.Fatalf("literal %% search must match only literal row, got %d rows: %+v", len(resp.Data.List), resp.Data.List)
	}
}

// 深翻页超过 auditLogDeepPageLimit 时显式 400 并给出筛选指引（不静默 clamp）。
func TestAuditLogs_deepPageRejected(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs?page=10001", nil))
	// 深翻页语义：不再静默 clamp（用户会以为翻到了第 10001 页），改为 400
	// 并指引用筛选缩小范围。
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("deep page: %d %s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "筛选") {
		t.Fatalf("deep page message must guide filtering: %s", rec.Body.String())
	}
}

func TestAuditLogOptions_cached(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	t.Cleanup(resetAuditOptionsCacheForTest)
	resetAuditOptionsCacheForTest()

	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('cache-user', '登录', '用户认证', '', '1.1.1.1')`); err != nil {
		t.Fatal(err)
	}
	get := func() []string {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs/options", nil))
		var resp struct {
			Data struct {
				Usernames []struct {
					Value string `json:"value"`
				} `json:"usernames"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, u := range resp.Data.Usernames {
			out = append(out, u.Value)
		}
		return out
	}
	first := get()
	if len(first) == 0 {
		t.Fatal("first options call must return seeded username")
	}
	// 清空审计表——60s 缓存窗口内第二次调用仍应命中缓存(不重查 DB)。
	if _, err := db.AuditDB.Exec("DELETE FROM audit_log"); err != nil {
		t.Fatal(err)
	}
	second := get()
	if len(second) == 0 {
		t.Fatalf("options within cache window must serve cached result, got empty (DB was cleared)")
	}
}
