package handlers

// 设置族与原始配置逃生口的失败分支必须把 last-known-good 钉回「已提交库
// 视图」：回弹目标是「请求前运行配置」，它可能已经漂移（外来路由/带外
// `caddy api` 改动）——把漂移形态固化成启动兜底，会在「重启 + DB 渲染被拒」
// 时重新加载外来配置。

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// driftedRuntimeConfig 是「请求前运行配置」：含一条不属于任何库内规则的
// 外来路由。
const driftedRuntimeConfig = `{"apps":{"http":{"servers":{"s_80":{"routes":[{"@id":"foreign_extra","handle":[]}]}}}}}`

func newFailingLoadHandlers(t *testing.T) (*Handlers, string) {
	t.Helper()
	initializeRuleFeatureTestDB(t)
	var mu sync.Mutex
	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/config/":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(driftedRuntimeConfig))
			return
		case r.Method == http.MethodPost && r.URL.Path == "/load":
			_, _ = io.ReadAll(r.Body)
			mu.Lock()
			loads++
			first := loads == 1
			mu.Unlock()
			if first {
				// 候选应用失败；随后的快照回弹成功（「旧配置已保留」形态）。
				http.Error(w, "load rejected", http.StatusInternalServerError)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(server.Close)
	lkgPath := filepath.Join(t.TempDir(), "last_good.json")
	service := services.NewCaddyService(server.URL)
	service.SetLastGoodPath(lkgPath)
	return &Handlers{
		cfg:            &config.Config{CaddyAdminURL: server.URL},
		caddyService:   service,
		clusterService: services.NewClusterService(db.DB, ""),
	}, lkgPath
}

func assertLastGoodIsCommittedView(t *testing.T, lkgPath string) {
	t.Helper()
	data, err := os.ReadFile(lkgPath)
	if err != nil {
		t.Fatalf("last-known-good 必须在失败分支被钉回已提交视图: %v", err)
	}
	if strings.Contains(string(data), "foreign_extra") {
		t.Fatalf("last-known-good 固化了漂移形态（含外来路由）: %s", string(data))
	}
}

func TestUpdateConfig_applyFailurePinsLastKnownGoodToCommittedView(t *testing.T) {
	handler, lkgPath := newFailingLoadHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"log_level":"debug"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（候选 /load 失败）", response.Code, response.Body.String())
	}
	assertLastGoodIsCommittedView(t, lkgPath)
}

func TestPutCaddyConfig_applyFailurePinsLastKnownGoodToCommittedView(t *testing.T) {
	handler, lkgPath := newFailingLoadHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config/raw", handler.PutCaddyConfig)

	body := `{"content":"{\"apps\":{\"http\":{\"servers\":{\"s\":{\"routes\":[]}}}}}"}`
	request := httptest.NewRequest(http.MethodPut, "/config/raw", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（候选应用失败）", response.Code, response.Body.String())
	}
	assertLastGoodIsCommittedView(t, lkgPath)
}
