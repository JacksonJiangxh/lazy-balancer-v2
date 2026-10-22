package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// 后台强制重载成功必须清除陈旧的「配置应用失败」横幅：此前只有 handler 写路径
// 经 recordCaddyApplyResult 清，后台数据类重载（证书/CRS/IP 库/威胁库/自动封禁）
// 成功后面板横幅仍挂在一次早已被后续配置覆盖的失败上。
func TestForcedReloadClearsStaleApplyBanner(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET caddy_apply_error='上一次写路径失败：旧横幅' WHERE id=1`); err != nil {
		t.Fatalf("seed stale banner: %v", err)
	}

	loads := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads++
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	if err := service.GenerateAndApplyConfigForceInLock(); err != nil {
		t.Fatalf("强制重载失败: %v", err)
	}
	if loads != 1 {
		t.Fatalf("/load 次数=%d, want 1", loads)
	}
	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if banner != "" {
		t.Fatalf("后台强制重载成功后陈旧横幅未清除: %q", banner)
	}
	// 横幅不再显示：状态接口的失败面为空（后台失败面无登记）。
	resetBackgroundApplyFailures(t)
	if got := BackgroundApplyFailureBanner(); got != "" {
		t.Fatalf("后台失败横幅=%q, want 空", got)
	}
}
