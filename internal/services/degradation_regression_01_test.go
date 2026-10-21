package services

//（可用性优先不 fail-visible），但「面板显示启用、实际渲染分叉」的事实必须
// 可见——apply 成功后落审计行 + caddy_apply_error 横幅，LastRenderDegradation
// 抑制 handlers 侧成功清除，直至下次干净渲染恢复常规语义。

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestTrustedProxyDegradation_bannerRecordsOnApply：畸形网段 JSON + 启用态
// → 渲染成功（不 fail-visible）+ 横幅写入 + 降级状态置位；干净渲染成功应用
// 后状态归空（横幅清除恢复常规语义）。
func TestTrustedProxyDegradation_bannerRecordsOnApply(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-d3", false)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='{bad'`); err != nil {
		t.Fatalf("seed degraded trusted proxy: %v", err)
	}

	applied := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			_, _ = w.Write([]byte(`{}`))
			return
		}
		// 拒未知顶层字段返 400。旧桩恒 200 掩盖了内部键 __lazy_balancer_*
		// 漏进载荷导致降级配置被硬拒的缺陷（历史修复 可用性优先被反转）。
		body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"read body failed"}`))
			return
		}
		var payload map[string]json.RawMessage
		if err := json.Unmarshal(body, &payload); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"json decode failed"}`))
			return
		}
		for key := range payload {
			switch key {
			case "admin", "apps", "logging", "storage": // Caddy Config 已知顶层字段
			default:
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"error":"unknown field %q"}`, key)))
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
		applied <- r.URL.Path
	}))
	t.Cleanup(server.Close)
	service := NewCaddyService(server.URL)

	if err := service.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("degraded render must still apply (不 fail-visible): %v", err)
	}
	<-applied
	var banner string
	if err := database.QueryRow(`SELECT COALESCE(caddy_apply_error,'') FROM global_config WHERE id=1`).Scan(&banner); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !strings.Contains(banner, "受信代理网段配置解析失败") || !strings.Contains(banner, "真实 IP 还原失效") {
		t.Fatalf("degraded apply must leave a visible banner, got %q", banner)
	}
	if got := LastRenderDegradation(); !strings.Contains(got, "受信代理") {
		t.Fatalf("LastRenderDegradation must carry the degradation, got %q", got)
	}

	// 干净渲染（停用受信代理）+ 强制应用 → 状态归空。
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=0`); err != nil {
		t.Fatalf("disable trusted proxy: %v", err)
	}
	cfg := GenerateCaddyConfig()
	if err := service.ApplyConfigForce(cfg); err != nil {
		t.Fatalf("clean apply: %v", err)
	}
	if got := LastRenderDegradation(); got != "" {
		t.Fatalf("clean render+apply must clear degradation state, got %q", got)
	}
}

// TestTrustedProxyDegradation_disabledIsNotDegraded：enabled=false 是「未启用」
// 非降级——零横幅零状态（防止把正常关闭误报成分叉）。
func TestTrustedProxyDegradation_disabledIsNotDegraded(t *testing.T) {
	stubSecurityLibsAvailable(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb-d3-clean", false)
	if _, err := database.Exec(`UPDATE global_config SET trusted_proxy_enabled=0, trusted_proxy_ranges='{bad'`); err != nil {
		t.Fatalf("seed disabled trusted proxy: %v", err)
	}
	fields, degraded := trustedProxyServerFields(database)
	if fields != nil || degraded != "" {
		t.Fatalf("disabled state must be (nil, \"\"), got (%v, %q)", fields, degraded)
	}
}
