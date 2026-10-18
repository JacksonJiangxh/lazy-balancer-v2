package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

// 威胁大屏逐请求正常流量事件代理必须返回应用统一信封（APIResponse）
// 且把 Caddy 发射的英文国名翻成中文——前端按 res.data 消费，裸 JSON
// 会让 flowTask 每轮判 enabled=false 并重置游标为 0，正常蓝色光流永不绘制。
func TestGetThreatScreenFlowEvents_envelopesAndTranslatesCountries(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lb/traffic-events" {
			t.Errorf("admin path=%s, want /lb/traffic-events", r.URL.Path)
		}
		if r.URL.RawQuery != "since=7&limit=1000" {
			t.Errorf("admin query=%q, want since=7&limit=1000", r.URL.RawQuery)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true,"events":[{"seq":7,"country":"United States","at":1792351849814},{"seq":8,"country":"中国","province":"广东省","at":1792351849815}],"next_seq":8,"sample_n":1}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

	req := httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events?since=7&limit=1000", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, want := range []string{`"code":0`, `"data":{`, `"enabled":true`, `"country":"美国"`, `"country":"中国"`, `"province":"广东省"`, `"next_seq":8`, `"sample_n":1`} {
		if !strings.Contains(body, want) {
			t.Fatalf("body=%s, want %s", body, want)
		}
	}
	if strings.Contains(body, `"country":"United States"`) {
		t.Fatalf("body=%s, want country translated to Chinese", body)
	}
}

// Caddy 返回畸形 JSON 时必须显式 502，而不是把残缺内容包成成功信封。
func TestGetThreatScreenFlowEvents_rejectsMalformedAdminBody(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"enabled":true,"events":`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/security/overview/threat-screen/events", h.GetThreatScreenFlowEvents)

	req := httptest.NewRequest(http.MethodGet, "/security/overview/threat-screen/events", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("status=%d body=%s, want 502", rec.Code, rec.Body.String())
	}
}
