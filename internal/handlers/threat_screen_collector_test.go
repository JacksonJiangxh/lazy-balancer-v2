package handlers

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

func TestControlThreatScreenCollector_proxiesLease(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"enabled":true}`))
	}))
	defer admin.Close()

	h := &Handlers{cfg: &config.Config{CaddyAdminURL: admin.URL}}
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.POST("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)
	r.DELETE("/security/overview/threat-screen/collector", h.ControlThreatScreenCollector)

	body := `{"lease_id":"tab-1","ttl_ms":30000,"sample_n":1}`
	req := httptest.NewRequest(http.MethodPost, "/security/overview/threat-screen/collector", strings.NewReader(body))
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":true`) {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if gotMethod != http.MethodPost || gotPath != "/lb/traffic-collector" || gotBody != body {
		t.Fatalf("admin got method=%s path=%s body=%s", gotMethod, gotPath, gotBody)
	}

	req = httptest.NewRequest(http.MethodDelete, "/security/overview/threat-screen/collector", strings.NewReader(body))
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if gotMethod != http.MethodDelete {
		t.Fatalf("DELETE method=%s", gotMethod)
	}
}
