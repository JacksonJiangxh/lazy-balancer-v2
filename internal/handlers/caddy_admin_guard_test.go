package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// admin 是面板自管资源：逃生口提交 admin off / disabled 或把监听地址改到面板
// 不可达的 host:port，会让 apply 成功后面板失去全部配置写与启停能力（自锁）。
func TestCaddyAdminSectionGuard_rejectsLockoutShapes(t *testing.T) {
	const panelURL = "http://127.0.0.1:2019"
	cases := []struct {
		name    string
		config  map[string]interface{}
		wantErr bool
	}{
		{name: "admin 省略", config: map[string]interface{}{}, wantErr: false},
		{name: "admin 显式 null", config: map[string]interface{}{"admin": nil}, wantErr: false},
		{name: "对象回环不同写法", config: map[string]interface{}{"admin": map[string]interface{}{"listen": "localhost:2019"}}, wantErr: false},
		{name: "字符串监听地址", config: map[string]interface{}{"admin": "127.0.0.1:2019"}, wantErr: false},
		{name: "通配监听覆盖回环", config: map[string]interface{}{"admin": map[string]interface{}{"listen": "0.0.0.0:2019"}}, wantErr: false},
		{name: "省略主机仅端口", config: map[string]interface{}{"admin": map[string]interface{}{"listen": ":2019"}}, wantErr: false},
		{name: "对象 disabled", config: map[string]interface{}{"admin": map[string]interface{}{"disabled": true}}, wantErr: true},
		{name: "字符串 off", config: map[string]interface{}{"admin": "off"}, wantErr: true},
		{name: "改到其他端口", config: map[string]interface{}{"admin": map[string]interface{}{"listen": "127.0.0.1:2020"}}, wantErr: true},
		{name: "改到不可达地址", config: map[string]interface{}{"admin": map[string]interface{}{"listen": "10.1.2.3:2019"}}, wantErr: true},
		{name: "缺端口", config: map[string]interface{}{"admin": map[string]interface{}{"listen": "127.0.0.1"}}, wantErr: true},
		{name: "类型非法", config: map[string]interface{}{"admin": 2019.0}, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateCaddyAdminSection(tc.config, panelURL)
			if tc.wantErr && err == nil {
				t.Fatalf("config=%v 必须被护栏拒绝（面板自锁）", tc.config)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("config=%v 被误拒: %v", tc.config, err)
			}
		})
	}
}

// admin 段的字符串形态同样受护栏约束（"off" 与改址都必须拦下）。
func TestCaddyAdminSectionGuard_acceptsPanelAdminURLVariants(t *testing.T) {
	listen := map[string]interface{}{"admin": map[string]interface{}{"listen": "0.0.0.0:2019"}}
	if err := validateCaddyAdminSection(listen, "http://localhost:2019"); err != nil {
		t.Fatalf("通配监听对 localhost 面板必须放行: %v", err)
	}
	if err := validateCaddyAdminSection(listen, "not-a-url"); err != nil {
		t.Fatalf("畸形 caddy_admin_url 不得把逃生口锁死: %v", err)
	}
}

// 护栏必须在写库/apply 之前拦截：caddy_config 列与运行配置都保持不变。
func TestPutCaddyConfig_rejectsAdminLockoutBeforeApply(t *testing.T) {
	handler := newBackupTestHandlers(t)
	if _, err := db.DB.Exec("UPDATE global_config SET caddy_config='old-config' WHERE id=1"); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	loads := 0
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			loads++
		}
		_, _ = w.Write([]byte(`{"old":true}`))
	}))
	t.Cleanup(fakeCaddy.Close)
	handler.caddyService = services.NewCaddyService(fakeCaddy.URL)
	handler.cfg = &config.Config{CaddyAdminURL: fakeCaddy.URL}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/caddy", handler.PutCaddyConfig)

	request := httptest.NewRequest(http.MethodPut, "/caddy", strings.NewReader(`{"content":"{\"admin\":{\"disabled\":true},\"apps\":{}}"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（admin 自锁必须被拒）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "admin") {
		t.Fatalf("拒绝文案必须点名 admin 段: %s", response.Body.String())
	}
	var stored string
	if err := db.DB.QueryRow("SELECT caddy_config FROM global_config WHERE id=1").Scan(&stored); err != nil {
		t.Fatalf("read stored config: %v", err)
	}
	if stored != "old-config" {
		t.Fatalf("stored=%q, want unchanged old-config（护栏必须早于写库）", stored)
	}
	if loads != 0 {
		t.Fatalf("loads=%d, want 0（护栏必须早于 apply）", loads)
	}
}
