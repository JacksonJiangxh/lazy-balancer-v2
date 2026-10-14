package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// C-03（2026-09-05 证书域审计裁定）：global_config.dns_credentials 为遗留字段
// （签发链唯一凭证来源是 certificate_configs.dns_credentials，前端零消费），
// GET /config 不再返回其值——管理员与非管理员视角均须为空。
func TestGetConfig_omits_legacy_global_dns_credentials(t *testing.T) {
	// Given：遗留字段中存有真实凭证
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET dns_credentials='legacy-id,legacy-token', acme_email='ops@example.com' WHERE id=1`); err != nil {
		t.Fatalf("seed legacy dns credentials: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", h.GetConfig)
	adminRouter := gin.New()
	adminRouter.Use(func(c *gin.Context) { c.Set("role", "admin") })
	adminRouter.GET("/config", h.GetConfig)

	for name, target := range map[string]*gin.Engine{"anonymous": router, "admin": adminRouter} {
		t.Run(name, func(t *testing.T) {
			// When
			response := httptest.NewRecorder()
			target.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))

			// Then
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "legacy-id") || strings.Contains(response.Body.String(), "legacy-token") {
				t.Fatalf("response leaks legacy dns credentials: %s", response.Body.String())
			}
			var body struct {
				Data struct {
					DNSCredentials string `json:"dns_credentials"`
					DNSProvider    string `json:"dns_provider"`
					ACMEEmail      string `json:"acme_email"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode config response: %v", err)
			}
			if body.Data.DNSCredentials != "" {
				t.Fatalf("dns_credentials=%q, want empty (field no longer served)", body.Data.DNSCredentials)
			}
			if body.Data.ACMEEmail != "ops@example.com" {
				t.Fatalf("acme_email=%q, want unaffected field intact", body.Data.ACMEEmail)
			}
		})
	}
}

// G4（第 74 轮）：设置页读路径 SQL 默认值字面量是治理默认值的第三次复制
// （DDL DEFAULT+启动回填+此处）——改参数绑定 db.Default* 常量后，本扫描钉
// 防字面量回流：GetConfig 函数体内治理列名旁不得再出现写死默认值字面量。
func TestGetConfig_noGovernedDefaultLiterals(t *testing.T) {
	src, err := os.ReadFile("caddy.go")
	if err != nil {
		t.Fatalf("read caddy.go: %v", err)
	}
	start := strings.Index(string(src), "func (h *Handlers) GetConfig(")
	if start < 0 {
		t.Fatal("GetConfig not found")
	}
	end := strings.Index(string(src)[start:], "\nfunc ")
	if end < 0 {
		t.Fatal("GetConfig end not found")
	}
	body := string(src)[start : start+end]
	for _, pattern := range []string{
		`cert_expiry_days,` + "\r?`?\\s*" + `30`,
		`caddy_log_size_mb,` + "\r?`?\\s*" + `100`,
		`ELSE\s+128`,
		`http_read_timeout,` + "\r?`?\\s*" + `60`,
		`http_write_timeout,` + "\r?`?\\s*" + `60`,
		`http_idle_timeout,` + "\r?`?\\s*" + `120`,
	} {
		re := regexp.MustCompile(pattern)
		if re.MatchString(body) {
			t.Errorf("GetConfig 治理默认值字面量回流 %q——改用 db.Default* 参数绑定（G4 单源）", pattern)
		}
	}
}

// G4 行为钉：cert_expiry_days（fresh DDL 可空列）NULL 形态读路径回退
// db.DefaultCertExpiryDays 常量，不 500 不零值。批 1+2 值型列（request_body/
// http_*/caddy_log_size_mb）fresh DDL NOT NULL+启动回填报证 NULL 不可达，
// 其 COALESCE(? 常量) 仅为防御形态——由 TestGetConfig_noGovernedDefaultLiterals
// 与 db_truth_defaults_test.go 双向钉覆盖。
func TestGetConfig_nullCertExpiryDaysFallsBackToConstant(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET cert_expiry_days=NULL WHERE id=1`); err != nil {
		t.Fatalf("null cert_expiry_days: %v", err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/config", h.GetConfig)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var body struct {
		Data struct {
			CertExpiryDays int `json:"cert_expiry_days"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Data.CertExpiryDays != db.DefaultCertExpiryDays {
		t.Fatalf("NULL cert_expiry_days 须回退 db.DefaultCertExpiryDays(%d), got %d", db.DefaultCertExpiryDays, body.Data.CertExpiryDays)
	}
}
