package handlers

// 管理面板证书上传/保存的两个边界契约：
//   - 单文件超 1 MiB 显式 400「超过 1 MiB」，不得静默截断后让 tls.X509KeyPair
//     报「证书与私钥不匹配」（把大小问题伪装成材料问题）；
//   - 「值未变更」短路前仍跑形态校验：带外改库/坏导入留下的非法存量值，原样
//     提交不得以 200「未变更」固化且不给修复提示。

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestInspectAdminTLSCert_rejectsOversizedSingleFile(t *testing.T) {
	h := newBackupTestHandlers(t)
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	certPart, err := writer.CreateFormFile("cert_file", "cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := certPart.Write(bytes.Repeat([]byte("A"), 1<<20+1)); err != nil {
		t.Fatal(err)
	}
	keyPart, err := writer.CreateFormFile("key_file", "key.pem")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyPart.Write([]byte("placeholder")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/admin-tls/inspect", h.InspectAdminTLSCert)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()

	router.ServeHTTP(rec, request)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "超过 1 MiB") {
		t.Fatalf("body=%s, want 点名「超过 1 MiB」（不得以「证书与私钥不匹配」伪装大小问题）", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "不匹配") {
		t.Fatalf("body=%s, 超限被截断后才进入配对校验（误导性文案）", rec.Body.String())
	}
}

func TestUpdateAdminTLS_unchangedSubmissionStillValidatesStoredConfig(t *testing.T) {
	h := newBackupTestHandlers(t)
	// Given：带外写入的非法存量值（启用 upload 但无证书材料）。
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1, admin_tls_mode='upload', admin_tls_cert='', admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed invalid stored tls config: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/admin-tls", h.UpdateAdminTLS)
	// When：用户原样提交（空 JSON = 四值都不变）。
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, request)

	// Then：不得 200「配置未变更」把非法存量固化，须 400 点名存量无效。
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400（存量非法不得静默 200）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "当前已保存的管理面板 HTTPS 配置无效") {
		t.Fatalf("body=%s, want 点名存量配置无效并给出修复指引", rec.Body.String())
	}
	// 且库内值未被改写（失败不得落库）。
	var mode string
	if err := db.DB.QueryRow(`SELECT COALESCE(admin_tls_mode,'') FROM global_config WHERE id=1`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if mode != "upload" {
		t.Fatalf("admin_tls_mode=%q, want upload（校验失败不得落库）", mode)
	}
}
