package handlers

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
)

func TestUpdateAdminTLS_disables_upload_mode_without_new_files(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
		admin_tls_cert='existing cert',admin_tls_key='existing key' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	var body strings.Builder
	writer := multipart.NewWriter(&body)
	if err := writer.WriteField("enabled", "false"); err != nil {
		t.Fatalf("write enabled field: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls", strings.NewReader(body.String()))
	request.Header.Set("Content-Type", writer.FormDataContentType())
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	var cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_enabled,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&enabled, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if enabled || cert != "existing cert" || key != "existing key" {
		t.Fatalf("saved config=(%v,%q,%q), want disabled with existing files", enabled, cert, key)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
}

func TestInspectAdminTLSCertJSONBody_acceptsPEMStringFields(t *testing.T) {
	// Given：JSON 通道（MCP 转发）以 cert_file/key_file PEM 字符串入参，
	// 与 multipart 文件上传走同一校验链
	certPEM, keyPEM, err := generateTestCert("json-inspect.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	body, err := json.Marshal(map[string]string{"cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal inspect body: %v", err)
	}
	router := gin.New()
	router.POST("/admin-tls/inspect", (&Handlers{cfg: &config.Config{}}).InspectAdminTLSCert)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			Domain string `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if payload.Data.Domain != "json-inspect.example.com" {
		t.Fatalf("domain=%q, want json-inspect.example.com", payload.Data.Domain)
	}
}

func TestInspectAdminTLSCertJSONBody_rejectsInvalidPEMLikeMultipart(t *testing.T) {
	// Given：同一对不匹配的证书/私钥分别经 multipart 文件与 JSON 字符串提交
	certPEM, keyPEM, err := generateMismatchedCert()
	if err != nil {
		t.Fatalf("generate mismatched pair: %v", err)
	}
	jsonBody, err := json.Marshal(map[string]string{"cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal json body: %v", err)
	}
	var formBody bytes.Buffer
	writer := multipart.NewWriter(&formBody)
	writeFile := func(field, content string) {
		part, err := writer.CreateFormFile(field, field+".pem")
		if err != nil {
			t.Fatalf("create form file %s: %v", field, err)
		}
		if _, err := part.Write([]byte(content)); err != nil {
			t.Fatalf("write form file %s: %v", field, err)
		}
	}
	writeFile("cert_file", certPEM)
	writeFile("key_file", keyPEM)
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}
	router := gin.New()
	router.POST("/admin-tls/inspect", (&Handlers{cfg: &config.Config{}}).InspectAdminTLSCert)

	// When：multipart 文件上传
	multipartRequest := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", bytes.NewReader(formBody.Bytes()))
	multipartRequest.Header.Set("Content-Type", writer.FormDataContentType())
	multipartResponse := httptest.NewRecorder()
	router.ServeHTTP(multipartResponse, multipartRequest)
	// And：JSON 通道
	jsonRequest := httptest.NewRequest(http.MethodPost, "/admin-tls/inspect", bytes.NewReader(jsonBody))
	jsonRequest.Header.Set("Content-Type", "application/json")
	jsonResponse := httptest.NewRecorder()
	router.ServeHTTP(jsonResponse, jsonRequest)

	// Then：两通道同为 400 且错误文案一致（无效 PEM 的同语义契约）
	if multipartResponse.Code != http.StatusBadRequest || jsonResponse.Code != http.StatusBadRequest {
		t.Fatalf("multipart=%d json=%d, want both 400", multipartResponse.Code, jsonResponse.Code)
	}
	if multipartResponse.Body.String() != jsonResponse.Body.String() {
		t.Fatalf("multipart body=%s json body=%s, want identical error contract", multipartResponse.Body.String(), jsonResponse.Body.String())
	}
	if !strings.Contains(jsonResponse.Body.String(), "证书与私钥不匹配") {
		t.Fatalf("json body=%s, want mismatch error", jsonResponse.Body.String())
	}
}

func TestUpdateAdminTLSJSONBody_savesUploadModeCertificate(t *testing.T) {
	// Given：JSON 通道提交 upload 模式证书（enabled/mode/cert_file/key_file
	// 字段名与 multipart 表单一致），走与文件上传相同的校验与落盘链路
	initializeRuleFeatureTestDB(t)
	certPEM, keyPEM, err := generateTestCert("json-update.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	body, err := json.Marshal(map[string]any{"enabled": true, "mode": "upload", "cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal update body: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
	router := gin.New()
	router.PUT("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：保存成功、落库内容与提交 PEM 一致、重启已排期
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var enabled bool
	var mode, cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_enabled,admin_tls_mode,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&enabled, &mode, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if !enabled || mode != "upload" || cert != certPEM || key != keyPEM {
		t.Fatalf("saved config=(%v,%q,cert match=%v,key match=%v), want enabled upload with submitted PEM", enabled, mode, cert == certPEM, key == keyPEM)
	}
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
}

func TestUpdateAdminTLSJSONBody_rejectsMismatchedPairWithoutSaving(t *testing.T) {
	// Given：upload 模式提交不匹配证书对——校验层拦截，不落库不重启
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=0,admin_tls_mode='selfsigned',
		admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	certPEM, keyPEM, err := generateMismatchedCert()
	if err != nil {
		t.Fatalf("generate mismatched pair: %v", err)
	}
	oldExit := exitProcess
	exitProcess = func(int) { t.Error("restart must not be scheduled for rejected update") }
	t.Cleanup(func() { exitProcess = oldExit })
	body, err := json.Marshal(map[string]any{"enabled": false, "mode": "upload", "cert_file": certPEM, "key_file": keyPEM})
	if err != nil {
		t.Fatalf("marshal update body: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
	router := gin.New()
	router.PUT("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "证书与私钥不匹配") {
		t.Fatalf("status=%d body=%s, want 400 mismatch", response.Code, response.Body.String())
	}
	var cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if cert != "" || key != "" {
		t.Fatalf("saved cert/key non-empty (cert=%v,key=%v), want unchanged", cert != "", key != "")
	}
}

// 历史问题 LBH-F9：2 MiB MaxBytesReader 上限超限 body 须 413（原恒 400，与规则域
// 413 口径不一致）。JSON 通道两入口（保存/预检）同门。
func TestAdminTLSOversizedBodyReturns413(t *testing.T) {
	// Given：超过 2 MiB 的 JSON 体（cert_file 承载超长 PEM 串）
	body := `{"mode":"selfsigned","cert_file":"` + strings.Repeat("a", (2<<20)+64) + `"}`
	newRouter := func(handler gin.HandlerFunc, method, path string) *gin.Engine {
		router := gin.New()
		router.Handle(method, path, handler)
		return router
	}
	send := func(router *gin.Engine, method, path string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}

	// When：保存与预检两入口各发一次超限请求
	updateResponse := send(newRouter((&Handlers{cfg: &config.Config{}}).UpdateAdminTLS, http.MethodPut, "/admin-tls"), http.MethodPut, "/admin-tls")
	inspectResponse := send(newRouter((&Handlers{cfg: &config.Config{}}).InspectAdminTLSCert, http.MethodPost, "/admin-tls/inspect"), http.MethodPost, "/admin-tls/inspect")

	// Then：均为 413（非 400）
	if updateResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT /admin-tls oversized status=%d body=%s, want 413", updateResponse.Code, updateResponse.Body.String())
	}
	if inspectResponse.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("POST /admin-tls/inspect oversized status=%d body=%s, want 413", inspectResponse.Code, inspectResponse.Body.String())
	}
}

// 历史问题（历史）：审计 detail 须显式记录本次是否替换了证书材料——
// 仅启用/禁用 + 来源无法区分「只开关」与「换证书」。
func TestUpdateAdminTLS_auditDetailRecordsCertificateReplacement(t *testing.T) {
	newRouter := func(handler gin.HandlerFunc) *gin.Engine {
		router := gin.New()
		router.PUT("/admin-tls", handler)
		return router
	}
	latestDetail := func(t *testing.T) string {
		t.Helper()
		var detail string
		if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新' AND resource='基础设置' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
			t.Fatalf("read audit detail: %v", err)
		}
		return detail
	}
	sendJSON := func(t *testing.T, payload map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		newRouter((&Handlers{cfg: &config.Config{Port: 8000}}).UpdateAdminTLS).ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		return response
	}

	t.Run("上传替换证书", func(t *testing.T) {
		initializeRuleFeatureTestDB(t)
		oldExit := exitProcess
		exited := make(chan struct{}, 1)
		exitProcess = func(int) { exited <- struct{}{} }
		t.Cleanup(func() { exitProcess = oldExit })
		if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=0,admin_tls_mode='selfsigned',
			admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
			t.Fatalf("seed admin TLS config: %v", err)
		}
		certPEM, keyPEM, err := generateTestCert("u13-10-replace.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		if err != nil {
			t.Fatalf("generate cert pair: %v", err)
		}

		sendJSON(t, map[string]any{"enabled": true, "mode": "upload", "cert_file": certPEM, "key_file": keyPEM})

		if detail := latestDetail(t); !strings.Contains(detail, "证书：已更换（来源 upload）") {
			t.Fatalf("audit detail=%q, want 含「证书：已更换（来源 upload）」", detail)
		}
		// 等待 restartProcess 的延迟退出 goroutine 在桩生效期内消费，避免清理
		// 还原 exitProcess 后被迟到的 os.Exit 打穿测试进程（同既有用例口径）。
		select {
		case <-exited:
		case <-time.After(time.Second):
			t.Fatal("restart was not scheduled")
		}
	})

	t.Run("仅开关未换证书", func(t *testing.T) {
		initializeRuleFeatureTestDB(t)
		oldExit := exitProcess
		exited := make(chan struct{}, 1)
		exitProcess = func(int) { exited <- struct{}{} }
		t.Cleanup(func() { exitProcess = oldExit })
		certPEM, keyPEM, err := generateTestCert("u13-10-toggle.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		if err != nil {
			t.Fatalf("generate cert pair: %v", err)
		}
		if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
			admin_tls_cert=?,admin_tls_key=? WHERE id=1`, certPEM, keyPEM); err != nil {
			t.Fatalf("seed admin TLS config: %v", err)
		}

		sendJSON(t, map[string]any{"enabled": false})

		detail := latestDetail(t)
		if !strings.Contains(detail, "证书：未更换") {
			t.Fatalf("audit detail=%q, want 含「证书：未更换」", detail)
		}
		if strings.Contains(detail, "已更换") {
			t.Fatalf("audit detail=%q, want 不应声称证书更换（本次仅切换启用态）", detail)
		}
		select {
		case <-exited:
		case <-time.After(time.Second):
			t.Fatal("restart was not scheduled")
		}
	})
}

// B2-03（历史）：upload → selfsigned 切换此前把已上传证书/私钥继续留在
// global_config（selfsigned 由 ResolveCertificate 自生成，残留 upload 材料无消费者，
// 且随备份/导入继续传播）。切换后必须清空；upload 模式禁用保留既有钉测已锁。
func TestUpdateAdminTLS_switchingToSelfsignedClearsUploadedMaterial(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='upload',
		admin_tls_cert='existing cert',admin_tls_key='existing key' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	handler := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls",
		strings.NewReader(`{"enabled":true,"mode":"selfsigned"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var mode, cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_mode,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&mode, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if mode != "selfsigned" || cert != "" || key != "" {
		t.Fatalf("saved=(%q,%q,%q), want selfsigned 且证书材料清空", mode, cert, key)
	}
	// 变更路径必重启——且须在本测试内收走 500ms 延迟的 exitProcess 调用，
	// 否则残留 goroutine 会打进后续测试的 stub（跨测试污染实证）。
	select {
	case <-exited:
	case <-time.After(time.Second):
		t.Fatal("restart was not scheduled")
	}
}

// B2-04（历史）：值未变更时 PUT /admin-tls 此前仍写库并触发进程重启
// （设置页重复保存=无谓停机）。未变更 → 200「未变更」、不写库、不重启。
func TestUpdateAdminTLS_unchangedConfigSkipsWriteAndRestart(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='selfsigned',
		admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	oldExit := exitProcess
	exited := make(chan struct{}, 1)
	exitProcess = func(int) { exited <- struct{}{} }
	t.Cleanup(func() { exitProcess = oldExit })
	handler := &Handlers{cfg: &config.Config{DataDir: t.TempDir()}}
	router := gin.New()
	router.POST("/admin-tls", handler.UpdateAdminTLS)
	request := httptest.NewRequest(http.MethodPost, "/admin-tls",
		strings.NewReader(`{"enabled":true,"mode":"selfsigned"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "未变更") {
		t.Fatalf("body=%s, want 未变更提示", response.Body.String())
	}
	select {
	case <-exited:
		t.Fatal("未变更配置不得触发重启")
	case <-time.After(800 * time.Millisecond):
	}
}

// B2-历史问题（历史）：携带证书材料但生效来源不是 upload 时不得静默丢弃
// （旧行为可能回「配置未变更」200）——必须 400 点名正确做法且不落库。
func TestUpdateAdminTLSJSONBody_rejectsUploadPayloadWithoutUploadMode(t *testing.T) {
	initializeRuleFeatureTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=0,admin_tls_mode='selfsigned',
		admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
		t.Fatalf("seed admin TLS config: %v", err)
	}
	certPEM, keyPEM, err := generateTestCert("silent-drop.example.com", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate cert pair: %v", err)
	}
	oldExit := exitProcess
	exitProcess = func(int) { t.Error("rejected update must not schedule restart") }
	t.Cleanup(func() { exitProcess = oldExit })
	handler := &Handlers{cfg: &config.Config{Port: 8000}}
	router := gin.New()
	router.PUT("/admin-tls", handler.UpdateAdminTLS)

	for _, test := range []struct {
		name string
		body map[string]any
	}{
		{name: "mode omitted (keeps current selfsigned)", body: map[string]any{"enabled": false, "cert_file": certPEM, "key_file": keyPEM}},
		{name: "explicit non-upload mode", body: map[string]any{"enabled": false, "mode": "selfsigned", "cert_file": certPEM, "key_file": keyPEM}},
	} {
		payload, err := json.Marshal(test.body)
		if err != nil {
			t.Fatalf("marshal %s: %v", test.name, err)
		}
		request := httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "证书来源不是 upload") {
			t.Fatalf("%s status=%d body=%s, want 400 upload-mode guidance", test.name, response.Code, response.Body.String())
		}
	}
	var mode, cert, key string
	if err := db.DB.QueryRow("SELECT admin_tls_mode,admin_tls_cert,admin_tls_key FROM global_config WHERE id=1").Scan(&mode, &cert, &key); err != nil {
		t.Fatalf("read admin TLS config: %v", err)
	}
	if mode != "selfsigned" || cert != "" || key != "" {
		t.Fatalf("saved config=(%q,%v,%v), want untouched selfsigned", mode, cert != "", key != "")
	}
}

// B2-历史问题：enabled 是安全开关，字符串值必须遵循 true/1/false/0 白名单；
// 非法拼写不得静默按 false 关闭 HTTPS 并触发重启，合法 "0" 保持回归。
func TestUpdateAdminTLS_enabledValueWhitelist(t *testing.T) {
	for _, tc := range []struct {
		name        string
		multipart   bool
		value       string
		wantStatus  int
		wantEnabled bool
		wantRestart bool
	}{
		{name: "JSON invalid uppercase", value: "TRUE", wantStatus: http.StatusBadRequest, wantEnabled: true},
		{name: "multipart invalid text", multipart: true, value: "on", wantStatus: http.StatusBadRequest, wantEnabled: true},
		{name: "JSON valid zero", value: "0", wantStatus: http.StatusOK, wantEnabled: false, wantRestart: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			initializeRuleFeatureTestDB(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET admin_tls_enabled=1,admin_tls_mode='selfsigned',admin_tls_cert='',admin_tls_key='' WHERE id=1`); err != nil {
				t.Fatalf("seed admin TLS config: %v", err)
			}
			oldExit := exitProcess
			exited := make(chan struct{}, 1)
			exitProcess = func(int) { exited <- struct{}{} }
			t.Cleanup(func() { exitProcess = oldExit })
			handler := &Handlers{cfg: &config.Config{Port: 8000}}
			router := gin.New()
			router.PUT("/admin-tls", handler.UpdateAdminTLS)

			var request *http.Request
			if tc.multipart {
				var body strings.Builder
				writer := multipart.NewWriter(&body)
				if err := writer.WriteField("enabled", tc.value); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				request = httptest.NewRequest(http.MethodPut, "/admin-tls", strings.NewReader(body.String()))
				request.Header.Set("Content-Type", writer.FormDataContentType())
			} else {
				payload, err := json.Marshal(map[string]any{"enabled": tc.value})
				if err != nil {
					t.Fatal(err)
				}
				request = httptest.NewRequest(http.MethodPut, "/admin-tls", bytes.NewReader(payload))
				request.Header.Set("Content-Type", "application/json")
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != tc.wantStatus {
				t.Fatalf("status=%d body=%s, want %d", response.Code, response.Body.String(), tc.wantStatus)
			}
			var enabled bool
			if err := db.DB.QueryRow(`SELECT admin_tls_enabled FROM global_config WHERE id=1`).Scan(&enabled); err != nil {
				t.Fatal(err)
			}
			if enabled != tc.wantEnabled {
				t.Fatalf("enabled=%v, want %v", enabled, tc.wantEnabled)
			}
			if tc.wantRestart {
				select {
				case <-exited:
				case <-time.After(2 * time.Second):
					t.Fatal("合法状态变更未触发重启")
				}
			} else {
				select {
				case <-exited:
					t.Fatal("非法 enabled 触发了重启")
				case <-time.After(600 * time.Millisecond):
				}
			}
		})
	}
}
