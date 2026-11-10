package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"

	"github.com/gin-gonic/gin"
)

// unpackExportBody 解包导出响应(lbbak tar.gz → config.json 原文)。
func unpackExportBody(t *testing.T, raw []byte) []byte {
	t.Helper()
	payload, err := parseLbbak(raw)
	if err != nil {
		t.Fatalf("export body is not lbbak: %v", err)
	}
	return payload.ConfigJSON
}

func newBackupSectionRouter(h *Handlers) *gin.Engine {
	gin.SetMode(gin.TestMode)
	g := gin.New()
	g.GET("/config/export", func(c *gin.Context) { c.Set("user_id", 1); c.Set("role", "admin"); h.ExportConfigBackup(c) })
	g.POST("/config/import", func(c *gin.Context) { c.Set("user_id", 1); c.Set("role", "admin"); h.ImportConfigBackup(c) })
	return g
}

// v2.3.0 分类导入导出(用户裁定):分类初版沿用集群同步五类,2026-09-19 已合并为
// 三分类(users/rules/security,legacy 键归一——config_backup.go configBackupSections);
// 导出按 sections 过滤;导入按 sections 只覆盖所选分类(校验和仍验整包)。
func TestConfigBackup_sectionFiltering(t *testing.T) {
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)

	// ---- 导出:仅负载规则 → Tables 只含 rules 四表,Config 为空 ----
	rec := httptest.NewRecorder()
	g.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/export?sections=rules", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", rec.Code, rec.Body.String())
	}
	var exported struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}
	if err := json.Unmarshal(unpackExportBody(t, rec.Body.Bytes()), &exported); err != nil {
		t.Fatal(err)
	}
	for table := range exported.Tables {
		switch table {
		case "lb_rules", "upstreams", "path_rules", "cert_jobs":
		default:
			t.Fatalf("sections=rules export leaked table %s", table)
		}
	}
	if len(exported.Config) != 0 {
		t.Fatalf("sections=rules export must not include global config, got %d keys", len(exported.Config))
	}

	// ---- 导入:整包备份 + sections=rules → 用户表不被覆盖 ----
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (5,'local-keeper','x','admin',1)`); err != nil {
		t.Fatal(err)
	}
	backup := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"lb_rules": {{"caddy_id": "imp1", "name": "imp", "protocol": "http", "domain": "a.example.com", "listen_port": 80, "enabled": 1}},
	}, EmptyConfigIfNil: true})

	// 顶层注入 sections(避免 strings.Replace 命中嵌套 '}')
	var parsed map[string]json.RawMessage
	if err := json.Unmarshal([]byte(backup), &parsed); err != nil {
		t.Fatal(err)
	}
	parsed["sections"] = json.RawMessage(`["rules"]`)
	assembled, _ := json.Marshal(parsed)
	body := string(assembled)
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	g.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", rec.Code, rec.Body.String())
	}
	var keeper int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM users WHERE username='local-keeper'`).Scan(&keeper); err != nil || keeper != 1 {
		t.Fatalf("sections=rules import must not touch users, count=%d err=%v", keeper, err)
	}
	var rules int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='imp1'`).Scan(&rules); err != nil || rules != 1 {
		t.Fatalf("sections=rules import must apply rules, count=%d err=%v", rules, err)
	}
}

// v3 纯 JSON 的分节选择必须走 ?sections= query（体内 sections 参与校验和，
// 改写会被判「已篡改」）。请求体保持原始字节：query 只缩不扩，交集为空 400。
func TestImportPureJson_sectionsQueryNarrowsWithoutBreachingChecksum(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedAdminShared(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_local_keep','keep','http','keep.example.com',80,1)`); err != nil {
		t.Fatal(err)
	}
	payload, _, _, _, err := h.buildLbbakExport(context.Background(), []string{"users"})
	if err != nil {
		t.Fatalf("buildLbbakExport: %v", err)
	}
	parsed, err := parseLbbak(payload)
	if err != nil {
		t.Fatalf("parseLbbak: %v", err)
	}
	// 取出 lbbak 内的 config.json：v3 纯 JSON（sections=["users"]，checksum 覆盖）。
	body := string(parsed.ConfigJSON)

	gin.SetMode(gin.TestMode)
	validateRouter := gin.New()
	validateRouter.POST("/config/import/validate", h.ValidateConfigImport)
	preview := func(endpoint string) importValidateResponse {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, endpoint, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		validateRouter.ServeHTTP(recorder, request)
		var envelope struct {
			Data importValidateResponse `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &envelope); err != nil {
			t.Fatalf("decode validate: %v body=%s", err, recorder.Body.String())
		}
		return envelope.Data
	}

	// query 与体内 sections 有交集：交集生效，且不改写体内值（否则判篡改）。
	if got := preview("/config/import/validate?sections=users,rules,security"); !got.Valid {
		t.Fatalf("preview 应可导入: %+v", got)
	}
	// query 与体内无交集：与导入同文案拒绝（不得零导入冒充成功）。
	if got := preview("/config/import/validate?sections=rules"); got.Valid || !strings.Contains(got.Error, "无交集") {
		t.Fatalf("preview=%+v, want 无交集", got)
	}

	disjoint := httptest.NewRecorder()
	disjointReq := httptest.NewRequest(http.MethodPost, "/config/import?sections=rules", strings.NewReader(body))
	disjointReq.Header.Set("Content-Type", "application/json")
	newBackupSectionRouter(h).ServeHTTP(disjoint, disjointReq)
	if disjoint.Code != http.StatusBadRequest || !strings.Contains(disjoint.Body.String(), "无交集") {
		t.Fatalf("disjoint import status=%d body=%s, want 400 无交集", disjoint.Code, disjoint.Body.String())
	}

	narrowed := httptest.NewRecorder()
	narrowedReq := httptest.NewRequest(http.MethodPost, "/config/import?sections=users", strings.NewReader(body))
	narrowedReq.Header.Set("Content-Type", "application/json")
	newBackupSectionRouter(h).ServeHTTP(narrowed, narrowedReq)
	if narrowed.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", narrowed.Code, narrowed.Body.String())
	}
	var kept int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_local_keep'`).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("本地规则 count=%d err=%v, want 未随 users 分节替换", kept, err)
	}
}
