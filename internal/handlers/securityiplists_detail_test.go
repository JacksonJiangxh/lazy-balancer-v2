package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// IP 列表弹框性能重构（v2.3.2）：列表接口不再内联 entries（大名单载荷瘦身），
// 新增单条详情端点供弹框按需拉取。
func TestListIPLists_omitsEntries_keepsCount(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('big-list', '恶意 IP', '[{"value":"10.0.0.1","remark":"a"},{"value":"10.0.0.2","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d", resp.Code)
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	var found map[string]any
	for _, row := range payload.Data {
		if row["name"] == "big-list" {
			found = row
		}
	}
	if found == nil {
		t.Fatal("big-list 行缺失")
	}
	if _, has := found["entries"]; has {
		t.Fatalf("列表载荷不得内联 entries: %v", found)
	}
	if found["entry_count"] != float64(2) {
		t.Fatalf("entry_count=%v, want 2", found["entry_count"])
	}
}

func TestGetIPList_returnsEntries(t *testing.T) {
	newBackupTestHandlers(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('detail-list', '数据中心', '[{"value":"192.0.2.1","remark":"r1"}]')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id", h.GetIPList)

	// When
	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(int(id)), nil))

	// Then
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "192.0.2.1") || !strings.Contains(resp.Body.String(), "r1") {
		t.Fatalf("详情须含条目: %s", resp.Body.String()[:300])
	}
	// 不存在 → 404
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, httptest.NewRequest(http.MethodGet, "/security/ip-lists/99999", nil))
	if resp2.Code != http.StatusNotFound {
		t.Fatalf("缺失 id status=%d, want 404", resp2.Code)
	}
}

// 用户名单不得与内置威胁名单重名（2026-09-24 用户裁定）——内置重名走专属
// 409 提示；同库既有通用重名校验含内置行，本测试钉住专属文案分支。
func TestCreateIPList_rejectsBuiltinName(t *testing.T) {
	newBackupTestHandlers(t) // 迁移已种子三源内置名单（新专业化名）
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/security/ip-lists", h.CreateIPList)

	body := `{"name":"中科大恶意 IP 名单（USTC）","category":"恶意 IP","entries":"[]"}`
	resp := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/security/ip-lists", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(resp, req)
	if resp.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	if !strings.Contains(resp.Body.String(), "内置威胁情报名单保留") {
		t.Fatalf("应提示内置保留名: %s", resp.Body.String())
	}
}

// 内置威胁名单引用门禁（2026-09-24 用户裁定）：system=1 名单仅允许 IP ACL
// 黑名单（deny）引用；信任名单 / ACL 白名单（allow/bypass）/ CRS 排除一律 400。
func TestCreatePolicy_rejectsBuiltinListOutsideACLDeny(t *testing.T) {
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/security/policies", h.CreateSecurityPolicy)
	var sysID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 ORDER BY id LIMIT 1`).Scan(&sysID); err != nil {
		t.Fatalf("内置名单种子缺失: %v", err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/security/policies", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp := httptest.NewRecorder()
		router.ServeHTTP(resp, req)
		return resp
	}
	refs := fmt.Sprintf(`[%d]`, sysID)

	// 信任名单引用内置名单 → 400
	if resp := post(`{"name":"t1","policy_type":"stage0","ip_whitelist_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("信任名单引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL 白名单模式引用内置名单 → 400
	if resp := post(`{"name":"t2","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"allow","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("ACL allow 引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL bypass 引用内置名单 → 400
	if resp := post(`{"name":"t2b","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"bypass","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusBadRequest {
		t.Fatalf("ACL bypass 引用内置名单应 400, got %d: %s", resp.Code, resp.Body.String())
	}
	// ACL 黑名单模式引用内置名单 → 放行（唯一合法用途）
	if resp := post(`{"name":"t3","policy_type":"stage1","ip_acl_enabled":true,"ip_acl_mode":"deny","ip_acl_list_refs":"` + refs + `"}`); resp.Code != http.StatusOK {
		t.Fatalf("ACL deny 引用内置名单应放行, got %d: %s", resp.Code, resp.Body.String())
	}
	// 用户名单不受限（信任名单引用自建名单 → 放行）
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, category, entries) VALUES ('自建名单', '数据中心', '[]')`); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name='自建名单'`).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if resp := post(fmt.Sprintf(`{"name":"t4","policy_type":"stage0","ip_whitelist_refs":"[%d]"}`, userID)); resp.Code != http.StatusOK {
		t.Fatalf("信任名单引用自建名单应放行, got %d: %s", resp.Code, resp.Body.String())
	}
}

// RDB 文件化（v2.3.4）：system=1 威胁库详情条目从 .iplist 文件读取
// （DB entries 已恒空）；system=0 仍读 DB entries（回归形状）。
func TestGetIPList_systemListReadsIplistFile(t *testing.T) {
	newBackupTestHandlers(t)
	wafDir := t.TempDir()
	restoreWaf := services.OverrideThreatWafDirForTest(wafDir)
	defer restoreWaf()
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("192.0.2.0/24\n198.51.100.7\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 内置威胁名单行（迁移已种子；DB entries 恒空）
	var id int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 AND name=?`, db.ThreatListNameBySource("ustc")).Scan(&id); err != nil {
		t.Fatalf("种子威胁名单缺失: %v", err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists/:id", h.GetIPList)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(int(id)), nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", resp.Code, resp.Body.String())
	}
	body := resp.Body.String()
	if !strings.Contains(body, "192.0.2.0/24") || !strings.Contains(body, "198.51.100.7") {
		t.Fatalf("详情须含 .iplist 文件条目: %s", body[:min(300, len(body))])
	}
	if !strings.Contains(body, `"entry_count":2`) {
		t.Fatalf("entry_count 必须=2: %s", body[:min(300, len(body))])
	}

	// 文件缺失（禁用/未更新）→ 空集不报错
	os.Remove(filepath.Join(wafDir, "threat-ustc.iplist"))
	resp2 := httptest.NewRecorder()
	router.ServeHTTP(resp2, httptest.NewRequest(http.MethodGet, "/security/ip-lists/"+strconv.Itoa(int(id)), nil))
	if resp2.Code != http.StatusOK {
		t.Fatalf("文件缺失应返回空集 200, got %d", resp2.Code)
	}
	if !strings.Contains(resp2.Body.String(), `"entry_count":0`) {
		t.Fatalf("文件缺失 entry_count=0: %s", resp2.Body.String()[:min(300, len(resp2.Body.String()))])
	}
}

// RDB 文件化回归（v2.3.4）：system=1 行 entries=”（空串非 NULL）时
// ListIPLists 不得因 json_array_length(”) 报 500；威胁库条数改由
// security_threat_sources.entry_count 供给。
func TestListIPLists_emptyEntriesOnSystemRows(t *testing.T) {
	newBackupTestHandlers(t) // 迁移已种子三源内置名单与 threat_sources 行
	// RDB 形态：system 行 entries 置空串（非 NULL——COALESCE 不会替换）
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='' WHERE system=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET entry_count=14189 WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/security/ip-lists", h.ListIPLists)

	resp := httptest.NewRecorder()
	router.ServeHTTP(resp, httptest.NewRequest(http.MethodGet, "/security/ip-lists", nil))
	if resp.Code != http.StatusOK {
		t.Fatalf("entries='' 的 system 行不得 500: status=%d body=%s", resp.Code, resp.Body.String()[:min(200, len(resp.Body.String()))])
	}
	var payload struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	for _, row := range payload.Data {
		if row["system"] == true && strings.Contains(row["name"].(string), "USTC") {
			if row["entry_count"] != float64(14189) {
				t.Fatalf("威胁库 entry_count 须取自 threat_sources: got %v want 14189", row["entry_count"])
			}
		}
	}
}
