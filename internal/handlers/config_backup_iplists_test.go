package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func postBackupImport(t *testing.T, h *Handlers, backup string) *httptest.ResponseRecorder {
	t.Helper()
	router := gin.New()
	router.POST("/config/import", h.ImportConfigBackup)
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(backup))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

// W2：策略 refs 引用备份内不存在的 IP 列表 → 整包 400 点名策略与悬挂 id，
// 零写入（与 历史问题 C-#2 绑定悬挂引用同口径——refs 落库后引用展开静默跳过，
// UI 宣称的引用控制静默失效）。
func TestImportConfigBackup_rejectsPolicyReferencingMissingIPList(t *testing.T) {
	// Given：策略引用列表 99，备份仅有列表 1
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_policies": {{"id": 7, "name": "refs-policy", "mode": "off", "ip_acl_list_refs": "[99]", "ip_whitelist_refs": "[1]"}},
		"security_ip_lists": {{"id": 1, "name": "list-1", "entries": "[]"}},
	})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	for _, want := range []string{"refs-policy", "引用了不存在的 IP 列表 99"} {
		if !strings.Contains(response.Body.String(), want) {
			t.Fatalf("rejection must name %q: %s", want, response.Body.String())
		}
	}
	for _, table := range []string{"security_policies", "security_ip_lists"} {
		var count int
		// security_ip_lists 含三行 system=1 内置名单种子（v2.3.2 名单化）——
		// 与被拒备份无关，只计用户行（security_policies 无 system 列）。
		query := "SELECT COUNT(*) FROM " + table
		if table == "security_ip_lists" {
			query += " WHERE COALESCE(system,0)=0"
		}
		if err := db.DB.QueryRow(query).Scan(&count); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		if count != 0 {
			t.Fatalf("rejected backup must not persist %s, got %d rows", table, count)
		}
	}
}

// W2 对照组：引用完整的 refs + 列表（含空串 entries 视同 '[]'）导入成功并落库。
func TestImportConfigBackup_acceptsValidIPListReferences(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_policies": {{"id": 7, "name": "refs-policy", "mode": "off", "ip_acl_list_refs": "[1,2]", "ip_whitelist_refs": "[2]"}},
		"security_ip_lists": {
			{"id": 1, "name": "acl-list", "entries": `[{"value":"10.0.0.1","remark":"r"}]`},
			{"id": 2, "name": "wl-list", "entries": ""},
		},
	})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var aclRefs, wlRefs string
	if err := db.DB.QueryRow("SELECT ip_acl_list_refs,ip_whitelist_refs FROM security_policies WHERE id=7").Scan(&aclRefs, &wlRefs); err != nil {
		t.Fatalf("read imported policy refs: %v", err)
	}
	if aclRefs != "[1,2]" || wlRefs != "[2]" {
		t.Fatalf("imported refs mismatch: acl=%q whitelist=%q", aclRefs, wlRefs)
	}
	var listCount, systemCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE system=0").Scan(&listCount); err != nil {
		t.Fatalf("count imported ip lists: %v", err)
	}
	if listCount != 2 {
		t.Fatalf("imported user ip lists=%d, want 2", listCount)
	}
	// 历史问题-1：导入后必须重播 system 名单（威胁三源 + 自动封禁）。
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE system=1").Scan(&systemCount); err != nil {
		t.Fatal(err)
	}
	if systemCount != 4 {
		t.Fatalf("system ip lists=%d, want 4", systemCount)
	}
}

// W2：refs 形状门——必须是整数数组的 JSON 文本（字符串列），非数组 JSON、
// 非整数元素、非字符串类型均 400 点名字段。
func TestImportConfigBackup_rejectsMalformedIPListRefs(t *testing.T) {
	tests := []struct {
		name  string
		refs  any
		field string
	}{
		{name: "non-array json", refs: `{"x":1}`, field: "ip_acl_list_refs"},
		{name: "non-integer elements", refs: `["a","b"]`, field: "ip_acl_list_refs"},
		{name: "fractional elements", refs: `[1.5]`, field: "ip_whitelist_refs"},
		{name: "non-string inline array", refs: []any{1, 2}, field: "ip_acl_list_refs"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			policy := map[string]any{"id": 7, "name": "refs-policy", "mode": "off"}
			policy[tt.field] = tt.refs
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"security_policies": {policy},
				"security_ip_lists": {{"id": 1, "name": "list-1", "entries": "[]"}},
			})

			// When
			response := postBackupImport(t, h, backup)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			for _, want := range []string{tt.field, "需为整数数组的 JSON 文本"} {
				if !strings.Contains(response.Body.String(), want) {
					t.Fatalf("rejection must name %q: %s", want, response.Body.String())
				}
			}
		})
	}
}

// W2：security_ip_lists.entries 形状门——备份携带该表时 entries 需为 JSON
// 数组文本（空串视同 '[]'）；非 JSON / 非数组 / 非字符串类型均 400 点名行。
func TestImportConfigBackup_rejectsIPListWithInvalidEntries(t *testing.T) {
	tests := []struct {
		name    string
		entries any
	}{
		{name: "not json", entries: "not-json"},
		{name: "json object not array", entries: `{"value":"10.0.0.1"}`},
		{name: "non-string type", entries: 123},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given
			h := newBackupTestHandlers(t)
			backup := completeBackupJSON(t, map[string][]map[string]any{
				"security_ip_lists": {{"id": 1, "name": "bad-list", "entries": tt.entries}},
			})

			// When
			response := postBackupImport(t, h, backup)

			// Then
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
			for _, want := range []string{"安全 IP 列表 #1", "entries 需为 JSON 数组文本"} {
				if !strings.Contains(response.Body.String(), want) {
					t.Fatalf("rejection must name %q: %s", want, response.Body.String())
				}
			}
		})
	}
}

// W2：导出携带 security_ip_lists 行与策略 refs 列（导出/导入往返不丢引用）。
func TestExportConfigBackup_includesSecurityIPLists(t *testing.T) {
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,description,category,entries) VALUES (13,'exp-list','d','allow','[{"value":"10.0.0.1","remark":""}]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode,ip_acl_list_refs) VALUES (4,'p','off','[13]')`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)

	// When
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/config/export", nil))

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var backup configBackup
	if err := json.Unmarshal(unpackExportBody(t, response.Body.Bytes()), &backup); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	listRows, ok := backup.Tables["security_ip_lists"]
	if !ok {
		t.Fatal("export must carry security_ip_lists")
	}
	// 3 行 system=1 内置名单（v2.3.2 名单化）随表导出——引用它们的策略
	// 经备份还原后引用目标必须存在；用户行按 system=0 过滤断言。
	var userRows []map[string]any
	for _, row := range listRows {
		if row["system"] == float64(0) || row["system"] == nil {
			userRows = append(userRows, row)
		}
	}
	if len(userRows) != 1 {
		t.Fatalf("export must carry exactly 1 user ip list row, got %+v", listRows)
	}
	if userRows[0]["name"] != "exp-list" || userRows[0]["category"] != "allow" {
		t.Fatalf("exported ip list row mismatch: %+v", userRows[0])
	}
	policyRows := backup.Tables["security_policies"]
	if len(policyRows) != 1 || policyRows[0]["ip_acl_list_refs"] != "[13]" {
		t.Fatalf("exported policy refs missing: %+v", policyRows)
	}
}

// W2：全量替换语义——备份携带空 security_ip_lists 表（主节点已清空）时，
// 导入必须清掉本地列表行（deleteOrder/insertOrder 含新表）。
func TestImportConfigBackup_emptyIPListsTableWipesLocalLists(t *testing.T) {
	// Given：本地存在备份之外的列表行
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (id,name,entries) VALUES (11,'local-only','[]')`); err != nil {
		t.Fatal(err)
	}
	backup := completeBackupJSON(t, map[string][]map[string]any{
		"security_ip_lists": {},
	})

	// When
	response := postBackupImport(t, h, backup)

	// Then
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE system=0").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("security_ip_lists rows=%d after empty-table import, want 0", count)
	}
	// 历史问题-1：空表导入后 system 名单仍由提交后重播补回。
	var systemCount int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_ip_lists WHERE system=1").Scan(&systemCount); err != nil {
		t.Fatal(err)
	}
	if systemCount != 4 {
		t.Fatalf("system ip lists=%d after empty-table import, want 4", systemCount)
	}
}

func emptyBackupSecurityTables() map[string][]map[string]any {
	return map[string][]map[string]any{
		"security_custom_rules": {},
		"security_ip_lists":     {},
		"security_policies":     {},
		"security_block_pages":  {},
	}
}

func TestValidateV2BackupSecurityPolicies_rejectsBuiltinListMisuse(t *testing.T) {
	builtinList := map[string]any{"id": 1, "name": "内置威胁名单", "system": 1, "entries": `[{"value":"203.0.113.8","remark":""}]`}
	for _, tc := range []struct {
		name   string
		policy map[string]any
		want   string
	}{
		{name: "trust whitelist", policy: map[string]any{"id": 7, "name": "bad-trust", "mode": "off", "ip_whitelist_refs": "[1]"}, want: "不能用于信任名单"},
		{name: "ACL allow", policy: map[string]any{"id": 7, "name": "bad-allow", "mode": "off", "ip_acl_enabled": 1, "ip_acl_mode": "allow", "ip_acl_list": "[]", "ip_acl_list_refs": "[1]"}, want: "仅允许用于 IP 访问控制的黑名单模式"},
		{name: "ACL 绕过", policy: map[string]any{"id": 7, "name": "bad-绕过", "mode": "off", "ip_acl_mode": "绕过", "ip_acl_list_refs": "[1]"}, want: "仅允许用于 IP 访问控制的黑名单模式"},
		{name: "CRS exclusion", policy: map[string]any{"id": 7, "name": "bad-crs", "mode": "off", "crs_excluded_rules": `[{"target":"942550","scope":"list","listRefs":[1]}]`}, want: "不能用于 CRS 排除"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tables := emptyBackupSecurityTables()
			tables["security_ip_lists"] = []map[string]any{builtinList}
			tables["security_policies"] = []map[string]any{tc.policy}
			if err := validateV2BackupSecurityPolicies(tables, true); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want containing %q", err, tc.want)
			}
		})
	}

	// 回归：唯一合法用途 ACL deny 必须继续通过。
	tables := emptyBackupSecurityTables()
	tables["security_ip_lists"] = []map[string]any{builtinList}
	tables["security_policies"] = []map[string]any{{"id": 7, "name": "valid-deny", "mode": "off", "ip_acl_enabled": 1, "ip_acl_mode": "deny", "ip_acl_list_refs": "[1]"}}
	if err := validateV2BackupSecurityPolicies(tables, true); err != nil {
		t.Fatalf("builtin deny reference must remain valid: %v", err)
	}
}

func TestValidateV2BackupSecurityPolicies_enforcesSaveSideQuotas(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string][]map[string]any)
		want   string
	}{
		{name: "list name", mutate: func(t map[string][]map[string]any) {
			t["security_ip_lists"] = []map[string]any{{"id": 1, "name": strings.Repeat("n", 51), "entries": "[]"}}
		}, want: "名称长度"},
		{name: "list description", mutate: func(t map[string][]map[string]any) {
			t["security_ip_lists"] = []map[string]any{{"id": 1, "name": "ok", "description": strings.Repeat("d", 201), "entries": "[]"}}
		}, want: "描述长度"},
		{name: "list category", mutate: func(t map[string][]map[string]any) {
			t["security_ip_lists"] = []map[string]any{{"id": 1, "name": "ok", "category": strings.Repeat("c", 33), "entries": "[]"}}
		}, want: "分类长度"},
		{name: "list entries", mutate: func(t map[string][]map[string]any) {
			t["security_ip_lists"] = []map[string]any{{"id": 1, "name": "ok", "entries": bigEntriesJSON(2001)}}
		}, want: "条目数量"},
		{name: "entry remark", mutate: func(t map[string][]map[string]any) {
			t["security_ip_lists"] = []map[string]any{{"id": 1, "name": "ok", "entries": fmt.Sprintf(`[{"value":"10.0.0.1","remark":"%s"}]`, strings.Repeat("r", 101))}}
		}, want: "备注长度"},
		{name: "global list count", mutate: func(t map[string][]map[string]any) {
			rows := make([]map[string]any, 201)
			for i := range rows {
				rows[i] = map[string]any{"id": i + 1, "name": fmt.Sprintf("list-%d", i+1), "entries": "[]"}
			}
			t["security_ip_lists"] = rows
		}, want: "数量已达上限"},
		{name: "policy name", mutate: func(t map[string][]map[string]any) {
			t["security_policies"] = []map[string]any{{"id": 7, "name": strings.Repeat("p", 101), "mode": "off"}}
		}, want: "策略名称"},
		{name: "policy description", mutate: func(t map[string][]map[string]any) {
			t["security_policies"] = []map[string]any{{"id": 7, "name": "ok", "description": strings.Repeat("d", 501), "mode": "off"}}
		}, want: "策略描述"},
		{name: "page name", mutate: func(t map[string][]map[string]any) {
			t["security_block_pages"] = []map[string]any{{"id": 9, "name": strings.Repeat("p", 101), "content": "x"}}
		}, want: "拦截页面名称"},
		{name: "page description", mutate: func(t map[string][]map[string]any) {
			t["security_block_pages"] = []map[string]any{{"id": 9, "name": "ok", "description": strings.Repeat("d", 501), "content": "x"}}
		}, want: "拦截页面描述"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tables := emptyBackupSecurityTables()
			tc.mutate(tables)
			if err := validateV2BackupSecurityPolicies(tables, true); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v, want containing %q", err, tc.want)
			}
		})
	}

	// 边界回归：2000 条目、100/500 rune 文本与 200 个名单均合法。
	tables := emptyBackupSecurityTables()
	lists := make([]map[string]any, 200)
	for i := range lists {
		lists[i] = map[string]any{"id": i + 1, "name": fmt.Sprintf("list-%d", i+1), "entries": "[]"}
	}
	lists[0]["name"] = strings.Repeat("n", 50)
	lists[0]["description"] = strings.Repeat("d", 200)
	lists[0]["category"] = strings.Repeat("c", 32)
	lists[0]["entries"] = bigEntriesJSON(2000)
	tables["security_ip_lists"] = lists
	tables["security_policies"] = []map[string]any{{"id": 7, "name": strings.Repeat("p", 100), "description": strings.Repeat("d", 500), "mode": "off"}}
	tables["security_block_pages"] = []map[string]any{{"id": 9, "name": strings.Repeat("p", 100), "description": strings.Repeat("d", 500), "content": "x"}}
	if err := validateV2BackupSecurityPolicies(tables, true); err != nil {
		t.Fatalf("boundary-valid backup rejected: %v", err)
	}
}

func TestValidateV2BackupSecurityPolicies_checksBuiltinPageProvenance(t *testing.T) {
	for _, tc := range []struct {
		name    string
		page    map[string]any
		wantErr bool
	}{
		{name: "forged custom builtin", page: map[string]any{"id": 7, "name": "forged", "content": "x", "is_builtin": 1}, wantErr: true},
		{name: "wrong name at builtin id", page: map[string]any{"id": 9001, "name": "forged", "content": "x", "is_builtin": 1}, wantErr: true},
		{name: "legitimate rate limit", page: map[string]any{"id": 9001, "name": "限流拦截页面", "content": "x", "is_builtin": 1}},
		{name: "legitimate maintenance", page: map[string]any{"id": 9002, "name": "系统维护页面", "content": "x", "is_builtin": 1}},
		{name: "legacy missing builtin flag", page: map[string]any{"id": 9001, "name": "限流拦截页面", "content": "x", "is_builtin": 0}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tables := emptyBackupSecurityTables()
			tables["security_block_pages"] = []map[string]any{tc.page}
			err := validateV2BackupSecurityPolicies(tables, true)
			if tc.wantErr && (err == nil || !strings.Contains(err.Error(), "is_builtin")) {
				t.Fatalf("err=%v, want forged is_builtin rejection", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("legitimate builtin page rejected: %v", err)
			}
		})
	}
}

func TestValidateBuiltinThreatListRefs_chunksLargeReferenceSets(t *testing.T) {
	h := newBackupTestHandlers(t)
	_ = h
	var builtinID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE system=1 ORDER BY id LIMIT 1`).Scan(&builtinID); err != nil {
		t.Fatal(err)
	}
	refs := make([]int64, 33001)
	for i := range 33000 {
		refs[i] = int64(100000 + i)
	}
	refs[33000] = builtinID
	message, err := validateBuiltinThreatListRefs(db.DB, nil, nil, refs, "deny")
	if err != nil {
		t.Fatalf("large reference set must be chunked instead of exceeding SQLite variables: %v", err)
	}
	if !strings.Contains(message, "不能用于 CRS 排除") {
		t.Fatalf("message=%q, want built-in exclusion rejection after chunked lookup", message)
	}
}
