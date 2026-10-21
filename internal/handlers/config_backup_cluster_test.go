package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestConfigBackup_clusterTopologyRoundTripAndSanitization(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := newBackupSectionRouter(h)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,protocol,is_approved,status,health_json,last_seen,cluster_token_hash,registration_secret,registration_secret_expires_at,server_map_lat,server_map_lon)
		VALUES (2,'edge-a','slave','10.0.0.2',8000,'https',1,'online','{"ok":true}',datetime('now'),'token-hash','plain-secret',datetime('now'),31.23,121.47)`); err != nil {
		t.Fatalf("seed node: %v", err)
	}

	// 导出「节点拓扑」：只含 nodes，且不导出明文注册密钥与瞬态状态。
	export := httptest.NewRecorder()
	router.ServeHTTP(export, httptest.NewRequest(http.MethodGet, "/config/export?sections=cluster", nil))
	if export.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", export.Code, export.Body.String())
	}
	var exported struct {
		Tables map[string][]map[string]any `json:"tables"`
		Config map[string]any              `json:"config"`
	}
	if err := json.Unmarshal(unpackExportBody(t, export.Body.Bytes()), &exported); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if len(exported.Config) != 0 {
		t.Fatalf("cluster-only export config=%v, want empty", exported.Config)
	}
	if len(exported.Tables) != 1 {
		t.Fatalf("cluster-only export tables=%v, want only nodes", exported.Tables)
	}
	nodeRows := exported.Tables["nodes"]
	if len(nodeRows) != 1 {
		t.Fatalf("nodes rows=%d, want 1", len(nodeRows))
	}
	for _, key := range []string{"registration_secret", "registration_secret_expires_at", "status", "health_json", "last_seen"} {
		if _, exists := nodeRows[0][key]; exists {
			t.Fatalf("export leaked transient field %s", key)
		}
	}
	if nodeRows[0]["cluster_token_hash"] != "token-hash" {
		t.Fatalf("cluster_token_hash=%v, want token-hash", nodeRows[0]["cluster_token_hash"])
	}

	// 改坏本地节点后从备份恢复：坐标/名称/令牌哈希恢复，状态重置 offline。
	if _, err := db.DB.Exec(`UPDATE nodes SET name='broken',server_map_lat=0,server_map_lon=0,status='online',health_json='{"ok":false}',cluster_token_hash='',registration_secret='new-secret' WHERE id=2`); err != nil {
		t.Fatalf("mutate node: %v", err)
	}
	importReq := httptest.NewRequest(http.MethodPost, "/config/import?sections=cluster", bytes.NewReader(export.Body.Bytes()))
	importRec := httptest.NewRecorder()
	router.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var name, status, health, tokenHash, secret string
	var lat, lon float64
	if err := db.DB.QueryRow(`SELECT name,status,COALESCE(health_json,''),COALESCE(cluster_token_hash,''),COALESCE(registration_secret,''),server_map_lat,server_map_lon FROM nodes WHERE id=2`).
		Scan(&name, &status, &health, &tokenHash, &secret, &lat, &lon); err != nil {
		t.Fatalf("read restored node: %v", err)
	}
	if name != "edge-a" || lat != 31.23 || lon != 121.47 || tokenHash != "token-hash" {
		t.Fatalf("restored node name=%q coords=(%v,%v) token=%q", name, lat, lon, tokenHash)
	}
	if status != "offline" || health != "" || secret != "" {
		t.Fatalf("transient node state not reset: status=%q health=%q secret=%q", status, health, secret)
	}
}

func TestConfigBackup_oldBackupWithoutNodesPreservesLocalTopology(t *testing.T) {
	h := newBackupTestHandlers(t)
	router := newBackupSectionRouter(h)
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved,server_map_lat,server_map_lon) VALUES (2,'edge-a','slave','10.0.0.2',8000,1,31.23,121.47)`); err != nil {
		t.Fatalf("seed node: %v", err)
	}
	export := httptest.NewRecorder()
	router.ServeHTTP(export, httptest.NewRequest(http.MethodGet, "/config/export?sections=users", nil))
	if export.Code != http.StatusOK {
		t.Fatalf("export status=%d", export.Code)
	}
	importReq := httptest.NewRequest(http.MethodPost, "/config/import?sections=users", bytes.NewReader(export.Body.Bytes()))
	importRec := httptest.NewRecorder()
	router.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s", importRec.Code, importRec.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM nodes WHERE id=2 AND name='edge-a'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("local node count=%d err=%v, want preserved", count, err)
	}
}

// ── 历史问题（历史）：nodes 导入行级门的
// access_url / name+ip_address 形态，以及「存活身份键与落库 port 默认同源」。 ──

func a3SeedLiveAdmin(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed live admin: %v", err)
	}
}

func a3ImportClusterRows(t *testing.T, h *Handlers, rows []map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	a3SeedLiveAdmin(t)
	body := buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{"nodes": rows}, Config: nil, Sections: []string{"cluster"}, EmptyConfigIfNil: true})
	return r78Import(h, t, body)
}

func Test87_P2_01_nodesImportValidatesAccessURL(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"name": "edge-a", "ip_address": "10.0.0.2", "port": 8000, "protocol": "https"}
	}
	rejected := []struct {
		name      string
		accessURL any
	}{
		{"带查询参数", "https://attacker.example/collect?token=1"},
		{"带用户信息", "http://user:pass@10.0.0.2:8000"},
		{"非 http(s) scheme", "ftp://10.0.0.2"},
		{"带片段", "https://10.0.0.2:8000/#frag"},
		{"非字符串类型", 42},
	}
	for _, tc := range rejected {
		t.Run("拒绝/"+tc.name, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			row := base()
			row["access_url"] = tc.accessURL
			rec := a3ImportClusterRows(t, h, []map[string]any{row})
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), "access_url") {
				t.Fatalf("body=%s, want access_url 点名拒绝", rec.Body.String())
			}
		})
	}

	accepted := []string{"", "https://10.0.0.2:8000", "http://[::1]:8000"}
	for _, value := range accepted {
		t.Run("接受/"+value, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			row := base()
			row["access_url"] = value
			rec := a3ImportClusterRows(t, h, []map[string]any{row})
			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
			}
			var stored string
			if err := db.DB.QueryRow(`SELECT COALESCE(access_url,'') FROM nodes WHERE name='edge-a'`).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored != value {
				t.Fatalf("access_url=%q, want %q", stored, value)
			}
		})
	}
}

func Test87_P3_01_nodeRowsNormalizeNameAndValidateAddress(t *testing.T) {
	t.Run("名称", func(t *testing.T) {
		cases := []struct {
			name    string
			value   any
			wantErr string
		}{
			{"合法", "edge-a", ""},
			{"首尾空白归一去空白", "  edge-a  ", ""},
			{"恰好 100 字符", strings.Repeat("n", 100), ""},
			{"101 字符超长", strings.Repeat("n", 101), "name"},
			{"含换行控制字符", "edge\r\n-a", "name"},
			{"非字符串", 42, "name"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rows := []map[string]any{{"name": tc.value, "ip_address": "10.0.0.2", "port": 8000}}
				err := validateV2BackupNodeRows(rows)
				if tc.wantErr == "" {
					if err != nil {
						t.Fatalf("err=%v, want nil", err)
					}
					if got := rows[0]["name"]; got != strings.TrimSpace(tc.value.(string)) {
						t.Fatalf("name=%v, want %q（落库前归一）", got, strings.TrimSpace(tc.value.(string)))
					}
					return
				}
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err=%v, want containing %q", err, tc.wantErr)
				}
			})
		}
	})

	t.Run("地址", func(t *testing.T) {
		cases := []struct {
			name    string
			value   any
			wantErr bool
		}{
			{"IPv4", "10.0.0.2", false},
			{"IPv6", "::1", false},
			{"主机+端口形态", "10.0.0.2:8000", true},
			{"路径形态", "10.0.0.2/admin", true},
			{"主机名/非 IP", "not-an-ip", true},
			{"带首尾空白", " 10.0.0.2 ", true},
			{"URL 形态", "https://10.0.0.2", true},
			{"非字符串", 10, true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				rows := []map[string]any{{"name": "edge-a", "ip_address": tc.value, "port": 8000}}
				err := validateV2BackupNodeRows(rows)
				if tc.wantErr {
					if err == nil || !strings.Contains(err.Error(), "ip_address") {
						t.Fatalf("err=%v, want ip_address 点名拒绝", err)
					}
					return
				}
				if err != nil {
					t.Fatalf("err=%v, want nil", err)
				}
			})
		}
	})
}

func Test87_P3_03_nodeSurvivingIdentitiesUseStoreDefaultPort(t *testing.T) {
	rows := []map[string]any{
		{"name": "缺 port", "ip_address": "10.0.0.2"},
		{"name": "port null", "ip_address": "10.0.0.3", "port": nil},
		{"name": "port 8000", "ip_address": "10.0.0.4", "port": 8000},
		{"name": "port 字符串", "ip_address": "10.0.0.5", "port": "8000"},
		{"name": "port 非默认", "ip_address": "10.0.0.6", "port": 9000},
	}
	surviving := nodeSurvivingIdentities(rows)
	for _, want := range []string{"10.0.0.2:8000", "10.0.0.3:8000", "10.0.0.4:8000", "10.0.0.5:8000", "10.0.0.6:9000"} {
		if !surviving[want] {
			t.Fatalf("surviving 缺 %s（身份键须与 restoreTable 的 port 默认 8000 同源）: %v", want, surviving)
		}
	}
	if len(surviving) != 5 {
		t.Fatalf("surviving=%v, want 5 条身份键", surviving)
	}
}
