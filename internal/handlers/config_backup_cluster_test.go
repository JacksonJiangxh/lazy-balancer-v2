package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
