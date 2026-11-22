package services

// 从端自动热重载验证（用户裁定流程的核心链路）：
// 主节点扫描器把新证书密文写入 cert_secrets → 快照只变 cert_version /
// vault_certs（cluster_version 不变）→ 从端导入后 before<after →
// ReloadFromDB → ApplyConfigForce → POST /load + Cache-Control: must-revalidate，
// 即使渲染出的 JSON 字节完全相同也真实重载，不需要重启容器。
//
// 同时钉住主节点快照缓存键必须包含 cert_version：否则主端缓存恒命中，
// 从端永远收到 304，新证书根本下不来。

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"lazy-balancer-v2/caddydbcert"
	"lazy-balancer-v2/internal/config"
)

func TestRouteAVaultChange_slaveForceReloadsWithIdenticalRenderedJSON(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	enableCertVaultForTest(t, database)

	// 最小可渲染规则集（与既有 applySnapshot 条件重载测试同口径）。
	for _, stmt := range []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source) VALUES ('lb_slave_reload','slave reload','http','slave-reload.example.test',80,1,1,'manual')`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_slave_reload','127.0.0.1',8080,1,1)`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
		`INSERT INTO api_keys (name,key_hash,key_prefix,created_by,is_enabled,last_used) VALUES ('k','kh','kp',1,1,datetime('now'))`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("set master: %v", err)
	}

	cert1, key1 := scanTestCertPair(t, "slave-reload.example.test")
	provider := certKeyProvider("")
	if _, err := caddydbcert.Upsert(ctx, database, provider, "", "slave-reload.example.test", "lb_slave_reload", cert1, key1, false, []string{"lb_slave_reload"}); err != nil {
		t.Fatalf("seed vault cert: %v", err)
	}

	service := NewClusterService(database, "")
	snap1, full1, err := service.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("master snapshot 1: %v", err)
	}
	if !full1 {
		t.Fatal("master snapshot 1 returned 304 on first pull")
	}
	if len(snap1.VaultCerts) != 1 {
		t.Fatalf("snapshot vault certs=%d, want 1", len(snap1.VaultCerts))
	}

	// 模拟主节点扫描器入库：只换证书密文，cluster_version 不变。
	cert2, key2 := scanTestCertPair(t, "slave-reload.example.test")
	if cert2 == cert1 {
		t.Fatal("test cert generator produced identical PEM")
	}
	if _, err := caddydbcert.Upsert(ctx, database, provider, "", "slave-reload.example.test", "lb_slave_reload", cert2, key2, false, []string{"lb_slave_reload"}); err != nil {
		t.Fatalf("scanner-style vault upsert: %v", err)
	}
	// 关键：同 sinceVersion + 旧指纹，缓存若不含 cert_version 会误判 304。
	snap2, full2, err := service.Snapshot(ctx, snap1.Version, snap1.Fingerprint, "")
	if err != nil {
		t.Fatalf("master snapshot 2: %v", err)
	}
	if !full2 {
		t.Fatal("master returned 304 after cert-only vault change（快照缓存键缺 cert_version）")
	}
	if snap2.CertVersion <= snap1.CertVersion {
		t.Fatalf("snapshot cert_version %d→%d did not advance", snap1.CertVersion, snap2.CertVersion)
	}
	if snap2.Version != snap1.Version {
		t.Fatalf("cluster_version changed %d→%d；本用例要钉「仅证书变化」", snap1.Version, snap2.Version)
	}

	// 切到从节点侧，观察两次 /load 的载荷与强制标志。
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave: %v", err)
	}
	var mu sync.Mutex
	var bodies [][]byte
	var forced []bool
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			bodies = append(bodies, body)
			forced = append(forced, r.Header.Get("Cache-Control") == "must-revalidate")
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	if err := syncService.applySnapshot(ctx, snap1); err != nil {
		t.Fatalf("slave apply snapshot 1: %v", err)
	}
	if err := syncService.applySnapshot(ctx, snap2); err != nil {
		t.Fatalf("slave apply snapshot 2: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 {
		t.Fatalf("/load 次数=%d, want 2（证书变化必须触发第二次真实重载）", len(bodies))
	}
	if !bytes.Equal(bodies[0], bodies[1]) {
		t.Fatal("两次渲染 JSON 字节不同——本用例要钉「JSON 不变仍强制重载」的场景")
	}
	if !forced[0] || !forced[1] {
		t.Fatalf("must-revalidate flags=%v, want [true true]（force 击穿同配置短路）", forced)
	}
}

// TestRouteAVaultChange_noReloadWhenCertUnchanged 补反面：证书密文一致时导入
// 不推进本地水位，不应触发额外的强制重载（防「同步通道每轮永久 reload」）。
func TestRouteAVaultChange_noReloadWhenCertUnchanged(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	enableCertVaultForTest(t, database)
	for _, stmt := range []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_no_reload','no reload','http','nr.example.test',80,1)`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_no_reload','127.0.0.1',8080,1,1)`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("set master: %v", err)
	}
	certPEM, keyPEM := scanTestCertPair(t, "nr.example.test")
	if _, err := caddydbcert.Upsert(ctx, database, certKeyProvider(""), "", "nr.example.test", "lb_no_reload", certPEM, keyPEM, false, []string{"lb_no_reload"}); err != nil {
		t.Fatalf("seed vault cert: %v", err)
	}
	service := NewClusterService(database, "")
	snap, _, err := service.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave: %v", err)
	}
	var mu sync.Mutex
	loads := 0
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/load" {
			mu.Lock()
			loads++
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("apply 1: %v", err)
	}
	if err := syncService.applySnapshot(ctx, snap); err != nil {
		t.Fatalf("apply 2: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if loads != 1 {
		t.Fatalf("/load 次数=%d, want 1（证书未变不得二次重载）", loads)
	}
}
