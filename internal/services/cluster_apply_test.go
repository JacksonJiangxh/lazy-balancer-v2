package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
	"lazy-balancer-v2/internal/models"
)

func TestSyncService_applySnapshot_keeps_valid_certificate_while_master_job_is_queued(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	certPEM, keyPEM := matchingCertificatePair(t, "example.com")
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,enabled) VALUES (7,'queued cert CA','letsencrypt','https://acme-v02.api.letsencrypt.org/directory','{}',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (11,'queued cert DNS','dnspod','{}',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled)
		VALUES ('lb_queued_cert','queued cert','http','Example.COM',443,1,'acme_dns',11,7,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_queued_cert','127.0.0.1',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_queued_cert','example.com','queued',datetime('now','+30 days'),?,?,7,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_queued_cert','WWW.Example.com,example.com','issued',datetime('now','-1 day'),'expired-cert','expired-key',8,datetime('now','+2 minutes')),
		('lb_queued_cert','www.example.com,example.com','disabled',datetime('now','+90 days'),'retired-cert','retired-key',9,datetime('now','+1 minute'))`); err != nil {
		t.Fatal(err)
	}
	incoming, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE cert_jobs SET status='issued' WHERE rule_id='lb_queued_cert'"); err != nil {
		t.Fatal(err)
	}
	clusterSnapshotCaches.Delete(database)
	if err := WriteCertFiles("lb_queued_cert", certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	err = syncService.applySnapshot(context.Background(), incoming)

	// Then
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := CertFilePaths("lb_queued_cert")
	if _, err := os.Stat(certPath); err != nil {
		t.Fatalf("synced certificate was removed: %v", err)
	}
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("synced private key was removed: %v", err)
	}
	var status string
	var providerID int
	if err := database.QueryRow("SELECT status,ca_provider_id FROM cert_jobs WHERE rule_id='lb_queued_cert'").Scan(&status, &providerID); err != nil {
		t.Fatal(err)
	}
	if status != "issued" || providerID != 7 {
		t.Fatalf("synced job status=%q provider=%d", status, providerID)
	}
}

func TestClusterSnapshot_roundTrip_preservesACMEState_for_promoted_slave(t *testing.T) {
	// Given
	cluster, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	var sequence int
	var databaseName, databasePath string
	if err := database.QueryRow("PRAGMA database_list").Scan(&sequence, &databaseName, &databasePath); err != nil {
		t.Fatal(err)
	}
	dataDir := filepath.Dir(databasePath)
	ownership := `{"version":1,"records":[{"provider":"dnspod","zone":"example.com","fqdn":"_acme-challenge.example.com","value":"token","record_id":"record-1"}]}`
	if err := os.WriteFile(filepath.Join(dataDir, "acme_dns_ownership.json"), []byte(ownership), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled)
		VALUES (7,'ZeroSSL promotion','zerossl','https://acme.zerossl.com/v2/DV90','{"eab_kid":"kid","eab_hmac_key":"secret"}',3,750,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled)
		VALUES (11,'DNSPod promotion','dnspod','{"secret_id":"dns-id","secret_key":"dns-secret"}',1)`); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := matchingCertificatePair(t, "promotion.example.com")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled)
		VALUES ('lb_promote_acme','promotion','http','promotion.example.com',443,1,'acme_dns',11,7,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_promote_acme','127.0.0.1',8080,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_promote_acme','promotion.example.com','waiting_ca',datetime('now','+60 days'),?,?,7,datetime('now'))`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "cluster-token")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.ACME == nil {
		t.Fatal("snapshot omitted ACME state")
	}
	if _, err := database.Exec("DELETE FROM cert_jobs; DELETE FROM lb_rules; DELETE FROM certificate_configs; DELETE FROM ca_providers"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (99,'stale','letsencrypt','https://acme-v02.api.letsencrypt.org/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled) VALUES (99,'stale','dnspod','{}',1)`); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "acme_dns_ownership.json"), []byte(`{"version":1,"records":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec("UPDATE global_config SET is_master=0"); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	lifecycle := &clusterLifecycleFake{}
	promotable := NewClusterService(database, "")
	wireClusterLifecycleEngineForTest(t, lifecycle, false)

	// When
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	if err := promotable.Promote(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Then
	var providerCredentials, dnsCredentials, jobStatus string
	var jobProviderID int
	if err := database.QueryRow(`SELECT p.credentials,c.dns_credentials,j.status,j.ca_provider_id
		FROM ca_providers p CROSS JOIN certificate_configs c JOIN cert_jobs j ON j.rule_id='lb_promote_acme'
		WHERE p.id=7 AND c.id=11`).Scan(&providerCredentials, &dnsCredentials, &jobStatus, &jobProviderID); err != nil {
		t.Fatal(err)
	}
	if providerCredentials != `{"eab_kid":"kid","eab_hmac_key":"secret"}` || dnsCredentials != `{"secret_id":"dns-id","secret_key":"dns-secret"}` {
		t.Fatalf("restored credentials provider=%q dns=%q", providerCredentials, dnsCredentials)
	}
	waitForCond(t, 2*time.Second, func() bool { return lifecycle.acmeStarted.Load() })
	if jobStatus != "issued" || jobProviderID != 7 {
		t.Fatalf("promoted job status=%q provider=%d", jobStatus, jobProviderID)
	}
	var staleProviders, staleConfigs int
	if err := database.QueryRow(`SELECT (SELECT COUNT(*) FROM ca_providers WHERE id=99),(SELECT COUNT(*) FROM certificate_configs WHERE id=99)`).Scan(&staleProviders, &staleConfigs); err != nil {
		t.Fatal(err)
	}
	if staleProviders != 0 || staleConfigs != 0 {
		t.Fatalf("stale ACME rows remain providers=%d configs=%d", staleProviders, staleConfigs)
	}
	restoredOwnership, err := os.ReadFile(filepath.Join(dataDir, "acme_dns_ownership.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restoredOwnership) != ownership {
		t.Fatalf("restored DNS ownership=%s", restoredOwnership)
	}
}

func TestSyncService_materializeSnapshotDNSOwnership_usesSharedOwnershipLock(t *testing.T) {
	// Given：一份较大快照，以及 ownership 包锁被另一个真实 writer 持有。
	dataDir := t.TempDir()
	service := &SyncService{cfg: &config.Config{DataDir: dataDir}}
	records := make([]ownership.Record, 64)
	for i := range records {
		records[i] = ownership.Record{
			Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.",
			Value: fmt.Sprintf("value-%d", i), RecordID: fmt.Sprintf("snapshot-%d", i),
		}
	}
	snapshot, err := json.Marshal(map[string]any{"version": 1, "records": records})
	if err != nil {
		t.Fatalf("encode ownership snapshot: %v", err)
	}
	acme := &models.ClusterACMEState{DNSOwnership: snapshot}
	release := ownership.AcquireFileLockForTest()
	locked := true
	t.Cleanup(func() {
		if locked {
			release()
		}
	})
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		done <- service.materializeSnapshotDNSOwnership(acme)
	}()
	<-started

	// When/Then：共享锁下必须等待；旧独立 temp+rename 会在此窗口内完成。
	select {
	case err := <-done:
		release()
		locked = false
		t.Fatalf("snapshot write 绕过ed ownership fileMu: err=%v", err)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	locked = false
	if err := <-done; err != nil {
		t.Fatalf("snapshot write after lock release: %v", err)
	}
	path := filepath.Join(dataDir, "acme_dns_ownership.json")
	if got, err := os.ReadFile(path); err != nil || string(got) != string(snapshot) {
		t.Fatalf("snapshot bytes=(%q,%v), want exact replacement", got, err)
	}

	// Then：锁释放后与 Store.Add 真实并发仍全部成功，文件保持可解码。
	store, err := ownership.New(dataDir)
	if err != nil {
		t.Fatalf("open ownership store: %v", err)
	}
	for round := range 10 {
		var wg sync.WaitGroup
		errs := make(chan error, 2)
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- service.materializeSnapshotDNSOwnership(acme)
		}()
		go func(round int) {
			defer wg.Done()
			errs <- store.Add(ownership.Record{
				Provider: "dnspod", Zone: "example.com", FQDN: "_acme-challenge.example.com.",
				Value: fmt.Sprintf("burst-%d", round), RecordID: fmt.Sprintf("burst-%d", round), CreatedAt: time.Now(),
			})
		}(round)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("round %d concurrent ownership operation: %v", round, err)
			}
		}
	}
	if _, err := store.Matching("dnspod", "example.com", "_acme-challenge.example.com."); err != nil {
		t.Fatalf("concurrent ownership file is unreadable: %v", err)
	}
}

func TestSyncService_applySnapshot_rollsBackWhenDNSOwnershipWriteFails(t *testing.T) {
	// Given：从端应用快照，但 ownership 目标路径被目录占据，原子替换必败。
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0, applied_version=0 WHERE id=1"); err != nil {
		t.Fatalf("seed slave role: %v", err)
	}
	dataDir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dataDir, "acme_dns_ownership.json"), 0700); err != nil {
		t.Fatalf("block ownership target: %v", err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 10})
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)

	// When
	err := service.applySnapshot(context.Background(), snapshot)

	// Then：错误不得被吞，快照事务整体回滚（applied_version 不前进）。
	if err == nil || !strings.Contains(err.Error(), "DNS 所有权") {
		t.Fatalf("apply error=%v, want DNS ownership failure", err)
	}
	var appliedVersion int
	if err := database.QueryRow("SELECT COALESCE(applied_version,0) FROM global_config WHERE id=1").Scan(&appliedVersion); err != nil {
		t.Fatalf("read applied version: %v", err)
	}
	if appliedVersion != 0 {
		t.Fatalf("applied_version=%d, want rollback to 0", appliedVersion)
	}
}

func TestSyncService_materializeSnapshotDNSOwnership_preservesFailureSemantics(t *testing.T) {
	dataDir := t.TempDir()
	service := &SyncService{cfg: &config.Config{DataDir: dataDir}}
	path := filepath.Join(dataDir, "acme_dns_ownership.json")

	t.Run("invalid snapshot leaves committed bytes", func(t *testing.T) {
		old := []byte(`{"version":1,"records":[]}`)
		if err := os.WriteFile(path, old, 0600); err != nil {
			t.Fatalf("seed committed ownership: %v", err)
		}
		err := service.materializeSnapshotDNSOwnership(&models.ClusterACMEState{
			DNSOwnership: []byte(`{"version":1,"records":[{"provider":"dnspod"}]}`),
		})
		if err == nil {
			t.Fatal("invalid ownership snapshot was accepted")
		}
		if got, readErr := os.ReadFile(path); readErr != nil || !bytes.Equal(got, old) {
			t.Fatalf("invalid snapshot changed committed bytes: got=%q err=%v", got, readErr)
		}
	})

	t.Run("atomic replace failure propagates and keeps target", func(t *testing.T) {
		blockedPath := filepath.Join(t.TempDir(), "acme_dns_ownership.json")
		if err := os.Mkdir(blockedPath, 0700); err != nil {
			t.Fatalf("block ownership target: %v", err)
		}
		blockedService := &SyncService{cfg: &config.Config{DataDir: filepath.Dir(blockedPath)}}
		err := blockedService.materializeSnapshotDNSOwnership(&models.ClusterACMEState{
			DNSOwnership: []byte(`{"version":1,"records":[]}`),
		})
		if err == nil {
			t.Fatal("ownership replace failure was swallowed")
		}
		info, statErr := os.Stat(blockedPath)
		if statErr != nil || !info.IsDir() {
			t.Fatalf("blocked target changed: info=%v err=%v", info, statErr)
		}
		if _, tmpErr := os.Stat(blockedPath + ".tmp"); !os.IsNotExist(tmpErr) {
			t.Fatalf("failed replace left temporary file: %v", tmpErr)
		}
	})
}

func TestSyncService_applySnapshot_restarts_for_uploaded_admin_certificate_rotation(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, admin_tls_enabled=1, admin_tls_mode='upload', admin_tls_cert='old-cert', admin_tls_key='old-key' WHERE id=1`); err != nil {
		t.Fatalf("seed slave admin TLS: %v", err)
	}
	RecordRuntimeAdminTLS(AdminTLSConfig{Enabled: true, Mode: "upload", Cert: "old-cert", Key: "old-key"})
	t.Cleanup(func() { runtimeAdminTLS.Store(nil) })
	restarted := make(chan struct{}, 1)
	SetRestartRequiredHandler(func() { restarted <- struct{}{} })
	t.Cleanup(func() { SetRestartRequiredHandler(nil) })
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	service := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 2, BasicSettings: models.ClusterBasicSettings{
		LogLevel: new("info"), Timezone: new("Asia/Shanghai"), AdminTLSEnabled: new(true), AdminTLSMode: new("upload"), AdminTLSCert: new("new-cert"), AdminTLSKey: new("new-key"),
	}})

	if err := service.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	select {
	case <-restarted:
	case <-time.After(time.Second):
		t.Fatal("restart callback was not invoked for certificate rotation")
	}
}

func TestSyncService_applySnapshot_replays_cert_jobs_when_rules_section_skipped(t *testing.T) {
	// Given：从节点已应用过 rules 节（哈希一致将被跳过），但主节点另发来一张
	// 证书。cert_jobs 有唯一索引 (rule_id,domain)，若 rules 节跳过时不清理
	// cert_jobs，证书 INSERT 重放会撞唯一索引，导致同步永久失败。
	_, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,acme_config_id,ca_provider_id,enabled)
		VALUES ('lb_b1','b1','http','example.com',443,1,'acme_dns',11,7,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,cert_pem,key_pem,ca_provider_id,updated_at)
		VALUES ('lb_b1','example.com','issued',datetime('now','+30 days'),'old-cert','old-key',7,datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	newCertPEM, newKeyPEM := matchingCertificatePair(t, "example.com")
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version: 3,
		Rules: []models.LbRule{{
			CaddyID: "lb_b1", Name: "b1", Protocol: "http", Domain: "example.com",
			ListenPort: 443, EnableTLS: true, TLSSource: "acme_dns",
			ACMEConfigID: 11, CAProviderID: 7, Enabled: true,
		}},
		Certs: []models.ClusterCertificate{{
			RuleID: "lb_b1", Domain: "example.com",
			CertPEM: newCertPEM, KeyPEM: newKeyPEM, CAProviderID: 7,
		}},
	})
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version) VALUES ('rules', ?, ?)`,
		snapshot.SectionHashes["rules"], snapshot.Version); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	err := syncService.applySnapshot(context.Background(), snapshot)

	// Then
	if err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}
	var certPEM string
	if err := database.QueryRow(`SELECT cert_pem FROM cert_jobs WHERE rule_id='lb_b1' AND domain='example.com'`).Scan(&certPEM); err != nil {
		t.Fatal(err)
	}
	if certPEM != newCertPEM {
		t.Fatalf("cert_jobs 未被主节点证书替换: got %q", certPEM)
	}
}

func TestClearSyncTables_propagatesDeleteError(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	tx, err := database.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()

	// When
	err = clearSyncTables(context.Background(), tx, "nonexistent_table")

	// Then
	if err == nil {
		t.Fatal("expected delete error for nonexistent table")
	}
	if !strings.Contains(err.Error(), "清理同步表 nonexistent_table 失败") {
		t.Fatalf("error=%v, want table context", err)
	}
}

func TestSyncService_applySnapshot_warnsOnInvalidCustomRuleTarget(t *testing.T) {
	// Given：主节点下发一条内嵌非法 target 的自定义规则（同步路径不校验 target/operator）
	_, database := newClusterTestService(t)
	snapshot := models.ClusterSnapshot{
		Version: 11,
		SecurityCustomRules: []models.SecurityCustomRule{{
			ID: 3, Name: "bad-target", Action: "block", Score: 5, Enabled: true,
			Conditions: []models.CustomRuleCondition{{Target: "cookie", Operator: "contains", Pattern: "x"}},
		}},
	}
	var logs bytes.Buffer
	previousWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previousWriter) })

	// When：应用快照
	err := replaceSnapshotDB(context.Background(), database, snapshot)

	// Then：同步成功（告警-only，不阻断忠实复制），规则仍被复制，且告警覆盖非法 target
	if err != nil {
		t.Fatalf("apply snapshot with invalid-target rule: %v", err)
	}
	var count int
	if err := database.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE id=3").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("custom rule not faithfully replicated: count=%d, want 1", count)
	}
	if !strings.Contains(logs.String(), "非法 target/operator 或名字含控制字符") {
		t.Fatalf("sync warning must cover invalid target/operator, got %q", logs.String())
	}
}

func TestSyncService_applySnapshot_heals_local_rules_drift(t *testing.T) {
	// Given：从节点记录的 rules 哈希与主节点快照一致（将被哈希跳过），但本地
	// lb_rules 为空 —— 数据在同步之外丢失。哈希跳过必须让位于强制重放。
	_, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version: 7,
		Rules: []models.LbRule{{
			CaddyID: "lb_d1", Name: "d1", Protocol: "http", Domain: "drift.example.com",
			ListenPort: 80, Enabled: true,
		}},
	})
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section, hash, applied_version) VALUES ('rules', ?, ?)`,
		snapshot.SectionHashes["rules"], snapshot.Version); err != nil {
		t.Fatal(err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// When
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	// Then：规则被强制重放，本地数据自愈
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_d1'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rules drift 未自愈: lb_rules 行数=%d, want 1", count)
	}
}

// 审计 历史问题：快照 dump 的 INTEGER 列 JSON 化为 float64（0/1）——断言 helper
// 必须接受数字形态，否则主端 ip_whitelist_enabled=0 在从端被误存为启用。
func TestPolicyWhitelistEnabled_acceptsNumericJSON(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]interface{}
		want bool
	}{
		{"numeric zero", map[string]interface{}{"ip_whitelist_enabled": float64(0)}, false},
		{"numeric one", map[string]interface{}{"ip_whitelist_enabled": float64(1)}, true},
		{"bool false", map[string]interface{}{"ip_whitelist_enabled": false}, false},
		{"bool true", map[string]interface{}{"ip_whitelist_enabled": true}, true},
		{"missing defaults enabled", map[string]interface{}{}, true},
	}
	for _, c := range cases {
		if got := policyWhitelistEnabled(c.in); got != c.want {
			t.Fatalf("%s: policyWhitelistEnabled=%v, want %v", c.name, got, c.want)
		}
	}
}

// OIDC 集成数据必须随集群同步(2026-09-18 用户实测:从节点 OIDC 用户变本地
// 账号、OIDC 未启用)。钉两个不变量:①users 节携带 auth_provider/oidc_
// subject/oidc_issuer 且 apply 落库;②global 节携带 oidc_config 且 apply 落库。
func TestSyncService_applySnapshot_preservesOIDCIdentityAndConfig(t *testing.T) {
	cluster, database := newClusterTestService(t)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	// Given: 主节点有 1 个 OIDC 用户 + oidc_config 已启用
	if _, err := database.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled,auth_provider,oidc_subject,oidc_issuer) VALUES (7,'sso-user','','user',1,'oidc','sub-1','https://idp.example.com')`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET oidc_config='{"enabled":true,"issuer":"https://idp.example.com","client_id":"c","client_secret":"s"}' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := cluster.Snapshot(context.Background(), 0, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var gotUser models.ClusterUser
	for _, u := range snapshot.Users {
		if u.Username == "sso-user" {
			gotUser = u
		}
	}
	if gotUser.AuthProvider != "oidc" || gotUser.OIDCSubject != "sub-1" || gotUser.OIDCIssuer != "https://idp.example.com" {
		t.Fatalf("snapshot user OIDC identity lost: %+v", gotUser)
	}
	if snapshot.BasicSettings.OIDCConfig == nil || !strings.Contains(*snapshot.BasicSettings.OIDCConfig, "idp.example.com") {
		t.Fatalf("snapshot global oidc_config lost: %v", snapshot.BasicSettings.OIDCConfig)
	}
	// When: 应用到干净从库
	err = syncService.applySnapshot(context.Background(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Then: OIDC 身份与配置在从库保留
	var provider, subject, cfg string
	if err := database.QueryRow(`SELECT COALESCE(auth_provider,''), COALESCE(oidc_subject,''), COALESCE((SELECT oidc_config FROM global_config WHERE id=1),'') FROM users WHERE username='sso-user'`).Scan(&provider, &subject, &cfg); err != nil {
		t.Fatalf("query applied user: %v", err)
	}
	if provider != "oidc" || subject != "sub-1" {
		t.Fatalf("applied user lost OIDC identity: provider=%q subject=%q", provider, subject)
	}
	if !strings.Contains(cfg, "idp.example.com") {
		t.Fatalf("applied global oidc_config lost: %q", cfg)
	}
}

// 历史问题-11：nil 版本行规范化为空切片，空表不再恒判「有差异」。
func TestSnapshotSecurityVersionRowsDiffer_normalizesNilRows(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	// 种子库可能带默认版本行：先清空，夹具才是「本地空表」形态。
	if _, err := database.Exec("DELETE FROM security_crs_version; DELETE FROM security_ip2region_version"); err != nil {
		t.Fatal(err)
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if snapshotSecurityVersionRowsDiffer(ctx, tx, models.ClusterSnapshot{}) {
		t.Fatal("nil snapshot version rows vs empty local tables must be equal")
	}
	if snapshotSecurityVersionRowsDiffer(ctx, tx, models.ClusterSnapshot{SecurityCRSVersion: []models.ClusterSecurityCRSVersion{{ID: 1, Version: "v1", AutoUpdate: true, UpdateStatus: "idle", ScheduleDays: "1,2,3,4,5,6,7", ScheduleTime: "04:00"}}}) != true {
		t.Fatal("non-empty snapshot version rows vs empty local tables must differ")
	}
}

// 历史问题-15：版本行读取列清单单源——排程列变化可被差分行观测（列清单分叉的
// 历史教训：差分行漏列 → 变化永判无差异）。
func TestClusterRuleLibVersionRows_diffSeesScheduleColumns(t *testing.T) {
	service, database := newClusterTestService(t)
	ctx := context.Background()
	if _, err := database.Exec(`INSERT OR REPLACE INTO security_crs_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at,schedule_days,schedule_time) VALUES (1,'v1','2026-10-19 12:00:00',1,'idle','','','','','','','1,2,3','05:00')`); err != nil {
		t.Fatalf("seed CRS version row: %v", err)
	}
	if _, err := database.Exec(`INSERT OR REPLACE INTO security_ip2region_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at,schedule_days,schedule_time) VALUES (1,'v1','2026-10-19 12:00:00',1,'idle','','','','','','','1,2,3','05:00')`); err != nil {
		t.Fatalf("seed IP2Region version row: %v", err)
	}
	var snapshot models.ClusterSnapshot
	var err error
	if snapshot.SecurityCRSVersion, err = service.snapshotSecurityCRSVersion(ctx, database); err != nil {
		t.Fatal(err)
	}
	if snapshot.SecurityIP2RegionVersion, err = service.snapshotSecurityIP2RegionVersion(ctx, database); err != nil {
		t.Fatal(err)
	}

	// 每次差分用独立事务：同一事务内的第二次读会沿用首个读快照（WAL 快照
	// 隔离），看不到下方外部 UPDATE。
	differ := func(t *testing.T) bool {
		t.Helper()
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		return snapshotSecurityVersionRowsDiffer(ctx, tx, snapshot)
	}
	if differ(t) {
		t.Fatal("identical version rows must compare equal")
	}

	if _, err := database.Exec(`UPDATE security_crs_version SET schedule_days='6,7' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if !differ(t) {
		t.Fatal("schedule_days change must be visible to the differ (shared column list)")
	}
}
