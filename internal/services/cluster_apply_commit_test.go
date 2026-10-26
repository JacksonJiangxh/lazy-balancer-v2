package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestSyncServicePull_commitErrorPreservesArtifactsAndReplays(t *testing.T) {
	tests := []struct {
		name                  string
		committed             bool
		wantAppliedAfterError int
		wantRequestVersions   []string
	}{
		{name: "commit succeeded but acknowledgement failed", committed: true, wantAppliedAfterError: 9, wantRequestVersions: []string{"4", "9", "0"}},
		{name: "commit did not happen", committed: false, wantAppliedAfterError: 4, wantRequestVersions: []string{"4", "4"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given：本地旧证书/旧 DNS ownership，以及一张携带新材料的有效签名快照。
			_, database := newClusterTestService(t)
			dataDir := t.TempDir()
			t.Cleanup(SetCertDirForTest(t.TempDir()))
			oldCert, oldKey := matchingCertificatePair(t, "commit.example.test")
			newCert, newKey := matchingCertificatePair(t, "commit.example.test")
			if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enable_tls,tls_source,tls_cert,tls_key,enabled)
			VALUES ('lb_commit','commit','http','commit.example.test',443,1,'manual',?,?,1);
			INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_commit','127.0.0.1',8080,1)`, oldCert, oldKey); err != nil {
				t.Fatalf("seed previous rule: %v", err)
			}
			if err := WriteCertFiles("lb_commit", oldCert, oldKey); err != nil {
				t.Fatalf("seed previous certificate: %v", err)
			}
			oldOwnership := `{"version":1,"records":[]}`
			newOwnership := `{"version":1,"records":[{"provider":"dnspod","zone":"example.test","fqdn":"_acme-challenge.example.test","value":"new-token","record_id":"new-record"}]}`
			ownershipPath := filepath.Join(dataDir, "acme_dns_ownership.json")
			if err := os.WriteFile(ownershipPath, []byte(oldOwnership), 0600); err != nil {
				t.Fatalf("seed previous ownership: %v", err)
			}
			snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
				Version:          9,
				MinReaderVersion: CurrentSnapshotSchema,
				Rules: []models.LbRule{{
					CaddyID: "lb_commit", Name: "commit", Protocol: "http", Domain: "commit.example.test", ListenPort: 443,
					EnableTLS: true, TLSSource: "manual", TLSCert: newCert, TLSKey: newKey, Enabled: true,
					Upstreams: []models.Upstream{{Host: "127.0.0.1", Port: 8080, Enabled: true}},
				}},
				Certs: []models.ClusterCertificate{{RuleID: "lb_commit", CertPEM: newCert, KeyPEM: newKey}},
			})
			snapshot.ACME.DNSOwnership = json.RawMessage(newOwnership)
			snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
			snapshot = signTestSnapshot(snapshot, "token")

			requestedVersions := make(chan string, 4)
			var requestCount atomic.Int32
			master := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				sinceVersion := request.URL.Query().Get("since_version")
				requestedVersions <- sinceVersion
				if requestCount.Add(1) == 1 || sinceVersion == "0" || !test.committed {
					response.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(response).Encode(models.APIResponse{Code: 0, Data: snapshot})
					return
				}
				response.WriteHeader(http.StatusNotModified)
			}))
			defer master.Close()
			if _, err := database.Exec("UPDATE global_config SET is_master=0, master_url=?, cluster_token='token', applied_version=4 WHERE id=1", master.URL); err != nil {
				t.Fatalf("seed slave sync state: %v", err)
			}
			caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
				response.WriteHeader(http.StatusOK)
			}))
			defer caddyServer.Close()
			service := NewSyncService(database, &config.Config{DataDir: dataDir, CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
			service.commitSnapshotTx = func(tx *sql.Tx) error {
				if test.committed {
					if err := tx.Commit(); err != nil {
						return err
					}
				}
				return errors.New("injected commit acknowledgement loss")
			}

			// When：Commit 返回错误；真实结果分别是已提交与未提交。
			_, firstErr := service.Pull(context.Background())

			// Then：两种形态都保留本轮文件、留下不确定态补偿标记，不虚报应用成功。
			if firstErr == nil || !strings.Contains(firstErr.Error(), "提交结果不确定") {
				t.Fatalf("first pull error=%v, want explicit uncertain commit result", firstErr)
			}
			assertSnapshotCommitArtifacts(t, database, ownershipPath, test.wantAppliedAfterError, oldCert, oldKey, newCert, newKey)
			storedMessage, _ := decodeSyncError(readLastSyncError(t, database))
			if !strings.HasPrefix(storedMessage, syncCommitUncertainMarkerPrefix) || !strings.Contains(storedMessage, "提交结果不确定") {
				t.Fatalf("last_sync_error message=%q, want uncertain-commit compensation marker", storedMessage)
			}

			// When：恢复正常 Commit 后再次同步。
			service.commitSnapshotTx = nil
			result, secondErr := service.Pull(context.Background())

			// Then：已提交形态由 304 标记强制全量重拉；未提交形态按旧版本直接重放，最终同源。
			if secondErr != nil {
				t.Fatalf("second pull: %v", secondErr)
			}
			if !result.Changed || result.AppliedVersion != 9 {
				t.Fatalf("second result=%+v, want full version 9 replay", result)
			}
			for _, want := range test.wantRequestVersions {
				if got := waitSyncTest(t, requestedVersions); got != want {
					t.Fatalf("since_version=%q, want %q", got, want)
				}
			}
			assertSnapshotCommitArtifacts(t, database, ownershipPath, 9, oldCert, oldKey, newCert, newKey)
			if stored := readLastSyncError(t, database); stored != "" {
				t.Fatalf("last_sync_error=%q, want cleared after successful replay", stored)
			}
		})
	}
}

func TestSyncServiceApplySnapshot_commitUncertaintyMarkerForcesReload(t *testing.T) {
	// Given： canonical 夹具已连续两次应用同一快照，第二次证明所有常规重载因子均不变。
	fixture := newReloadFactorFixture(t)
	fixture.apply(nil)
	fixture.apply(nil)
	if got := fixture.loadCount(); got != 1 {
		t.Fatalf("unchanged baseline /load count=%d, want 1", got)
	}
	if _, err := fixture.service.db.Exec("UPDATE global_config SET last_sync_error=? WHERE id=1",
		encodeSyncError(syncCommitUncertainMarkerPrefix+": 提交结果不确定", models.SyncErrorCodeApplyFailed)); err != nil {
		t.Fatalf("seed commit uncertainty marker: %v", err)
	}

	// When：仅提交不确定标记变化，其他节哈希、证书轴、WAF 文件与品牌均不变。
	fixture.apply(nil)

	// Then：标记自身必须强制一次重载，并在成功应用后清除。
	if got := fixture.loadCount(); got != 2 {
		t.Fatalf("compensation /load count=%d, want 2", got)
	}
	if stored := readLastSyncError(t, fixture.service.db); stored != "" {
		t.Fatalf("last_sync_error=%q, want cleared after successful compensation", stored)
	}
}

func assertSnapshotCommitArtifacts(t *testing.T, database *sql.DB, ownershipPath string, wantAppliedVersion int, oldCert, oldKey, newCert, newKey string) {
	t.Helper()
	certPath, keyPath := CertFilePaths("lb_commit")
	for _, file := range []struct {
		path string
		want string
	}{{certPath, newCert}, {keyPath, newKey}} {
		content, err := os.ReadFile(file.path)
		if err != nil || string(content) != file.want {
			t.Fatalf("artifact %s=(%q,%v), want %q", file.path, content, err, file.want)
		}
	}
	ownership, err := os.ReadFile(ownershipPath)
	if err != nil || !strings.Contains(string(ownership), "new-token") {
		t.Fatalf("DNS ownership=(%q,%v), want new snapshot material", ownership, err)
	}
	var appliedVersion int
	var certPEM, keyPEM string
	if err := database.QueryRow(`SELECT
		(SELECT COALESCE(applied_version,0) FROM global_config WHERE id=1),
		(SELECT tls_cert FROM lb_rules WHERE caddy_id='lb_commit'),
		(SELECT tls_key FROM lb_rules WHERE caddy_id='lb_commit')`).Scan(&appliedVersion, &certPEM, &keyPEM); err != nil {
		t.Fatalf("read committed database state: %v", err)
	}
	if appliedVersion != wantAppliedVersion {
		t.Fatalf("applied_version=%d, want %d", appliedVersion, wantAppliedVersion)
	}
	wantCert, wantKey := oldCert, oldKey
	if wantAppliedVersion == 9 {
		wantCert, wantKey = newCert, newKey
	}
	if certPEM != wantCert || keyPEM != wantKey {
		t.Fatalf("database certificate=(%q,%q), want (%q,%q)", certPEM, keyPEM, wantCert, wantKey)
	}
}
