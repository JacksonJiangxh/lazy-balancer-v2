package services

// JJC-20261122-001 引用型证书（tls_source="file"）随集群快照同步测试。

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// seedReferencedCertRule 落盘被引用的文件对并返回路径。
func seedReferencedCertRule(t *testing.T, certPEM, keyPEM string) (certPath, keyPath string) {
	t.Helper()
	certPath = filepath.Join(CertDir(), "site.crt")
	keyPath = filepath.Join(CertDir(), "site.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o644); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return certPath, keyPath
}

func TestSnapshotReferencedCerts_loadsFilePairs(t *testing.T) {
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "ref.example.com")
	certPath, keyPath := seedReferencedCertRule(t, certPEM, keyPEM)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_refcert','ref','http','ref.example.com',443,1,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	pairs, err := snapshotReferencedCerts(context.Background(), database)
	if err != nil {
		t.Fatalf("snapshot referenced certs: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("pairs=%d, want 1", len(pairs))
	}
	if pairs[0].CertPath != certPath || pairs[0].KeyPath != keyPath {
		t.Fatalf("paths mismatch: %s/%s", pairs[0].CertPath, pairs[0].KeyPath)
	}
	if pairs[0].CertPEM != certPEM || pairs[0].KeyPEM != keyPEM {
		t.Fatalf("content should be loaded from referenced files")
	}

	// 文件缺失：单对 fail-open 跳过（不阻断快照），返回空
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	pairs, err = snapshotReferencedCerts(context.Background(), database)
	if err != nil {
		t.Fatalf("missing key file should not fail snapshot: %v", err)
	}
	if len(pairs) != 0 {
		t.Fatalf("missing pair should be skipped, got %d", len(pairs))
	}
}

func TestReferencedCertsDigest_tracksContentAndExistence(t *testing.T) {
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "ref.example.com")
	certPath, keyPath := seedReferencedCertRule(t, certPEM, keyPEM)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_refdigest','ref','http','ref.example.com',443,1,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	digest1, err := referencedCertsDigest(context.Background(), database)
	if err != nil || digest1 == "" {
		t.Fatalf("digest=%q err=%v", digest1, err)
	}
	// 文件内容变化 → 摘要变化（外部更新证书文件无 DB 版本递增，缓存键必须感知）
	newCert, newKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(48*time.Hour), "ref.example.com")
	if err := os.WriteFile(certPath, []byte(newCert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(newKey), 0o600); err != nil {
		t.Fatal(err)
	}
	digest2, err := referencedCertsDigest(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if digest2 == digest1 {
		t.Fatalf("digest should change when referenced file content changes")
	}
	// 文件删除 → 摘要再变化（存在性同样进摘要）
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	digest3, err := referencedCertsDigest(context.Background(), database)
	if err != nil {
		t.Fatal(err)
	}
	if digest3 == digest2 {
		t.Fatalf("digest should change when referenced file is removed")
	}
}

func TestMaterializeSnapshotReferencedCerts_writesAndSignals(t *testing.T) {
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "ref.example.com")
	certPath := filepath.Join(CertDir(), "site.crt")
	keyPath := filepath.Join(CertDir(), "site.key")
	current := []models.ClusterReferencedCertPair{{CertPath: certPath, KeyPath: keyPath, CertPEM: certPEM, KeyPEM: keyPEM}}

	// 首次落盘：changed=true
	changed, err := materializeSnapshotReferencedCerts(nil, current)
	if err != nil || !changed {
		t.Fatalf("first materialize changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(certPath)
	if err != nil || string(data) != certPEM {
		t.Fatalf("cert file content mismatch: err=%v", err)
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file perm=%v err=%v", info, err)
	}

	// 与上次已应用快照一致：changed=false
	changed, err = materializeSnapshotReferencedCerts(current, current)
	if err != nil || changed {
		t.Fatalf("unchanged materialize changed=%v err=%v", changed, err)
	}

	// 内容变化：changed=true（强制重载信号）
	newCert, newKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(48*time.Hour), "ref.example.com")
	updated := []models.ClusterReferencedCertPair{{CertPath: certPath, KeyPath: keyPath, CertPEM: newCert, KeyPEM: newKey}}
	changed, err = materializeSnapshotReferencedCerts(current, updated)
	if err != nil || !changed {
		t.Fatalf("content change should signal reload, changed=%v err=%v", changed, err)
	}
	if data, err := os.ReadFile(certPath); err != nil || string(data) != newCert {
		t.Fatalf("cert content should be updated")
	}

	// 路径越界（certDir 之外）：warn+跳过，不落盘、不判变化
	outside := []models.ClusterReferencedCertPair{{CertPath: "/etc/lazy_evil.crt", KeyPath: "/etc/lazy_evil.key", CertPEM: certPEM, KeyPEM: keyPEM}}
	changed, err = materializeSnapshotReferencedCerts(nil, outside)
	if err != nil {
		t.Fatalf("out-of-boundary pair should be skipped without error: %v", err)
	}
	if changed {
		t.Fatalf("out-of-boundary pair should not signal reload")
	}
	if _, err := os.Stat("/etc/lazy_evil.crt"); !os.IsNotExist(err) {
		t.Fatalf("out-of-boundary file must not be written")
	}
}

func TestCachedSnapshot_fingerprintTracksReferencedCertFileChanges(t *testing.T) {
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	service, database := newClusterTestService(t)
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	service.snapshotNow = func() time.Time { return now }
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "ref.example.com")
	certPath, keyPath := seedReferencedCertRule(t, certPEM, keyPEM)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_fp','ref','http','ref.example.com',443,1,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	ctx := context.Background()

	_, _, fingerprint1, err := service.cachedSnapshot(ctx)
	if err != nil {
		t.Fatalf("first snapshot: %v", err)
	}
	// 外部更新证书文件（无 DB 写 → cluster_version 不变）：缓存键随文件摘要
	// 失效，指纹必须重算——从节点凭指纹差异走全量重拉。
	newCert, newKey := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(48*time.Hour), "ref.example.com")
	if err := os.WriteFile(certPath, []byte(newCert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(newKey), 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, fingerprint2, err := service.cachedSnapshot(ctx)
	if err != nil {
		t.Fatalf("second snapshot: %v", err)
	}
	if fingerprint1 == fingerprint2 {
		t.Fatalf("fingerprint should change when referenced cert file content changes (cache key invalidation)")
	}
	// 文件未再变化：缓存命中，指纹稳定（304 门依赖）
	_, _, fingerprint3, err := service.cachedSnapshot(ctx)
	if err != nil {
		t.Fatalf("third snapshot: %v", err)
	}
	if fingerprint2 != fingerprint3 {
		t.Fatalf("fingerprint should be stable across cache hits")
	}
}

// TestSnapshotReferencedCerts_pathOnlyMode_zeroPlaintext 回归用例 a（JJC-20261125-001）：
// 主端 feature flag 开启后快照只传路径、零明文——序列化 JSON 断言无 PEM 字段。
func TestSnapshotReferencedCerts_pathOnlyMode_zeroPlaintext(t *testing.T) {
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	t.Setenv(SnapshotReferencedCertsPathOnlyModeEnv, "1")
	_, database := newClusterTestService(t)
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "ref.example.com")
	certPath, keyPath := seedReferencedCertRule(t, certPEM, keyPEM)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_pathonly','ref','http','ref.example.com',443,1,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	pairs, err := snapshotReferencedCerts(context.Background(), database)
	if err != nil {
		t.Fatalf("snapshot referenced certs: %v", err)
	}
	if len(pairs) != 1 {
		t.Fatalf("pairs=%d, want 1", len(pairs))
	}
	if pairs[0].CertPath != certPath || pairs[0].KeyPath != keyPath {
		t.Fatalf("paths mismatch: %s/%s", pairs[0].CertPath, pairs[0].KeyPath)
	}
	if pairs[0].CertPEM != "" || pairs[0].KeyPEM != "" {
		t.Fatalf("path-only mode must not carry content, got %q/%q", pairs[0].CertPEM, pairs[0].KeyPEM)
	}

	payload, err := json.Marshal(pairs)
	if err != nil {
		t.Fatalf("marshal pairs: %v", err)
	}
	body := string(payload)
	for _, needle := range []string{"BEGIN CERTIFICATE", "BEGIN PRIVATE KEY"} {
		if strings.Contains(body, needle) {
			t.Fatalf("path-only snapshot payload must contain no plaintext PEM (%q found): %s", needle, body)
		}
	}
	// 字段键存在但值为空串（模型字段无 omitempty）：无任何明文内容随快照下发。
	var round []models.ClusterReferencedCertPair
	if err := json.Unmarshal(payload, &round); err != nil {
		t.Fatalf("unmarshal pairs: %v", err)
	}
	if len(round) != 1 || round[0].CertPEM != "" || round[0].KeyPEM != "" {
		t.Fatalf("path-only mode must carry empty content, got %+v", round)
	}
}

// TestMaterializeSnapshotReferencedCerts_localFirstAndContentFallback 回归用例 b
// （JJC-20261125-001）：渐进期从端行为。
//  1) flag 关（默认，渐进期）+ 从端本地文件缺失 + 快照携带内容 → 内容落盘
//     生效，渲染仍有证书（存量从节点服务不中断）；
//  2) flag 开（主从均新版）+ 本地文件就绪 + 纯路径快照 → 直接采用本地文件，
//     零落盘、零明文；
//  3) flag 开 + 本地缺失 + 仍携带内容的旧主端快照（滚动升级混跑）→ 回退内容落盘；
//  4) flag 开 + 本地缺失 + 纯路径快照 → 无内容可回退，不写坏本地路径、不中断。
func TestMaterializeSnapshotReferencedCerts_localFirstAndContentFallback(t *testing.T) {
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	now := time.Now().UTC()
	certPEM, keyPEM := certificatePairForDomains(t, now.Add(-time.Hour), now.Add(24*time.Hour), "ref.example.com")
	certPath := filepath.Join(CertDir(), "site.crt")
	keyPath := filepath.Join(CertDir(), "site.key")
	withContent := models.ClusterReferencedCertPair{CertPath: certPath, KeyPath: keyPath, CertPEM: certPEM, KeyPEM: keyPEM}
	pathOnly := models.ClusterReferencedCertPair{CertPath: certPath, KeyPath: keyPath}

	// 场景 1：flag 关（默认）+ 本地文件缺失 → 快照内容落盘，服务不中断。
	if err := os.MkdirAll(CertDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	changed, err := materializeSnapshotReferencedCerts(nil, []models.ClusterReferencedCertPair{withContent})
	if err != nil || !changed {
		t.Fatalf("default mode should materialize snapshot content when local file missing, changed=%v err=%v", changed, err)
	}
	data, err := os.ReadFile(certPath)
	if err != nil || string(data) != certPEM {
		t.Fatalf("fallback snapshot content should be written to disk (rendering must have cert)")
	}
	if info, err := os.Stat(keyPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file perm=%v err=%v", info, err)
	}

	// 场景 2：flag 开 + 本地文件就绪 + 纯路径快照 → 直接采用本地，不落盘。
	t.Setenv(SnapshotReferencedCertsPathOnlyModeEnv, "1")
	changed, err = materializeSnapshotReferencedCerts(nil, []models.ClusterReferencedCertPair{pathOnly})
	if err != nil || changed {
		t.Fatalf("local-ready pair should be adopted silently, changed=%v err=%v", changed, err)
	}
	data, err = os.ReadFile(certPath)
	if err != nil || string(data) != certPEM {
		t.Fatalf("local file must be left untouched: err=%v", err)
	}

	// 场景 3：flag 开 + 本地缺失 + 旧主端内容快照（滚动升级混跑）→ 回退内容落盘。
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	changed, err = materializeSnapshotReferencedCerts(nil, []models.ClusterReferencedCertPair{withContent})
	if err != nil || !changed {
		t.Fatalf("missing local file should fall back to snapshot content, changed=%v err=%v", changed, err)
	}
	data, err = os.ReadFile(certPath)
	if err != nil || string(data) != certPEM {
		t.Fatalf("fallback snapshot content should be written to disk")
	}

	// 场景 4：flag 开 + 本地缺失 + 纯路径快照 → 无内容可回退：不落盘、不中断。
	if err := os.Remove(certPath); err != nil {
		t.Fatal(err)
	}
	changed, err = materializeSnapshotReferencedCerts(nil, []models.ClusterReferencedCertPair{pathOnly})
	if err != nil {
		t.Fatalf("path-only snapshot without local file must not fail apply: %v", err)
	}
	if changed {
		t.Fatalf("path-only snapshot without local file must not signal reload")
	}
	if _, err := os.Stat(certPath); !os.IsNotExist(err) {
		t.Fatalf("empty-content pair must not materialize an empty file")
	}
}
