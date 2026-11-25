package db

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

// tlsFileMigrationTestDB 建临时库 + 完整 schema（沿用 openMigrationTestDB
// 同款建库方式，并播种 global_config 单行供 cluster_version bump 消费）。
func tlsFileMigrationTestDB(t *testing.T) *sql.DB {
	t.Helper()
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT OR IGNORE INTO global_config (id, caddy_config, cluster_version) VALUES (1,'{}',0)"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	return database
}

// writePEMPair 写一对临时 PEM 文件，返回 (certPath, keyPath)。无效用例用
// garbage=true 写不可解析内容。
func writePEMPair(t *testing.T, dir, name string, garbage bool) (string, string) {
	t.Helper()
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if garbage {
		if err := os.WriteFile(certPath, []byte("not a pem"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(keyPath, []byte("also not"), 0o600); err != nil {
			t.Fatal(err)
		}
		return certPath, keyPath
	}
	certPEM, keyPEM := tlsFileTestCertPair(t, name+".example.test")
	if err := os.WriteFile(certPath, []byte(certPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

// seedTlsFileRule 播种一条 file 模式启用 TLS 的规则（可省略 path/material 列）。
func seedTlsFileRule(t *testing.T, database *sql.DB, caddyID string, opts map[string]string) {
	t.Helper()
	certPath, keyPath := opts["certPath"], opts["keyPath"]
	certPEM, keyPEM := opts["certPEM"], opts["keyPEM"]
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port,
		enable_tls, tls_source, tls_cert_path, tls_key_path, tls_cert, tls_key)
		VALUES (?,?,?,?,?,1,'file',?,?,?,?)`,
		caddyID, "file-"+caddyID, "http", caddyID+".example.test", 443, certPath, keyPath, certPEM, keyPEM); err != nil {
		t.Fatalf("seed %s: %v", caddyID, err)
	}
}

// readTlsFileState 读回一行 (tls_cert, tls_key, tls_cert_path, tls_key_path)。
func readTlsFileState(t *testing.T, database *sql.DB, caddyID string) (cert, key, certPath, keyPath string) {
	t.Helper()
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,''),
		COALESCE(tls_cert_path,''), COALESCE(tls_key_path,'') FROM lb_rules WHERE caddy_id=?`, caddyID).
		Scan(&cert, &key, &certPath, &keyPath); err != nil {
		t.Fatalf("read %s: %v", caddyID, err)
	}
	return
}

// 验收 a：校验失败（路径空/文件缺失/PEM 不可解析）→ 明文未被清空。
func TestMigrateTlsFilePlaintextClear_invalidRowsKeptPlaintext(t *testing.T) {
	database := tlsFileMigrationTestDB(t)
	dir := t.TempDir()
	badCert, badKey := writePEMPair(t, dir, "bad", true) // 不可解析
	missing := filepath.Join(dir, "missing.crt")
	missingKey := filepath.Join(dir, "missing.key")

	seedTlsFileRule(t, database, "lb_file_empty_path", map[string]string{
		"certPEM": "OLD_CERT_EMPTY_PATH", "keyPEM": "OLD_KEY_EMPTY_PATH",
	})
	seedTlsFileRule(t, database, "lb_file_missing_file", map[string]string{
		"certPath": missing, "keyPath": missingKey,
		"certPEM": "OLD_CERT_MISSING", "keyPEM": "OLD_KEY_MISSING",
	})
	seedTlsFileRule(t, database, "lb_file_bad_pem", map[string]string{
		"certPath": badCert, "keyPath": badKey,
		"certPEM": "OLD_CERT_BAD", "keyPEM": "OLD_KEY_BAD",
	})

	if err := migrateTlsFilePlaintextClear(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	for _, id := range []string{"lb_file_empty_path", "lb_file_missing_file", "lb_file_bad_pem"} {
		cert, key, _, _ := readTlsFileState(t, database, id)
		if cert == "" || key == "" {
			t.Fatalf("%s 明文被清空 cert=%q key=%q, want 保留（校验失败不得清空）", id, cert, key)
		}
	}
	// 备份表不得出现校验失败行（清空未发生，也无清单语义）。
	var backed int
	if err := database.QueryRow(`SELECT COUNT(*) FROM ` + migrationTlsFileBackupTable).Scan(&backed); err != nil {
		t.Fatal(err)
	}
	if backed != 0 {
		t.Fatalf("备份表 %d 行, want 0（校验失败行不清空不备份）", backed)
	}
}

// 验收 b：成功路径 → file 行 tls_cert/tls_key 清空 + 备份表有旧值（可回滚）+
// 路径列保留；幂等重跑零副作用。
func TestMigrateTlsFilePlaintextClear_clearsValidRowsWithBackup(t *testing.T) {
	database := tlsFileMigrationTestDB(t)
	dir := t.TempDir()
	certPath, keyPath := writePEMPair(t, dir, "good", false)

	// 有效行 + 一条不参与本迁移的 manual 行（对照）。
	seedTlsFileRule(t, database, "lb_file_valid", map[string]string{
		"certPath": certPath, "keyPath": keyPath,
		"certPEM": "OLD_CERT_VALID", "keyPEM": "OLD_KEY_VALID",
	})
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port,
		enable_tls, tls_source, tls_cert, tls_key)
		VALUES ('lb_manual_ctl','manual-ctl','http','ctl.example.test',443,1,'manual','M_CERT','M_KEY')`); err != nil {
		t.Fatalf("seed manual control: %v", err)
	}

	if err := migrateTlsFilePlaintextClear(); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	cert, key, gotCertPath, gotKeyPath := readTlsFileState(t, database, "lb_file_valid")
	if cert != "" || key != "" {
		t.Fatalf("file 行明文 cert=%q key=%q, want 已清空", cert, key)
	}
	if gotCertPath != certPath || gotKeyPath != keyPath {
		t.Fatalf("路径列被改写 cert_path=%q key_path=%q, want 保留 %q/%q", gotCertPath, gotKeyPath, certPath, keyPath)
	}
	var oldCert, oldKey string
	if err := database.QueryRow(`SELECT old_tls_cert, old_tls_key FROM `+migrationTlsFileBackupTable+` WHERE rule_id='lb_file_valid'`).
		Scan(&oldCert, &oldKey); err != nil {
		t.Fatalf("backup row missing: %v", err)
	}
	if oldCert != "OLD_CERT_VALID" || oldKey != "OLD_KEY_VALID" {
		t.Fatalf("备份值 cert=%q key=%q, want 旧明文（可回滚）", oldCert, oldKey)
	}
	// manual 对照行不得触碰。
	mCert, mKey, _, _ := readTlsFileState(t, database, "lb_manual_ctl")
	if mCert != "M_CERT" || mKey != "M_KEY" {
		t.Fatalf("manual 行被改写 cert=%q key=%q", mCert, mKey)
	}
	// 幂等：重跑零副作用（明文已空探测零命中）。
	if err := migrateTlsFilePlaintextClear(); err != nil {
		t.Fatalf("migrate again: %v", err)
	}
	var backupCount int
	if err := database.QueryRow(`SELECT COUNT(*) FROM ` + migrationTlsFileBackupTable).Scan(&backupCount); err != nil {
		t.Fatal(err)
	}
	if backupCount != 1 {
		t.Fatalf("二次迁移备份表 %d 行, want 1（幂等零新增）", backupCount)
	}
}

// 验收 c：DEK 配置（甲路线启用）→ 明文整体保留 + file 行清单记入备份表
// （old_tls_cert/key 留空）供渲染侧过滤；未配置 → 清空+备份。
func TestMigrateTlsFilePlaintextClear_routeAInterop(t *testing.T) {
	database := tlsFileMigrationTestDB(t)
	dir := t.TempDir()
	certPath, keyPath := writePEMPair(t, dir, "good", false)

	seedTlsFileRule(t, database, "lb_file_routeA", map[string]string{
		"certPath": certPath, "keyPath": keyPath,
		"certPEM": "OLD_CERT_ROUTEA", "keyPEM": "OLD_KEY_ROUTEA",
	})

	// 甲路线启用：KMS 端点非空即启用（与 services.CertVaultDEKSource 同谓词）。
	t.Setenv("LB_CERT_KMS_ENDPOINT", "https://kms.internal/unseal")
	t.Setenv("LB_CERT_DEK_B64", "")
	if err := migrateTlsFilePlaintextClear(); err != nil {
		t.Fatalf("migrate (route A on): %v", err)
	}
	cert, key, _, _ := readTlsFileState(t, database, "lb_file_routeA")
	if cert != "OLD_CERT_ROUTEA" || key != "OLD_KEY_ROUTEA" {
		t.Fatalf("甲路线下明文被清空 cert=%q key=%q, want 保留（互斥）", cert, key)
	}
	// 清单行：rule_id 在案、old 列留空。
	var invCert, invKey string
	if err := database.QueryRow(`SELECT old_tls_cert, old_tls_key FROM `+migrationTlsFileBackupTable+` WHERE rule_id='lb_file_routeA'`).
		Scan(&invCert, &invKey); err != nil {
		t.Fatalf("inventory row missing: %v", err)
	}
	if invCert != "" || invKey != "" {
		t.Fatalf("清单行 cert=%q key=%q, want 留空（非备份语义）", invCert, invKey)
	}

	// 关闭甲路线重跑：清单行在案不阻塞，明文仍校验通过并完成清空+备份。
	t.Setenv("LB_CERT_KMS_ENDPOINT", "")
	t.Setenv("LB_CERT_DEK_B64", "")
	if err := migrateTlsFilePlaintextClear(); err != nil {
		t.Fatalf("migrate (route A off): %v", err)
	}
	cert, key, _, _ = readTlsFileState(t, database, "lb_file_routeA")
	if cert != "" || key != "" {
		t.Fatalf("关闭甲路线重跑后明文 cert=%q key=%q, want 已清空", cert, key)
	}
	var oldCert, oldKey string
	if err := database.QueryRow(`SELECT old_tls_cert, old_tls_key FROM `+migrationTlsFileBackupTable+`
		WHERE rule_id='lb_file_routeA' AND old_tls_cert<>''`).Scan(&oldCert, &oldKey); err != nil {
		t.Fatalf("backup row missing after route A off: %v", err)
	}
	if oldCert != "OLD_CERT_ROUTEA" || oldKey != "OLD_KEY_ROUTEA" {
		t.Fatalf("备份值 cert=%q key=%q, want 旧明文", oldCert, oldKey)
	}
}

// tlsFileTestCertPair 生成自签证书对（与 services 包 scanTestCertPair 同款口径）。
func tlsFileTestCertPair(t *testing.T, domain string) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}
