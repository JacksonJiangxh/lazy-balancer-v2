package services

// 主节点证书文件扫描器测试（用户最终裁定流程）：
//   - 新证书入库、cert_version 推进；
//   - 指纹相同绝不重复 Upsert（cert_version 不抖动 → 从端不会永久重载）；
//   - 内容变化才推进版本；
//   - 非法 PEM 跳过、单行失败不中断整批；
//   - 甲路线关闭 / DEK 未配置时完全 no-op；
//   - 已有回填行沿用其 domain（不造重复证书行）；
//   - 扫描周期环境变量解析；
//   - 主节点入库后 force reload（真 /load）、无变化零 reload、与从端 apply 串行。
//
// 私钥一律 crypto/x509 内存生成，不留测试夹具文件。

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"lazy-balancer-v2/caddydbcert"
	"lazy-balancer-v2/internal/config"
)

// enableCertVaultForTest 在测试库上装 vault schema、注入 env 模式 DEK、开启甲路线。
// 与 InitCertVault 同一 DEK 来源与 provider 口径，清理时关掉全局开关避免污染后续用例。
func enableCertVaultForTest(t *testing.T, database *sql.DB) {
	t.Helper()
	if err := caddydbcert.EnsureVaultTables(context.Background(), database); err != nil {
		t.Fatalf("EnsureVaultTables: %v", err)
	}
	dek := make([]byte, 32)
	if _, err := rand.Read(dek); err != nil {
		t.Fatalf("rand dek: %v", err)
	}
	t.Setenv(DefaultCertDEKEnv, base64.StdEncoding.EncodeToString(dek))
	t.Setenv(kmsEndpointEnv, "")
	t.Setenv("LB_CERT_WRAPPED_DEK", "")
	ConfigureDBCertLoader(filepath.Join(t.TempDir(), "vault.db"), DefaultCertDEKEnv, "", "", "", "")
	t.Cleanup(func() { dbCertLoader.enabled.Store(false) })
}

// scanTestCertPair 生成自签证书对（无私钥落盘夹具）。SerialNumber 每次不同，
// 保证「内容变化」用例拿到真正不同的 PEM。
func scanTestCertPair(t *testing.T, domain string) (certPEM, keyPEM string) {
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

// resetCertFileReloadRetryForTest 隔离全局补偿标记与退避参数（用例间零污染）。
func resetCertFileReloadRetryForTest(t *testing.T) {
	t.Helper()
	clearCertFileReloadRetry()
	oldBase, oldMax := certFileReloadRetryBase, certFileReloadRetryMax
	t.Cleanup(func() {
		clearCertFileReloadRetry()
		certFileReloadRetryBase, certFileReloadRetryMax = oldBase, oldMax
	})
}

func certVaultVersion(t *testing.T, database *sql.DB) int64 {
	t.Helper()
	v, err := caddydbcert.CurrentVersion(context.Background(), database)
	if err != nil {
		t.Fatalf("read cert version: %v", err)
	}
	return v
}

func TestScanCertFilesToVault_newCertUpserted(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	restore := SetCertDirForTest(t.TempDir())
	defer restore()

	certPEM, keyPEM := scanTestCertPair(t, "scan-new.example.test")
	if err := WriteCertFiles("lb_scan_new", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	round := scanCertFilesToVault(context.Background())
	if round.Pairs != 1 || round.Upserted != 1 || round.Failed != 0 {
		t.Fatalf("scan round=%+v, want pairs=1 upserted=1 failed=0", round)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_secrets`).Scan(&count); err != nil {
		t.Fatalf("count vault rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("vault rows=%d, want 1", count)
	}
	var domain, cipher, keyCipher string
	if err := database.QueryRow(`SELECT domain, cert_ciphertext, key_ciphertext FROM cert_secrets`).Scan(&domain, &cipher, &keyCipher); err != nil {
		t.Fatalf("read vault row: %v", err)
	}
	if domain != "scan-new.example.test" {
		t.Fatalf("vault domain=%q, want SAN 首项 scan-new.example.test", domain)
	}
	if strings.Contains(cipher, "BEGIN CERTIFICATE") || strings.Contains(keyCipher, "PRIVATE KEY") {
		t.Fatal("plaintext PEM leaked into vault columns")
	}
	if v := certVaultVersion(t, database); v != 1 {
		t.Fatalf("cert_version=%d, want 1 after first upsert", v)
	}
}

// TestScanCertFilesToVault_identicalFingerprintDoesNotBumpVersion 是本次流程的
// 关键不变量：每轮重复 Upsert 会让触发器每轮 +1 cert_version，从端 before<after
// 恒真 → 永久强制重载。指纹一致必须跳过写入。
func TestScanCertFilesToVault_identicalFingerprintDoesNotBumpVersion(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	restore := SetCertDirForTest(t.TempDir())
	defer restore()

	certPEM, keyPEM := scanTestCertPair(t, "scan-idempotent.example.test")
	if err := WriteCertFiles("lb_scan_idem", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	first := scanCertFilesToVault(context.Background())
	if first.Upserted != 1 {
		t.Fatalf("first round=%+v, want upserted=1", first)
	}
	versionAfterFirst := certVaultVersion(t, database)
	for i := 0; i < 5; i++ {
		round := scanCertFilesToVault(context.Background())
		if round.Upserted != 0 || round.Unchanged != 1 {
			t.Fatalf("round %d=%+v, want upserted=0 unchanged=1（指纹相同不得重复入库）", i+1, round)
		}
		if got := certVaultVersion(t, database); got != versionAfterFirst {
			t.Fatalf("round %d bumped cert_version %d→%d（从端会永久重载）", i+1, versionAfterFirst, got)
		}
	}
}

func TestScanCertFilesToVault_changedCertAdvancesVersion(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	restore := SetCertDirForTest(t.TempDir())
	defer restore()

	certPEM, keyPEM := scanTestCertPair(t, "scan-change.example.test")
	if err := WriteCertFiles("lb_scan_change", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	scanCertFilesToVault(context.Background())
	before := certVaultVersion(t, database)

	newCert, newKey := scanTestCertPair(t, "scan-change.example.test")
	if newCert == certPEM {
		t.Fatal("test cert generator produced identical PEM")
	}
	if err := WriteCertFiles("lb_scan_change", newCert, newKey); err != nil {
		t.Fatalf("WriteCertFiles (changed): %v", err)
	}
	round := scanCertFilesToVault(context.Background())
	if round.Upserted != 1 {
		t.Fatalf("changed round=%+v, want upserted=1", round)
	}
	if after := certVaultVersion(t, database); after <= before {
		t.Fatalf("cert_version %d→%d did not advance on real content change", before, after)
	}
}

func TestScanCertFilesToVault_invalidPEMSkippedWithoutAbortingBatch(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	dir := t.TempDir()
	restore := SetCertDirForTest(dir)
	defer restore()

	// 合法对 + 非法对：非法对只记 failed，合法对仍须入库。
	goodCert, goodKey := scanTestCertPair(t, "scan-good.example.test")
	if err := WriteCertFiles("lb_scan_good", goodCert, goodKey); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lb_scan_bad.crt"), []byte("not a PEM"), 0644); err != nil {
		t.Fatalf("write bad crt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "lb_scan_bad.key"), []byte("not a PEM"), 0600); err != nil {
		t.Fatalf("write bad key: %v", err)
	}
	round := scanCertFilesToVault(context.Background())
	if round.Pairs != 1 || round.Upserted != 1 || round.Failed != 1 {
		t.Fatalf("round=%+v, want pairs=1 upserted=1 failed=1", round)
	}
	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_secrets`).Scan(&count); err != nil {
		t.Fatalf("count vault rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("vault rows=%d, want 1（非法对不得入库）", count)
	}
}

func TestScanCertFilesToVault_routeADisabledIsNoOp(t *testing.T) {
	database := setupIsolatedDB(t)
	if err := caddydbcert.EnsureVaultTables(context.Background(), database); err != nil {
		t.Fatalf("EnsureVaultTables: %v", err)
	}
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	certPEM, keyPEM := scanTestCertPair(t, "scan-off.example.test")
	if err := WriteCertFiles("lb_scan_off", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	// 不调用 ConfigureDBCertLoader：甲路线关闭。
	round := scanCertFilesToVault(context.Background())
	if round != (certScanRound{}) {
		t.Fatalf("route A off round=%+v, want zero", round)
	}
	if v := certVaultVersion(t, database); v != 0 {
		t.Fatalf("route A off bumped cert_version=%d, want 0", v)
	}
}

func TestScanCertFilesToVault_dekNotConfiguredIsNoOp(t *testing.T) {
	database := setupIsolatedDB(t)
	if err := caddydbcert.EnsureVaultTables(context.Background(), database); err != nil {
		t.Fatalf("EnsureVaultTables: %v", err)
	}
	t.Setenv(DefaultCertDEKEnv, "")
	t.Setenv(kmsEndpointEnv, "")
	ConfigureDBCertLoader(filepath.Join(t.TempDir(), "vault.db"), DefaultCertDEKEnv, "", "", "", "")
	t.Cleanup(func() { dbCertLoader.enabled.Store(false) })
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	certPEM, keyPEM := scanTestCertPair(t, "scan-nodek.example.test")
	if err := WriteCertFiles("lb_scan_nodek", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	round := scanCertFilesToVault(context.Background())
	if round != (certScanRound{}) {
		t.Fatalf("DEK missing round=%+v, want zero", round)
	}
	if v := certVaultVersion(t, database); v != 0 {
		t.Fatalf("DEK missing bumped cert_version=%d, want 0", v)
	}
}

// 已有回填行（domain ≠ SAN）沿用其 domain 计算指纹——内容一致时既不重复
// 造行，也不推进版本。
func TestScanCertFilesToVault_reusesBackfilledRowDomain(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	restore := SetCertDirForTest(t.TempDir())
	defer restore()

	certPEM, keyPEM := scanTestCertPair(t, "scan-san.example.test")
	if err := WriteCertFiles("lb_scan_domain", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	// 模拟启动回填：domain 取规则域名（与 SAN 不同），rule_id 与文件名一致。
	if _, err := caddydbcert.Upsert(context.Background(), database, certKeyProvider(""), "",
		"seed.example.test", "lb_scan_domain", certPEM, keyPEM, false, []string{"lb_scan_domain"}); err != nil {
		t.Fatalf("seed backfill row: %v", err)
	}
	before := certVaultVersion(t, database)
	round := scanCertFilesToVault(context.Background())
	if round.Upserted != 0 || round.Unchanged != 1 {
		t.Fatalf("round=%+v, want upserted=0 unchanged=1（沿用已有 domain 比对）", round)
	}
	if got := certVaultVersion(t, database); got != before {
		t.Fatalf("cert_version %d→%d bumped on unchanged backfilled row", before, got)
	}
	var count int
	var domain string
	if err := database.QueryRow(`SELECT COUNT(*) FROM cert_secrets WHERE rule_id='lb_scan_domain'`).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if err := database.QueryRow(`SELECT domain FROM cert_secrets WHERE rule_id='lb_scan_domain'`).Scan(&domain); err != nil {
		t.Fatalf("read domain: %v", err)
	}
	if count != 1 || domain != "seed.example.test" {
		t.Fatalf("rows=%d domain=%q, want 1 / seed.example.test（不得按 SAN 造第二行）", count, domain)
	}
}

// 循环接线 + 多轮不抖动：真实 ticker 连跑多轮，cert_version 只能推进一次；
// ctx 取消后循环退出，不再写库。
func TestStartCertFileScanLoop_repeatsWithoutChurnAndStopsOnCancel(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	certPEM, keyPEM := scanTestCertPair(t, "scan-loop.example.test")
	if err := WriteCertFiles("lb_scan_loop", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	oldInterval := certFileScanInterval
	certFileScanInterval = 20 * time.Millisecond
	defer func() { certFileScanInterval = oldInterval }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startCertFileScanLoop(ctx)

	deadline := time.Now().Add(3 * time.Second)
	for certVaultVersion(t, database) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if v := certVaultVersion(t, database); v != 1 {
		t.Fatalf("loop did not ingest on first round: cert_version=%d, want 1", v)
	}
	// 多轮 ticker（≥20ms × 10 轮）后版本不得抖动。
	time.Sleep(250 * time.Millisecond)
	if got := certVaultVersion(t, database); got != 1 {
		t.Fatalf("repeated ticks churned cert_version to %d（从端会永久重载）", got)
	}
	cancel()
	time.Sleep(60 * time.Millisecond)
	if got := certVaultVersion(t, database); got != 1 {
		t.Fatalf("scan loop wrote after ctx cancel: cert_version=%d", got)
	}
}

func TestCertFileScanInterval_envOverride(t *testing.T) {
	t.Setenv(CertFileScanIntervalEnv, "15")
	if got := effectiveCertFileScanInterval(); got != 15*time.Second {
		t.Fatalf("interval=%v, want 15s", got)
	}
	t.Setenv(CertFileScanIntervalEnv, "bogus")
	if got := effectiveCertFileScanInterval(); got != certFileScanInterval {
		t.Fatalf("invalid env interval=%v, want default %v", got, certFileScanInterval)
	}
	t.Setenv(CertFileScanIntervalEnv, "0")
	if got := effectiveCertFileScanInterval(); got != certFileScanInterval {
		t.Fatalf("zero env interval=%v, want default %v", got, certFileScanInterval)
	}
}

// 主节点「放文件即生效」：入库后只触发一次真实 /load，且强制击穿同配置短路。
// 注入的钩子与 main.go 的 certReloader 同语义（WithCaddyOpLock + ReloadFromDB）。
func TestScanCertFilesToVault_masterForceReloadOnChange(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	restore := SetCertDirForTest(t.TempDir())
	defer restore()

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
	caddyService := NewCaddyService(caddyServer.URL)
	SetCertFileScanReload(func() error {
		var reloadErr error
		WithCaddyOpLock(func() { reloadErr = ReloadFromDB(caddyService, database, database) })
		return reloadErr
	})
	defer SetCertFileScanReload(nil)
	loadCount := func() (int, []bool) {
		mu.Lock()
		defer mu.Unlock()
		return len(bodies), append([]bool(nil), forced...)
	}

	certPEM, keyPEM := scanTestCertPair(t, "scan-master-reload.example.test")
	if err := WriteCertFiles("lb_scan_mreload", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	first := scanCertFilesToVault(context.Background())
	if first.Upserted != 1 {
		t.Fatalf("first round=%+v, want upserted=1", first)
	}
	if n, flags := loadCount(); n != 1 || !flags[0] {
		t.Fatalf("/load 次数=%d flags=%v, want 1 次且 must-revalidate", n, flags)
	}

	// 指纹全同的重复扫描：0 次 reload（不能每 60s 空重载）。
	second := scanCertFilesToVault(context.Background())
	if second.Upserted != 0 || second.Unchanged != 1 {
		t.Fatalf("second round=%+v, want upserted=0 unchanged=1", second)
	}
	if n, _ := loadCount(); n != 1 {
		t.Fatalf("unchanged scan triggered extra /load: count=%d, want 1", n)
	}
}

// 扫描 reload 与从端 applySnapshot reload 必须共用 CaddyOpLock：
// apply 持锁期间扫描 reload 不得进入临界区；释放后串行进入，全程零重叠。
func TestCertFileScanReload_serializesWithSlaveApplySnapshot(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	enableCertVaultForTest(t, database)
	for _, stmt := range []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_conc','conc','http','conc.example.test',80,1)`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_conc','127.0.0.1',8080,1,1)`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("set master: %v", err)
	}
	seedCert, seedKey := scanTestCertPair(t, "conc.example.test")
	if _, err := caddydbcert.Upsert(ctx, database, certKeyProvider(""), "", "conc.example.test", "lb_conc", seedCert, seedKey, false, []string{"lb_conc"}); err != nil {
		t.Fatalf("seed vault cert: %v", err)
	}
	service := NewClusterService(database, "")
	snap, _, err := service.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave: %v", err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	var active atomic.Int32
	var overlap atomic.Bool
	applyEntered, scanEntered := make(chan struct{}), make(chan struct{})
	releaseApply, releaseScan := make(chan struct{}), make(chan struct{})
	oldHook := syncReloadLockHook
	syncReloadLockHook = func() { // applySnapshot 重载临界区入口（已在 CaddyOpLock 内）
		if active.Add(1) != 1 {
			overlap.Store(true)
		}
		close(applyEntered)
		<-releaseApply
		active.Add(-1)
	}
	defer func() { syncReloadLockHook = oldHook }()

	scanCaddy := NewCaddyService(caddyServer.URL)
	SetCertFileScanReload(func() error {
		var reloadErr error
		WithCaddyOpLock(func() {
			if active.Add(1) != 1 {
				overlap.Store(true)
			}
			close(scanEntered)
			<-releaseScan
			reloadErr = ReloadFromDB(scanCaddy, database, database)
			active.Add(-1)
		})
		return reloadErr
	})
	defer SetCertFileScanReload(nil)

	dirRestore := SetCertDirForTest(t.TempDir())
	defer dirRestore()
	newCert, newKey := scanTestCertPair(t, "scan-conc.example.test")
	if err := WriteCertFiles("lb_scan_conc", newCert, newKey); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}

	applyDone := make(chan error, 1)
	go func() { applyDone <- syncService.applySnapshot(ctx, snap) }()
	<-applyEntered // 从端已持 CaddyOpLock

	scanDone := make(chan certScanRound, 1)
	go func() { scanDone <- scanCertFilesToVault(ctx) }()
	select {
	case <-scanEntered:
		t.Fatal("扫描 reload 与从端 applySnapshot reload 重叠（未共用 CaddyOpLock）")
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseApply)
	if err := <-applyDone; err != nil {
		t.Fatalf("slave applySnapshot: %v", err)
	}
	select {
	case <-scanEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("apply 释放锁后扫描 reload 未进入")
	}
	close(releaseScan)
	round := <-scanDone
	if round.Upserted != 1 {
		t.Fatalf("scan round=%+v, want upserted=1", round)
	}
	if overlap.Load() {
		t.Fatal("两处 reload 临界区发生重叠")
	}
}

// 失败 → 标记 → 下一轮无变化仍重试 → 成功清标记 → 再下一轮零调用。
func TestCertFileReloadRetry_marksRetriesAndClears(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	restore := SetCertDirForTest(t.TempDir())
	defer restore()
	resetCertFileReloadRetryForTest(t)
	certFileReloadRetryBase = 0 // 立即到期，隔离退避等待

	var calls int
	SetCertFileScanReload(func() error {
		calls++
		if calls == 1 {
			return errors.New("caddy 503 service unavailable")
		}
		return nil
	})
	defer SetCertFileScanReload(nil)

	certPEM, keyPEM := scanTestCertPair(t, "scan-retry.example.test")
	if err := WriteCertFiles("lb_scan_retry", certPEM, keyPEM); err != nil {
		t.Fatalf("WriteCertFiles: %v", err)
	}
	first := scanCertFilesToVault(context.Background())
	if first.Upserted != 1 || calls != 1 {
		t.Fatalf("first round=%+v calls=%d, want upserted=1 calls=1", first, calls)
	}
	state, ok := certFileReloadRetrySnapshot()
	if !ok || state.attempts != 1 || state.certVersion < 1 {
		t.Fatalf("retry marker=%+v ok=%v, want attempts=1 cert_version>=1", state, ok)
	}

	second := scanCertFilesToVault(context.Background())
	if second.Upserted != 0 || second.Unchanged != 1 || calls != 2 {
		t.Fatalf("second round=%+v calls=%d, want unchanged only + retry (calls=2)", second, calls)
	}
	if _, stillPending := certFileReloadRetrySnapshot(); stillPending {
		t.Fatal("successful retry did not clear marker")
	}

	scanCertFilesToVault(context.Background())
	if calls != 2 {
		t.Fatalf("after clear, third round called hook %d times, want 2（无变化零重载）", calls)
	}
}

// 补偿重试必须与原触发路径一样走 CaddyOpLock：applySnapshot 持锁期间不进入。
func TestCertFileReloadRetry_serializesWithSlaveApplySnapshot(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	enableCertVaultForTest(t, database)
	resetCertFileReloadRetryForTest(t)
	certFileReloadRetryBase = 0
	for _, stmt := range []string{
		`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_retry_conc','retry conc','http','rc.example.test',80,1)`,
		`INSERT INTO upstreams (rule_id,host,port,weight,enabled) VALUES ('lb_retry_conc','127.0.0.1',8080,1,1)`,
		`INSERT INTO users (id,username,password_hash,role,is_enabled,last_login) VALUES (1,'admin','h','admin',1,datetime('now'))`,
	} {
		if _, err := database.Exec(stmt); err != nil {
			t.Fatalf("seed %q: %v", stmt, err)
		}
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatalf("set master: %v", err)
	}
	seedCert, seedKey := scanTestCertPair(t, "rc.example.test")
	if _, err := caddydbcert.Upsert(ctx, database, certKeyProvider(""), "", "rc.example.test", "lb_retry_conc", seedCert, seedKey, false, []string{"lb_retry_conc"}); err != nil {
		t.Fatalf("seed vault cert: %v", err)
	}
	service := NewClusterService(database, "")
	snap, _, err := service.Snapshot(ctx, 0, "", "")
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatalf("set slave: %v", err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	// 先制造一次失败，留下待重试标记（直接调 helper，避免额外文件/证书铺垫）。
	SetCertFileScanReload(func() error { return errors.New("caddy 503") })
	maybeReloadMasterAfterScan(ctx, certScanRound{Upserted: 1})
	if _, ok := certFileReloadRetrySnapshot(); !ok {
		t.Fatal("retry marker not set after failure")
	}

	var active atomic.Int32
	var overlap atomic.Bool
	applyEntered, retryEntered := make(chan struct{}), make(chan struct{})
	releaseApply, releaseRetry := make(chan struct{}), make(chan struct{})
	oldHook := syncReloadLockHook
	syncReloadLockHook = func() {
		if active.Add(1) != 1 {
			overlap.Store(true)
		}
		close(applyEntered)
		<-releaseApply
		active.Add(-1)
	}
	defer func() { syncReloadLockHook = oldHook }()

	retryCaddy := NewCaddyService(caddyServer.URL)
	SetCertFileScanReload(func() error {
		var reloadErr error
		WithCaddyOpLock(func() {
			if active.Add(1) != 1 {
				overlap.Store(true)
			}
			close(retryEntered)
			<-releaseRetry
			reloadErr = ReloadFromDB(retryCaddy, database, database)
			active.Add(-1)
		})
		return reloadErr
	})
	defer SetCertFileScanReload(nil)

	applyDone := make(chan error, 1)
	go func() { applyDone <- syncService.applySnapshot(ctx, snap) }()
	<-applyEntered

	retryDone := make(chan struct{})
	go func() { maybeReloadMasterAfterScan(ctx, certScanRound{}); close(retryDone) }()
	select {
	case <-retryEntered:
		t.Fatal("补偿重试与从端 applySnapshot reload 重叠（未共用 CaddyOpLock）")
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseApply)
	if err := <-applyDone; err != nil {
		t.Fatalf("slave applySnapshot: %v", err)
	}
	select {
	case <-retryEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("apply 释放锁后补偿重试未进入")
	}
	close(releaseRetry)
	<-retryDone
	if overlap.Load() {
		t.Fatal("两处 reload 临界区发生重叠")
	}
	if _, ok := certFileReloadRetrySnapshot(); ok {
		t.Fatal("successful compensated retry did not clear marker")
	}
}

// 连续失败时限流：退避 base=120ms / cap=240ms，500ms 窗口内调用次数远小于轮数。
func TestCertFileReloadRetry_throttlesConsecutiveFailures(t *testing.T) {
	database := setupIsolatedDB(t)
	enableCertVaultForTest(t, database)
	resetCertFileReloadRetryForTest(t)
	certFileReloadRetryBase = 120 * time.Millisecond
	certFileReloadRetryMax = 240 * time.Millisecond

	var calls int
	SetCertFileScanReload(func() error { calls++; return errors.New("caddy down") })
	defer SetCertFileScanReload(nil)

	maybeReloadMasterAfterScan(context.Background(), certScanRound{Upserted: 1}) // 首次失败 → attempts=1
	rounds := 0
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		maybeReloadMasterAfterScan(context.Background(), certScanRound{}) // 无入库，只有补偿到期才调用
		rounds++
		time.Sleep(10 * time.Millisecond)
	}
	if rounds < 20 {
		t.Fatalf("rounds=%d, want >=20（限流窗口未跑够）", rounds)
	}
	if calls < 2 || calls > 4 {
		t.Fatalf("500ms 内重载调用 %d 次（共 %d 轮），want 2..4（退避限流）", calls, rounds)
	}
	state, ok := certFileReloadRetrySnapshot()
	if !ok || state.attempts < 2 {
		t.Fatalf("retry marker=%+v ok=%v, want attempts>=2（失败持续保留）", state, ok)
	}
}
