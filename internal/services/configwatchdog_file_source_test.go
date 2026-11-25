package services

import (
	"database/sql"
	"os"
	"testing"
)

// 启用 file 行的看门狗判定与渲染层 availableCerts 同口径（路径引用架构，
// 重构 JJC-20261125-001）：文件可读 → 就绪不判漂移；路径悬挂（文件缺失）→
// 不就绪（沿用 manual 的 fail-visible）。
func TestConfigWatchdog_fileRuleReadyWhenContentStored(t *testing.T) {
	// Given：启用 file 规则，路径指向白名单目录内真实文件
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "wd-ready.crt", "wd-ready.key")
	ResetConfigDrift()
	t.Cleanup(ResetConfigDrift)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_wd_file_ready','wd-file-ready','http','file-ready.example.test',18091,'weighted_round_robin',1,10,2,3,2,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_wd_file_ready','127.0.0.1',9000,1,'http')"); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：Caddy 运行配置含该路由（渲染侧文件可读即有 TLS policy → 路由在位）
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_18091":{"listen":[":18091"],"routes":[{"@id":"lb_wd_file_ready","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：文件就绪 → 不判漂移
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("启用 file 行文件就绪即不判漂移: %+v", drift)
	}
}

func TestConfigWatchdog_fileRuleNotReadyWhenContentMissing(t *testing.T) {
	// Given：启用 file 规则，路径悬挂（文件不存在）
	_, database := newClusterTestService(t)
	ResetConfigDrift()
	t.Cleanup(ResetConfigDrift)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_wd_file_missing','wd-file-missing','http','file-missing.example.test',18092,'weighted_round_robin',1,10,2,3,2,1,'file','/app/certs/missing.crt','/app/certs/missing.key')`); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_wd_file_missing','127.0.0.1',9000,1,'http')"); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：Caddy 运行配置含该路由（渲染侧文件缺失跳过该规则 → 期望集不含它）
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_18092":{"listen":[":18092"],"routes":[{"@id":"lb_wd_file_missing","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：文件缺失 → 不就绪，判「多余」漂移并点名
	drift := CurrentConfigDrift()
	if drift.Consistent || len(drift.Extra) == 0 {
		t.Fatalf("启用 file 行文件缺失必须判不就绪（渲染无证跳过 → 多余）: %+v", drift)
	}
}

// ingestWatchFixture 组装「引用证书看门狗 + 回写前测试缝」夹具：启用 file 规则
// （带 last-good 内容）+ 重载计数 + 指纹基线复位，返回数据库句柄。
func ingestWatchFixture(t *testing.T, ruleID string, certPath, keyPath string) (*sql.DB, *int) {
	t.Helper()
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path, tls_cert, tls_key)
		VALUES (?,?, 'http', ?, 19459, 1, 'file', ?, ?, 'old-cert', 'old-key')`, ruleID, ruleID, ruleID+".test", certPath, keyPath); err != nil {
		t.Fatalf("seed referenced rule: %v", err)
	}
	reloads := 0
	SetReferencedCertReload(func() error { reloads++; return nil })
	ResetReferencedCertWatch()
	t.Cleanup(func() {
		SetReferencedCertReload(nil)
		ResetReferencedCertWatch()
		referencedCertChangeBeforeReloadForTest = nil
	})
	return database, &reloads
}

func assertRuleMaterials(t *testing.T, database *sql.DB, ruleID, wantCert, wantKey string) {
	t.Helper()
	var storedCert, storedKey string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id=?`, ruleID).Scan(&storedCert, &storedKey); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedCert != wantCert || storedKey != wantKey {
		t.Fatalf("tls_cert/tls_key=%q/%q, want %q/%q", storedCert, storedKey, wantCert, wantKey)
	}
}

// 乐观锁形态①：摄取源路径在「扫描→重载」窗口内被并发改写——重载仍触发一次
//（全局重载幂等），但并发改写的路径与存量内容不被覆盖（路径引用架构无回写，
// 重构 JJC-20261125-001）。
func TestReferencedCertWatch_optimisticLockPathRewritten(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "opt1.crt", "opt1.key")
	database, reloads := ingestWatchFixture(t, "lb_opt_lock1", certPath, keyPath)

	// 并发编辑在重载前改写摄取源路径（指向另一对真实文件）。
	newCertPath, newKeyPath := writeReferencedCertFiles(t, dir, "opt1-new.crt", "opt1-new.key")
	referencedCertChangeBeforeReloadForTest = func(string) {
		if _, err := database.Exec(`UPDATE lb_rules SET tls_cert_path=?, tls_key_path=? WHERE caddy_id='lb_opt_lock1'`, newCertPath, newKeyPath); err != nil {
			t.Errorf("并发改写路径: %v", err)
		}
	}

	checkReferencedCertFiles() // 首扫建基线
	// 外部更新源文件为新合法配对 → 本轮检出变化且校验通过 → 触发重载。
	changedCert, changedKey := matchingCertificatePair(t, "opt1-changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()

	if *reloads != 1 {
		t.Fatalf("文件变化应触发一次重载, reloads=%d", *reloads)
	}
	// 并发改写的路径与存量内容保留（无回写，天然成立）。
	assertRuleMaterials(t, database, "lb_opt_lock1", "old-cert", "old-key")
	var storedCertPath string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert_path,'') FROM lb_rules WHERE caddy_id='lb_opt_lock1'`).Scan(&storedCertPath); err != nil {
		t.Fatalf("read persisted path: %v", err)
	}
	if storedCertPath != newCertPath {
		t.Fatalf("并发改写的路径应保留: got %q, want %q", storedCertPath, newCertPath)
	}
}

// 乐观锁形态②：tls_source 在「扫描→重载」窗口内被切走（file→manual）——
// 重载仍触发一次，但并发切换的 tls_source/内容不被 file 校验覆盖
//（路径引用架构无回写，重构 JJC-20261125-001）。
func TestReferencedCertWatch_optimisticLockSourceSwitched(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "opt2.crt", "opt2.key")
	database, reloads := ingestWatchFixture(t, "lb_opt_lock2", certPath, keyPath)

	referencedCertChangeBeforeReloadForTest = func(string) {
		if _, err := database.Exec(`UPDATE lb_rules SET tls_source='manual', tls_cert='manual-cert', tls_key='manual-key' WHERE caddy_id='lb_opt_lock2'`); err != nil {
			t.Errorf("并发切换 tls_source: %v", err)
		}
	}

	checkReferencedCertFiles() // 首扫建基线
	// 外部更新源文件为新合法配对 → 检出变化且校验通过 → 触发重载。
	changedCert, changedKey := matchingCertificatePair(t, "opt2-changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()

	if *reloads != 1 {
		t.Fatalf("文件变化应触发一次重载, reloads=%d", *reloads)
	}
	var storedSource string
	if err := database.QueryRow(`SELECT tls_source FROM lb_rules WHERE caddy_id='lb_opt_lock2'`).Scan(&storedSource); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedSource != "manual" {
		t.Fatalf("tls_source=%q, want manual（并发切换不被覆盖）", storedSource)
	}
	assertRuleMaterials(t, database, "lb_opt_lock2", "manual-cert", "manual-key")
}

// 乐观锁形态③：规则行在「扫描→重载」窗口内被并发删除——重载仍触发一次，
// 但已删行不被复活（路径引用架构无回写，重构 JJC-20261125-001）。
func TestReferencedCertWatch_optimisticLockRowDeleted(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "opt3.crt", "opt3.key")
	database, reloads := ingestWatchFixture(t, "lb_opt_lock3", certPath, keyPath)

	referencedCertChangeBeforeReloadForTest = func(string) {
		if _, err := database.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_opt_lock3'`); err != nil {
			t.Errorf("并发删除规则: %v", err)
		}
	}

	checkReferencedCertFiles() // 首扫建基线
	// 外部更新源文件为新合法配对 → 检出变化且校验通过 → 触发重载。
	changedCert, changedKey := matchingCertificatePair(t, "opt3-changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()

	if *reloads != 1 {
		t.Fatalf("文件变化应触发一次重载, reloads=%d", *reloads)
	}

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_opt_lock3'`).Scan(&count); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if count != 0 {
		t.Fatal("并发删除的行不得被复活")
	}
}
