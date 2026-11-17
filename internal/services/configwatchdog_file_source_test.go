package services

import (
	"database/sql"
	"os"
	"testing"
)

// 启用 file 行的看门狗判定与渲染层 availableCerts 同口径（内容入库即就绪）：
// 内容齐 → 不判漂移；内容缺 → 不就绪（沿用 manual 的 fail-visible）。
func TestConfigWatchdog_fileRuleReadyWhenContentStored(t *testing.T) {
	// Given：启用 file 规则，证书内容已入库
	_, database := newClusterTestService(t)
	ResetConfigDrift()
	t.Cleanup(ResetConfigDrift)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_wd_file_ready','wd-file-ready','http','file-ready.example.test',18091,'weighted_round_robin',1,10,2,3,2,1,'file','CERT-PEM','KEY-PEM')`); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	if _, err := database.Exec("INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_wd_file_ready','127.0.0.1',9000,1,'http')"); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When：Caddy 运行配置含该路由（渲染侧内容入库即有 TLS policy → 路由在位）
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_18091":{"listen":[":18091"],"routes":[{"@id":"lb_wd_file_ready","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：内容齐 → 不判漂移
	if drift := CurrentConfigDrift(); !drift.Consistent {
		t.Fatalf("启用 file 行内容入库即就绪，不得判漂移: %+v", drift)
	}
}

func TestConfigWatchdog_fileRuleNotReadyWhenContentMissing(t *testing.T) {
	// Given：启用 file 规则，只有摄取源路径、内容为空
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

	// When：Caddy 运行配置含该路由（渲染侧无证书跳过该规则 → 期望集不含它）
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"http_18092":{"listen":[":18092"],"routes":[{"@id":"lb_wd_file_missing","handle":[{"handler":"reverse_proxy"}]}]}}}}}`)
	checkConfigConsistency(server.URL)
	checkConfigConsistency(server.URL)

	// Then：内容缺 → 不就绪，判「多余」漂移并点名
	drift := CurrentConfigDrift()
	if drift.Consistent || len(drift.Extra) == 0 {
		t.Fatalf("启用 file 行内容缺失必须判不就绪（渲染无证跳过 → 多余）: %+v", drift)
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
		referencedCertIngestBeforeWriteForTest = nil
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

// 乐观锁形态①：摄取源路径在「扫描→回写」窗口内被并发改写——0 行命中必须
// 跳过回写（不得用旧路径内容污染新形态）并留痕 warn。
func TestReferencedCertWatch_optimisticLockPathRewritten(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "opt1.crt", "opt1.key")
	database, reloads := ingestWatchFixture(t, "lb_opt_lock1", certPath, keyPath)

	// 并发编辑在回写前改写摄取源路径（指向另一对真实文件）。
	newCertPath, newKeyPath := writeReferencedCertFiles(t, dir, "opt1-new.crt", "opt1-new.key")
	referencedCertIngestBeforeWriteForTest = func(string) {
		if _, err := database.Exec(`UPDATE lb_rules SET tls_cert_path=?, tls_key_path=? WHERE caddy_id='lb_opt_lock1'`, newCertPath, newKeyPath); err != nil {
			t.Errorf("并发改写路径: %v", err)
		}
	}

	checkReferencedCertFiles() // 首扫建基线
	// 外部更新源文件为新合法配对 → 本轮检出变化且校验通过，但回写前路径已被
	// 改写 → 乐观条件 0 行命中。
	changedCert, changedKey := matchingCertificatePair(t, "opt1-changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()

	assertRuleMaterials(t, database, "lb_opt_lock1", "old-cert", "old-key")
	var storedCertPath string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert_path,'') FROM lb_rules WHERE caddy_id='lb_opt_lock1'`).Scan(&storedCertPath); err != nil {
		t.Fatalf("read persisted path: %v", err)
	}
	if storedCertPath != newCertPath {
		t.Fatalf("并发改写的路径应保留: got %q, want %q", storedCertPath, newCertPath)
	}
	if *reloads != 0 {
		t.Fatalf("跳过回写不应触发重载, reloads=%d", *reloads)
	}
}

// 乐观锁形态②：tls_source 在「扫描→回写」窗口内被切走（file→manual）——
// 0 行命中必须跳过（manual 内容不得被 file 摄取覆盖）并留痕 warn。
func TestReferencedCertWatch_optimisticLockSourceSwitched(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "opt2.crt", "opt2.key")
	database, _ := ingestWatchFixture(t, "lb_opt_lock2", certPath, keyPath)

	referencedCertIngestBeforeWriteForTest = func(string) {
		if _, err := database.Exec(`UPDATE lb_rules SET tls_source='manual', tls_cert='manual-cert', tls_key='manual-key' WHERE caddy_id='lb_opt_lock2'`); err != nil {
			t.Errorf("并发切换 tls_source: %v", err)
		}
	}

	checkReferencedCertFiles() // 首扫建基线
	// 外部更新源文件为新合法配对 → 检出变化且校验通过，但回写前 tls_source 已
	// 被切走 → 乐观条件 0 行命中。
	changedCert, changedKey := matchingCertificatePair(t, "opt2-changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()

	var storedSource string
	if err := database.QueryRow(`SELECT tls_source FROM lb_rules WHERE caddy_id='lb_opt_lock2'`).Scan(&storedSource); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedSource != "manual" {
		t.Fatalf("tls_source=%q, want manual（并发切换不被摄取回写覆盖）", storedSource)
	}
	assertRuleMaterials(t, database, "lb_opt_lock2", "manual-cert", "manual-key")
}

// 乐观锁形态③：规则行在「扫描→回写」窗口内被并发删除——0 行命中必须跳过
// （不得复活已删行）并留痕 warn。
func TestReferencedCertWatch_optimisticLockRowDeleted(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "opt3.crt", "opt3.key")
	database, _ := ingestWatchFixture(t, "lb_opt_lock3", certPath, keyPath)

	referencedCertIngestBeforeWriteForTest = func(string) {
		if _, err := database.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_opt_lock3'`); err != nil {
			t.Errorf("并发删除规则: %v", err)
		}
	}

	checkReferencedCertFiles() // 首扫建基线
	// 外部更新源文件为新合法配对 → 检出变化且校验通过，但回写前行已被删除 →
	// 乐观条件 0 行命中。
	changedCert, changedKey := matchingCertificatePair(t, "opt3-changed.example.test")
	if err := os.WriteFile(certPath, []byte(changedCert), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(changedKey), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()

	var count int
	if err := database.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_opt_lock3'`).Scan(&count); err != nil {
		t.Fatalf("count rules: %v", err)
	}
	if count != 0 {
		t.Fatal("0 行命中不得复活已删除的规则行")
	}
}
