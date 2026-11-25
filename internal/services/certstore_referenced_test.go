package services

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// writeReferencedCertFiles 在 dir 内落一对配对的证书/私钥文件，返回两个路径。
func writeReferencedCertFiles(t *testing.T, dir, certName, keyName string) (string, string) {
	t.Helper()
	certPEM, keyPEM := matchingCertificatePair(t, "ref.example.test")
	certPath := filepath.Join(dir, certName)
	keyPath := filepath.Join(dir, keyName)
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return certPath, keyPath
}

// Given: 位于证书目录内的合法成品证书文件
// When: ResolveReferencedCertPath 校验
// Then: 通过并返回归一路径
func TestResolveReferencedCertPath_acceptsFileInsideCertDir(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, _ := writeReferencedCertFiles(t, dir, "a.crt", "a.key")

	resolved, err := ResolveReferencedCertPath(certPath)
	if err != nil {
		t.Fatalf("resolve inside cert dir: %v", err)
	}
	if resolved != filepath.Clean(certPath) {
		t.Fatalf("resolved=%q, want %q", resolved, filepath.Clean(certPath))
	}
}

// Given: 各类越界/非法路径
// When: ResolveReferencedCertPath 校验
// Then: 全部拒绝（白名单前缀边界、目录穿越、空串、相对路径、目录、不存在）
func TestResolveReferencedCertPath_rejectsEscapes(t *testing.T) {
	dir := useTemporaryCertDir(t)
	// 目录内放一个真实文件，用于「.. 穿越」时目标存在性不成为唯一拒绝理由。
	realPath, _ := writeReferencedCertFiles(t, dir, "real.crt", "real.key")

	cases := []struct {
		name string
		path string
	}{
		{"空串", ""},
		{"相对路径", "certs/a.crt"},
		{"目录穿越逃逸", filepath.Join(dir, "..", "outside.crt")},
		{"同前缀兄弟目录绕过", dir + "-evil/a.crt"},
		{"不存在的文件", filepath.Join(dir, "missing.crt")},
		{"目录而非文件", dir},
		{"目录内嵌套穿越", filepath.Join(dir, "sub", "..", "..", "evil.crt")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ResolveReferencedCertPath(tc.path); err == nil {
				t.Fatalf("path %q 应被拒绝但通过了", tc.path)
			}
		})
	}

	// 合法路径仍应通过（确保拒绝不是「全部拒绝」的假阳性）。
	if _, err := ResolveReferencedCertPath(realPath); err != nil {
		t.Fatalf("真实文件路径应通过: %v", err)
	}
}

// Given: 目录内软链指向目录外的文件
// When: ResolveReferencedCertPath 解析符号链接后复核边界
// Then: 拒绝（Windows 无创建软链权限时跳过）
func TestResolveReferencedCertPath_rejectsSymlinkEscape(t *testing.T) {
	dir := useTemporaryCertDir(t)
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "outside.crt")
	if err := os.WriteFile(outsideFile, []byte("not-a-real-cert"), 0644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	linkPath := filepath.Join(dir, "link.crt")
	if err := os.Symlink(outsideFile, linkPath); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("当前环境无法创建符号链接，跳过: %v", err)
		}
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := ResolveReferencedCertPath(linkPath); err == nil {
		t.Fatal("指向目录外的软链应被拒绝")
	}
}

// Given: 证书与私钥不配对（用两套不同密钥对拼装）
// When: LoadReferencedCertificate 读取并配对校验
// Then: 报错（tls.X509KeyPair 失败）
func TestLoadReferencedCertificate_rejectsMismatchedPair(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, _ := writeReferencedCertFiles(t, dir, "a.crt", "a.key")
	_, otherKeyPath := writeReferencedCertFiles(t, dir, "b.crt", "b.key")

	if _, err := LoadReferencedCertificate(certPath, otherKeyPath); err == nil {
		t.Fatal("证书与私钥不匹配时应报错")
	}
}

// Given: 一对配对文件
// When: LoadReferencedCertificate 校验
// Then: 成功且返回读取到的 PEM 内容
func TestLoadReferencedCertificate_acceptsMatchingPair(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "pair.crt", "pair.key")

	referenced, err := LoadReferencedCertificate(certPath, keyPath)
	if err != nil {
		t.Fatalf("load matching pair: %v", err)
	}
	if referenced.CertPath == "" || referenced.KeyPath == "" || referenced.CertPEM == "" || referenced.KeyPEM == "" {
		t.Fatalf("返回内容不完整: %+v", referenced)
	}
}

// Given: 证书文件内容变化
// When: ReferencedCertFileDigest 计算指纹
// Then: 内容不同指纹不同；文件缺失时返回 missing 前缀指纹
func TestReferencedCertFileDigest_detectsContentChange(t *testing.T) {
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "d.crt", "d.key")

	before := ReferencedCertFileDigest(certPath, keyPath)
	if before == "" || before[:7] == "missing" {
		t.Fatalf("初始指纹异常: %q", before)
	}
	if err := os.WriteFile(certPath, []byte("changed-content"), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	after := ReferencedCertFileDigest(certPath, keyPath)
	if before == after {
		t.Fatal("证书内容变化后指纹应不同")
	}
	if missing := ReferencedCertFileDigest(filepath.Join(dir, "nope.crt"), keyPath); missing[:7] != "missing" {
		t.Fatalf("缺失文件应返回 missing 指纹, got %q", missing)
	}
}

// Given: 一条 tls_source=file 规则（库中仅路径）且源文件被外部更新为新配对
// When: checkReferencedCertFiles 逐轮扫描
// Then: 首扫建基线不重载；文件变化后强制重载一次（重构 JJC-20261125-001：
// 路径引用架构库不存 PEM，运行时渲染层 load_files 直接读文件，检出变化只
// 重载不再摄取回写）；无变化不再重载
func TestCheckReferencedCertFiles_ingestsChangedFiles(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "watch.crt", "watch.key")

	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path)
		VALUES ('lb_refcert','ref','http','ref.test',19443,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed referenced rule: %v", err)
	}

	reloads := 0
	SetReferencedCertReload(func() error { reloads++; return nil })
	ResetReferencedCertWatch()
	t.Cleanup(func() {
		SetReferencedCertReload(nil)
		ResetReferencedCertWatch()
	})

	// 首扫：仅建基线，不重载。
	checkReferencedCertFiles()
	if reloads != 0 {
		t.Fatalf("首扫不应重载, reloads=%d", reloads)
	}
	// 内容未变：仍不重载。
	checkReferencedCertFiles()
	if reloads != 0 {
		t.Fatalf("内容未变不应重载, reloads=%d", reloads)
	}
	// 外部更新为新配对文件：下一轮检出变化，强制重载一次（不回写 DB）。
	newCertPEM, newKeyPEM := matchingCertificatePair(t, "updated.example.test")
	if err := os.WriteFile(certPath, []byte(newCertPEM), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(newKeyPEM), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()
	if reloads != 1 {
		t.Fatalf("证书变化应触发一次重载, reloads=%d", reloads)
	}
	var storedCert, storedKey string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_refcert'`).Scan(&storedCert, &storedKey); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedCert != "" || storedKey != "" {
		t.Fatal("路径引用架构下看门狗不得回写 PEM 内容（运行时从文件读取）")
	}
	// 无进一步变化：不应重复重载。
	checkReferencedCertFiles()
	if reloads != 1 {
		t.Fatalf("无变化不应重复重载, reloads=%d", reloads)
	}
}

// Given: tls_source=file 规则且源文件被删除（digest=missing:）
// When: checkReferencedCertFiles 扫描
// Then: 跳过摄取（数据库保留上次有效内容 last-good）、不重载
func TestCheckReferencedCertFiles_missingFilesSkipsIngest(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "gone.crt", "gone.key")

	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path, tls_cert, tls_key)
		VALUES ('lb_refgone','ref-gone','http','ref-gone.test',19444,1,'file',?,?,'old-cert','old-key')`, certPath, keyPath); err != nil {
		t.Fatalf("seed referenced rule: %v", err)
	}

	reloads := 0
	SetReferencedCertReload(func() error { reloads++; return nil })
	ResetReferencedCertWatch()
	t.Cleanup(func() {
		SetReferencedCertReload(nil)
		ResetReferencedCertWatch()
	})

	checkReferencedCertFiles() // 首扫建基线
	if err := os.Remove(keyPath); err != nil {
		t.Fatalf("remove key file: %v", err)
	}
	checkReferencedCertFiles()
	if reloads != 0 {
		t.Fatalf("文件缺失不应触发重载, reloads=%d", reloads)
	}
	var storedCert, storedKey string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_refgone'`).Scan(&storedCert, &storedKey); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedCert != "old-cert" || storedKey != "old-key" {
		t.Fatal("文件缺失时数据库应保留上次有效内容（last-good）")
	}
}

// Given: tls_source=file 规则且源文件更新为不配对内容（外部工具更新到一半）
// When: checkReferencedCertFiles 扫描
// Then: 校验失败跳过摄取（数据库保留 last-good）、不重载
func TestCheckReferencedCertFiles_invalidPairSkipsIngest(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "half.crt", "half.key")

	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path, tls_cert, tls_key)
		VALUES ('lb_refhalf','ref-half','http','ref-half.test',19445,1,'file',?,?,'old-cert','old-key')`, certPath, keyPath); err != nil {
		t.Fatalf("seed referenced rule: %v", err)
	}

	reloads := 0
	SetReferencedCertReload(func() error { reloads++; return nil })
	ResetReferencedCertWatch()
	t.Cleanup(func() {
		SetReferencedCertReload(nil)
		ResetReferencedCertWatch()
	})

	checkReferencedCertFiles() // 首扫建基线
	// 仅换私钥为新密钥对（与现存证书不配对，模拟外部工具写了一半）。
	_, newKeyPEM := matchingCertificatePair(t, "other.example.test")
	if err := os.WriteFile(keyPath, []byte(newKeyPEM), 0600); err != nil {
		t.Fatalf("rewrite key: %v", err)
	}
	checkReferencedCertFiles()
	if reloads != 0 {
		t.Fatalf("配对无效不应触发重载, reloads=%d", reloads)
	}
	var storedCert, storedKey string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_refhalf'`).Scan(&storedCert, &storedKey); err != nil {
		t.Fatalf("read persisted rule: %v", err)
	}
	if storedCert != "old-cert" || storedKey != "old-key" {
		t.Fatal("配对无效时数据库应保留上次有效内容（last-good）")
	}
}

// Given: tls_source=file 规则且内容已入库（旧版本存量行）
// When: MaterializeAllCertsFromDB 启动物化
// Then: 重构（JJC-20261125-001）后 file 行不再物化——渲染层 load_files 直接
// 引用源路径，物化语义仅保留给 manual
func TestMaterializeAllCertsFromDB_materializesReferencedRule(t *testing.T) {
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	wantCert, wantKey := matchingCertificatePair(t, "refmat.example.test")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path, tls_cert, tls_key)
		VALUES ('lb_refmat','ref-mat','http','refmat.example.test',19446,1,'file','/app/certs/refmat.example.test.crt','/app/certs/refmat.example.test.key',?,?)`,
		wantCert, wantKey); err != nil {
		t.Fatalf("seed referenced rule: %v", err)
	}

	MaterializeAllCertsFromDB()

	certPath, keyPath := CertFilePaths("lb_refmat")
	if _, err := os.Stat(certPath); err == nil {
		t.Fatal("file 行不应被启动物化（路径引用架构：渲染层直接引用源文件）")
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatal("file 行的私钥不应被启动物化")
	}
}

// Given: 旧版本/旧备份还原产生的「只有摄取源路径、内容为空」的 file 行
// When: IngestMissingReferencedCerts 启动回填
// Then: 本机源文件可读时内容入库；文件缺失的行保持空内容（幂等不命中已有内容行）
func TestIngestMissingReferencedCerts_backfillsPathOnlyRows(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	certPath, keyPath := writeReferencedCertFiles(t, dir, "backfill.crt", "backfill.key")
	gonePath := filepath.Join(dir, "gone.crt")
	goneKeyPath := filepath.Join(dir, "gone.key")
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path)
		VALUES ('lb_refbackfill','ref-backfill','http','backfill.test',19447,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed backfill rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path)
		VALUES ('lb_refgone2','ref-gone2','http','gone2.test',19448,1,'file',?,?)`, gonePath, goneKeyPath); err != nil {
		t.Fatalf("seed missing-file rule: %v", err)
	}

	recovered := IngestMissingReferencedCerts()
	if recovered != 1 {
		t.Fatalf("recovered=%d, want 1（可读行回填、缺失行跳过）", recovered)
	}
	var storedCert, storedKey string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,''), COALESCE(tls_key,'') FROM lb_rules WHERE caddy_id='lb_refbackfill'`).Scan(&storedCert, &storedKey); err != nil {
		t.Fatalf("read backfilled rule: %v", err)
	}
	wantCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read source cert: %v", err)
	}
	if storedCert != string(wantCert) {
		t.Fatal("回填内容应与源文件一致")
	}
	var emptyCert string
	if err := database.QueryRow(`SELECT COALESCE(tls_cert,'') FROM lb_rules WHERE caddy_id='lb_refgone2'`).Scan(&emptyCert); err != nil {
		t.Fatalf("read missing-file rule: %v", err)
	}
	if emptyCert != "" {
		t.Fatal("源文件缺失的行不应回填（保持空内容，由 EnableRule 门拦截）")
	}
	// 幂等：内容已非空的行不命中。
	if again := IngestMissingReferencedCerts(); again != 0 {
		t.Fatalf("重跑应零命中, recovered=%d", again)
	}
}

// Given: tls_source=file 规则（库中仅路径，无内联内容）
// When: GenerateRuleServerContext 构建单规则服务器上下文
// Then: 按路径引用判有证——文件当前可读可解析即产出 tls app，load_files
// 直接引用库中路径对（路径引用架构，重构 JJC-20261125-001）
func TestGenerateRuleServerContext_referencedRuleHasCertLikeManual(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	wantCert, wantKey := matchingCertificatePair(t, "refctx.example.test")
	certPath := filepath.Join(dir, "refctx.example.test.crt")
	keyPath := filepath.Join(dir, "refctx.example.test.key")
	if err := os.WriteFile(certPath, []byte(wantCert), 0644); err != nil {
		t.Fatalf("write source cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(wantKey), 0600); err != nil {
		t.Fatalf("write source key: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, domain, listen_port, enable_tls, tls_source, tls_cert_path, tls_key_path, enabled)
		VALUES ('lb_refctx','ref-ctx','http','refctx.example.test',19449,1,'file',?,?,'0')`,
		certPath, keyPath); err != nil {
		t.Fatalf("seed referenced rule: %v", err)
	}

	ctx := GenerateRuleServerContext("lb_refctx", 19449, "http", "refctx.example.test")
	apps, _ := ctx["apps"].(map[string]interface{})
	if apps == nil {
		t.Fatal("apps 缺失")
	}
	tlsApp, ok := apps["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("file 模式路径就绪应判有证并产出 tls app，got %v", ctx)
	}
	certs, _ := tlsApp["certificates"].(map[string]interface{})
	loadFiles, _ := certs["load_files"].([]interface{})
	if len(loadFiles) != 1 {
		t.Fatalf("load_files=%v, want 1 项", loadFiles)
	}
	entry, _ := loadFiles[0].(map[string]interface{})
	if entry["certificate"] != certPath || entry["key"] != keyPath {
		t.Fatalf("load_files 应引用源文件路径 (%v,%v), want (%s,%s)", entry["certificate"], entry["key"], certPath, keyPath)
	}
}
