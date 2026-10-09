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

// Given: 一条 tls_source=file 规则且证书文件被外部更新
// When: checkReferencedCertFiles 逐轮扫描
// Then: 首扫建基线不重载；文件变化后触发一次强制重载；无变化不再重载
func TestCheckReferencedCertFiles_triggersReloadOnChange(t *testing.T) {
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

	// 首扫：仅建基线，不应触发重载。
	checkReferencedCertFiles()
	if reloads != 0 {
		t.Fatalf("首扫不应重载, reloads=%d", reloads)
	}
	// 内容未变：仍不重载。
	checkReferencedCertFiles()
	if reloads != 0 {
		t.Fatalf("内容未变不应重载, reloads=%d", reloads)
	}
	// 外部更新证书文件：下一轮检出变化并重载一次。
	if err := os.WriteFile(certPath, []byte("updated-cert-content"), 0644); err != nil {
		t.Fatalf("rewrite cert: %v", err)
	}
	checkReferencedCertFiles()
	if reloads != 1 {
		t.Fatalf("证书变化应触发一次重载, reloads=%d", reloads)
	}
	// 无进一步变化：不应重复重载。
	checkReferencedCertFiles()
	if reloads != 1 {
		t.Fatalf("无变化不应重复重载, reloads=%d", reloads)
	}
}
