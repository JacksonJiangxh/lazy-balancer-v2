package services

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/caddydbcert"
)

// TestRender_fileRuleLoadFilesFromPaths 主路径：file 规则库中仅路径，渲染出
// load_files 引用源文件路径对，且不物化 .crt/.key 明文。
func TestRender_fileRuleLoadFilesFromPaths(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	certPEM, keyPEM := matchingCertificatePair(t, "file-render.example.test")
	certPath := filepath.Join(dir, "file-render.example.test.crt")
	keyPath := filepath.Join(dir, "file-render.example.test.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,strategy,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_file_render','file-render','file-render.example.test','http',9443,'weighted_round_robin',1,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_file_render','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	// 发布门：文件就绪的 file 规则必须发布（availableCerts 命中）。
	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	if _, ok := servers["http_9443"]; !ok {
		t.Fatalf("file 规则未被发布（server http_9443 缺失）——就绪判据未按文件解析评估")
	}
	// load_files 引用源文件路径对。
	tlsApp := apps["tls"].(map[string]interface{})
	certs := tlsApp["certificates"].(map[string]interface{})
	loadFiles := loadFilesAsMaps(certs["load_files"])
	found := false
	for _, raw := range loadFiles {
		tags := stringSlice(raw["tags"])
		if len(tags) == 1 && tags[0] == "lb_file_render" {
			if raw["certificate"] != certPath || raw["key"] != keyPath {
				t.Fatalf("load_files 引用的路径对错误: %#v", raw)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("file 规则未列入 load_files: %#v", loadFiles)
	}
	// 零物化：渲染不得把库内 PEM 写成物化文件（物化路径与源路径同形时会
	// 覆写源文件——库行没有 PEM，正常路径下 MaterializeCertPairs 不触发）。
	matCert, matKey := CertFilePaths("lb_file_render")
	if matCert == certPath {
		t.Fatalf("物化路径与源路径重合，渲染语义分叉")
	}
	if _, err := os.Stat(matCert); err == nil {
		t.Fatalf("file 规则的证书被物化: %s", matCert)
	}
	if _, err := os.Stat(matKey); err == nil {
		t.Fatalf("file 规则的私钥被物化: %s", matKey)
	}
}

// TestRender_fileRuleMissingFileNotPublished 保护门：文件缺失的 file 规则
// fail-closed 不发布（与既有「证书尚未就绪暂不发布」同语义）。
func TestRender_fileRuleMissingFileNotPublished(t *testing.T) {
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,strategy,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_file_gone','file-gone','file-gone.example.test','http',9444,'weighted_round_robin',1,1,'file','/app/certs/gone.crt','/app/certs/gone.key')`); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_file_gone','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	apps := cfg["apps"].(map[string]interface{})
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	if _, ok := servers["http_9444"]; ok {
		t.Fatalf("文件缺失的 file 规则被发布（应 fail-closed 跳过）")
	}
}

// TestRender_fileRuleBypassesVaultWhenDEKEnabled vault 分流：DEK 开启时
// manual 规则走 lb_db（vault 就绪集），file 规则仍按本地文件就绪并进 load_files
// —— file 模式就绪与内容只看本地文件，不消费 cert_secrets。
func TestRender_fileRuleBypassesVaultWhenDEKEnabled(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	ConfigureDBCertLoader(filepath.Join(t.TempDir(), "vault.db"), DefaultCertDEKEnv, "", "", "", "")
	t.Cleanup(func() { dbCertLoader.enabled.Store(false) })

	certPEM, keyPEM := matchingCertificatePair(t, "file-vault.example.test")
	certPath := filepath.Join(dir, "file-vault.example.test.crt")
	keyPath := filepath.Join(dir, "file-vault.example.test.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// file 规则：库中仅路径，vault（cert_secrets）无对应行——
	// 若 file 规则被 vault 分流吞掉，就绪集为空、规则不发布、load_files 为空。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,strategy,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_file_vault','file-vault','file-vault.example.test','http',9445,'weighted_round_robin',1,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_file_vault','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	apps := cfg["apps"].(map[string]interface{})
	tlsApp, ok := apps["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("DEK 开启时 apps.tls 缺失——file 规则未能贡献 certificates 节")
	}
	certs := tlsApp["certificates"].(map[string]interface{})
	if _, ok := certs["lb_db"]; !ok {
		t.Fatalf("DEK 开启时应发射 lb_db 节（manual/ACME 走 vault）: %#v", certs)
	}
	loadFiles := loadFilesAsMaps(certs["load_files"])
	found := false
	for _, raw := range loadFiles {
		tags := stringSlice(raw["tags"])
		if len(tags) == 1 && tags[0] == "lb_file_vault" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DEK 开启时 file 规则未列入 load_files（应绕过 vault 分流）: %#v", loadFiles)
	}
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	if _, ok := servers["http_9445"]; !ok {
		t.Fatalf("DEK 开启时 file 规则未被发布（不应被 vault 就绪集拦截）")
	}
}

// TestRender_fileRuleExcludedFromVaultEvenIfSecretExists 双加载器排除（吏部迁移
// 5433c1d2 接线）：甲路线下 cert_secrets 若存有 file 规则的密文行（历史回填残留
// 或从节点同步），该 rule_id 仍必须从 vault 就绪集排除——file 行只走 load_files，
// 不得同时被 lb_db 装载（SNI 选择歧义）。
func TestRender_fileRuleExcludedFromVaultEvenIfSecretExists(t *testing.T) {
	_, database := newClusterTestService(t)
	dir := useTemporaryCertDir(t)
	ConfigureDBCertLoader(filepath.Join(t.TempDir(), "vault.db"), DefaultCertDEKEnv, "", "", "", "")
	t.Cleanup(func() { dbCertLoader.enabled.Store(false) })
	if err := caddydbcert.EnsureVaultTables(context.Background(), database); err != nil {
		t.Fatalf("ensure vault tables: %v", err)
	}

	// Given：cert_secrets 存在 file 规则的活跃密文行（rule_id 与 tags 均指向它）。
	// 表结构需全部 NOT NULL 列（vaultAvailableRuleIDs 只查 rule_id/tags/deleted）。
	if _, err := database.Exec(`INSERT INTO cert_secrets (domain, rule_id, cert_ciphertext, key_ciphertext, wrapped_dek, fingerprint, tags, since_version, deleted)
		VALUES ('file-dup.example.test', 'lb_file_dup', 'cipher-c', 'cipher-k', '', 'fp-test', 'lb_file_dup', 0, 0)`); err != nil {
		t.Fatalf("seed cert_secrets: %v", err)
	}
	certPEM, keyPEM := matchingCertificatePair(t, "file-dup.example.test")
	certPath := filepath.Join(dir, "file-dup.example.test.crt")
	keyPath := filepath.Join(dir, "file-dup.example.test.key")
	if err := os.WriteFile(certPath, []byte(certPEM), 0644); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, []byte(keyPEM), 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,strategy,enabled,enable_tls,tls_source,tls_cert_path,tls_key_path)
		VALUES ('lb_file_dup','file-dup','file-dup.example.test','http',9446,'weighted_round_robin',1,1,'file',?,?)`, certPath, keyPath); err != nil {
		t.Fatalf("seed file rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_file_dup','127.0.0.1',9000,1,'http')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When
	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	apps := cfg["apps"].(map[string]interface{})
	tlsApp, ok := apps["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("apps.tls 缺失")
	}
	certs := tlsApp["certificates"].(map[string]interface{})
	loadFiles := loadFilesAsMaps(certs["load_files"])
	found := false
	for _, raw := range loadFiles {
		tags := stringSlice(raw["tags"])
		if len(tags) == 1 && tags[0] == "lb_file_dup" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cert_secrets 有密文行时 file 规则仍应走 load_files: %#v", loadFiles)
	}
	httpApp := apps["http"].(map[string]interface{})
	servers := httpApp["servers"].(map[string]interface{})
	if _, ok := servers["http_9446"]; !ok {
		t.Fatalf("cert_secrets 有密文行时 file 规则仍应按本地文件就绪并发布")
	}
}
