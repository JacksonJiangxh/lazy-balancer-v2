package services

import (
	"context"
	"os"
	"regexp"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// 续期扫描把 waiting_ca 任务转回 queued 时，CA 冷却残留必须与 markJobWaitingCA
// 的上限分支同字段集清理：否则后续以非 429 原因失败时，failed 行仍带旧 429
// 错误码与过期冷却时刻（UI/导出/备份看到与终态矛盾的字段）。
func TestRenewalRequeueClearsCAAntiAbuseFields(t *testing.T) {
	// Given：一条临期 waiting_ca 任务，冷却已到期但仍带 429 期残留字段
	_, database := newClusterTestService(t)
	ResetCAQueueManagerForTest()
	InitCAQueueManager(func() error { return nil })
	GetCAQueueManager().Start()
	manager := GetCAQueueManager()
	t.Cleanup(ResetCAQueueManagerForTest)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_wait_renew','wait-renew','wait-renew.example.com','http',8080,1,1,'acme_dns')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,ca_available_after,last_error_code,ca_provider_id)
		VALUES ('lb_wait_renew','wait-renew.example.com','waiting_ca',datetime('now','+1 day'),datetime('now','-5 minutes'),'429',1)`); err != nil {
		t.Fatalf("seed waiting_ca job: %v", err)
	}
	transitioned := make(chan struct{})
	release := make(chan struct{})
	manager.beforeEnqueue = func() {
		close(transitioned)
		<-release
	}
	resetCertificateServiceForTest(t)
	go func() {
		if err := NewCertificateService().renewExpiringCertificates(); err != nil {
			t.Logf("renew scan returned: %v", err)
		}
	}()

	// When：巡检完成状态迁移（beforeEnqueue 在迁移后、入队前阻塞）
	<-transitioned

	// Then：queued 且两列已清空
	var status string
	var caAvailableAfter, lastErrorCode any
	if err := database.QueryRow("SELECT status, ca_available_after, last_error_code FROM cert_jobs WHERE rule_id='lb_wait_renew'").
		Scan(&status, &caAvailableAfter, &lastErrorCode); err != nil {
		t.Fatalf("read requeued job: %v", err)
	}
	close(release)
	if status != "queued" {
		t.Fatalf("status=%q, want queued", status)
	}
	if caAvailableAfter != nil || lastErrorCode != nil {
		t.Fatalf("ca_available_after=%v last_error_code=%v, want 双 NULL（冷却残留必须随 requeue 清除）", caAvailableAfter, lastErrorCode)
	}
}

// 带外 NULL（直改库/外来快照）不得让 CA 提供商列表/单行读取 500：
// 可空列按 DDL 默认（max_concurrent=1、min_interval_ms=2000）与 fail-closed
// 语义（enabled 读 0，与所有 `WHERE enabled=1` 取用门一致）读出。
func TestCAProviderNullableColumnsReadWithDefaults(t *testing.T) {
	// Given
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO ca_providers (name,provider,directory_url,credentials) VALUES ('nulled','zerossl',?,'{}')`, ZeroSSLDirectoryURL)
	if err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	providerID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("read provider id: %v", err)
	}
	if _, err := database.Exec(`UPDATE ca_providers SET max_concurrent=NULL, min_interval_ms=NULL, enabled=NULL WHERE id=?`, providerID); err != nil {
		t.Fatalf("null out nullable columns: %v", err)
	}

	// When
	listed, err := NewCAProviderService().ListCAProviders()
	if err != nil {
		t.Fatalf("ListCAProviders 不得因带外 NULL 失败: %v", err)
	}
	got, err := NewCAProviderService().GetCAProvider(int(providerID))
	if err != nil {
		t.Fatalf("GetCAProvider 不得因带外 NULL 失败: %v", err)
	}

	// Then
	if got.MaxConcurrent != 1 || got.MinIntervalMS != 2000 || got.Enabled {
		t.Fatalf("NULL 列读取 max_concurrent=%d min_interval_ms=%d enabled=%v, want 1/2000/false",
			got.MaxConcurrent, got.MinIntervalMS, got.Enabled)
	}
	found := false
	for _, provider := range listed {
		if provider.ID == int(providerID) {
			found = true
			if provider.MaxConcurrent != 1 || provider.MinIntervalMS != 2000 || provider.Enabled {
				t.Fatalf("列表 NULL 列读取 max_concurrent=%d min_interval_ms=%d enabled=%v, want 1/2000/false",
					provider.MaxConcurrent, provider.MinIntervalMS, provider.Enabled)
			}
		}
	}
	if !found {
		t.Fatalf("列表缺少 provider %d", providerID)
	}
	// enabled=NULL 的提供商不得被队列取用（fail-closed）：显式加载必须报「已禁用」。
	if _, err := loadCAProvider(int(providerID)); err == nil {
		t.Fatal("enabled=NULL 的提供商被 loadCAProvider 取用，want 拒绝（fail-closed）")
	}
}

// issued 任务的到期时间回填必须写规范墙钟串（UTC、无时区标识），与 API 文档
// 声明的格式一致：直接绑定 time.Time 会落成 `+00:00` 形态，做
// time.Parse("2006-01-02 15:04:05") 的消费方会失败。
func TestBackfillIssuedCertExpiryWritesCanonicalWallClock(t *testing.T) {
	// Given：issued 行带材料但 expires_at 为 NULL
	jobID, _ := seedCertificateJob(t, "issued")
	notAfter := time.Date(2027, 5, 6, 7, 8, 9, 0, time.UTC)
	certPEM := testCertificatePEM(t, notAfter)
	if _, err := db.DB.Exec("UPDATE cert_jobs SET cert_pem=?, key_pem='persisted-key', expires_at=NULL WHERE id=?", certPEM, jobID); err != nil {
		t.Fatalf("seed issued material: %v", err)
	}

	// When
	filled, err := backfillIssuedCertExpiry(context.Background())

	// Then：回填 1 行且文本为无时区的 UTC 墙钟串
	if err != nil {
		t.Fatalf("backfillIssuedCertExpiry: %v", err)
	}
	if filled != 1 {
		t.Fatalf("filled=%d, want 1", filled)
	}
	// DATETIME 声明列被驱动读取时会还原为 time.Time，scan 进 string 会得到
	// RFC3339——这里读 CAST(... AS TEXT) 取得库里真实文本（API 契约口径）。
	var stored string
	if err := db.DB.QueryRow("SELECT CAST(expires_at AS TEXT) FROM cert_jobs WHERE id=?", jobID).Scan(&stored); err != nil {
		t.Fatalf("read backfilled expires_at: %v", err)
	}
	if !regexp.MustCompile(`^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$`).MatchString(stored) {
		t.Fatalf("expires_at=%q, want UTC 墙钟串（无时区标识）", stored)
	}
	parsed, parseErr := time.Parse("2006-01-02 15:04:05", stored)
	if parseErr != nil {
		t.Fatalf("expires_at=%q 无法按文档布局解析: %v", stored, parseErr)
	}
	if !parsed.Equal(notAfter) {
		t.Fatalf("expires_at=%q 与证书 NotAfter %v 不一致", stored, notAfter)
	}
}

// TCP/layer4 规则不能终止 TLS：写侧/迁移/导入已清零其 TLS 字段，带外保留
// enable_tls 的行不得在渲染时物化私钥文件，也不得列进 apps.tls.load_files。
func TestRenderSkipsTLSCertificatesForTCPRules(t *testing.T) {
	// Given：TCP 规则带外保留 manual TLS 材料
	_, database := newClusterTestService(t)
	useTemporaryCertDir(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,strategy,enabled,enable_tls,tls_source,tls_cert,tls_key)
		VALUES ('lb_tcp_tls','tcp-tls','tcp-tls.example.com','tcp',9443,'weighted_round_robin',1,1,'manual','CERT-PEM','KEY-PEM')`); err != nil {
		t.Fatalf("seed tcp rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled,protocol) VALUES ('lb_tcp_tls','127.0.0.1',9000,1,'tcp')`); err != nil {
		t.Fatalf("seed tcp upstream: %v", err)
	}

	// When
	cfg := generateCaddyConfigFromStore(database)

	// Then：不物化文件、不进 load_files
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	certPath, keyPath := CertFilePaths("lb_tcp_tls")
	if _, err := os.Stat(certPath); err == nil {
		t.Fatalf("TCP 规则的证书文件被物化: %s", certPath)
	}
	if _, err := os.Stat(keyPath); err == nil {
		t.Fatalf("TCP 规则的私钥文件被物化: %s", keyPath)
	}
	apps, ok := cfg["apps"].(map[string]interface{})
	if !ok {
		return
	}
	tlsApp, ok := apps["tls"].(map[string]interface{})
	if !ok {
		return
	}
	certs, ok := tlsApp["certificates"].(map[string]interface{})
	if !ok {
		return
	}
	for _, raw := range loadFilesAsMaps(certs["load_files"]) {
		if tags := stringSlice(raw["tags"]); len(tags) == 1 && tags[0] == "lb_tcp_tls" {
			t.Fatalf("TCP 规则被列入 load_files: %#v", raw)
		}
	}
}

// loadFilesAsMaps 归一 load_files 的两种可能形态（[]map / []interface）。
func loadFilesAsMaps(value any) []map[string]interface{} {
	switch files := value.(type) {
	case []map[string]interface{}:
		return files
	case []interface{}:
		out := make([]map[string]interface{}, 0, len(files))
		for _, raw := range files {
			if file, ok := raw.(map[string]interface{}); ok {
				out = append(out, file)
			}
		}
		return out
	}
	return nil
}

// stringSlice 归一 tags 的两种可能形态（[]string / []interface）。
func stringSlice(value any) []string {
	switch tags := value.(type) {
	case []string:
		return tags
	case []interface{}:
		out := make([]string, 0, len(tags))
		for _, raw := range tags {
			if tag, ok := raw.(string); ok {
				out = append(out, tag)
			}
		}
		return out
	}
	return nil
}
