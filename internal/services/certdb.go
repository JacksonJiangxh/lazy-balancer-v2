package services

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/caddydbcert"
	"lazy-balancer-v2/internal/db"
)

// Route A (imperial ruling JJC-20261122-003): the Caddy TLS app loads certs
// from the encrypted SQLite vault via the custom tls.certificates.lb_db
// module instead of certificates.load_files. The DB-rendered config never
// carries an inline private key and slave nodes need no .crt/.key files.
//
// The switch is off by default: a deployment that has not provisioned a DEK
// keeps the JJC-001 load_files path unchanged (no regression). Turning it on
// requires a real DEK source; there is deliberately no hardcoded fallback.
type dbCertLoaderSettings struct {
	dbPath      string
	keyEnv      string
	kmsEndpoint string
	kmsTokenEnv string
}

var dbCertLoader struct {
	settings atomic.Value // dbCertLoaderSettings
	enabled  atomic.Bool
}

// ConfigureDBCertLoader enables the vault loader. Call after the vault has
// been migrated; enabling without a DEK is rejected by the Caddy loader's
// Provision step, so a misconfiguration fails visible at /load time.
func ConfigureDBCertLoader(dbPath, keyEnv, kmsEndpoint, kmsTokenEnv string) {
	dbCertLoader.settings.Store(dbCertLoaderSettings{
		dbPath: dbPath, keyEnv: keyEnv,
		kmsEndpoint: kmsEndpoint, kmsTokenEnv: kmsTokenEnv,
	})
	dbCertLoader.enabled.Store(true)
}

// DBCertLoaderEnabled reports whether the rendered TLS app should use the
// custom vault loader instead of load_files.
func DBCertLoaderEnabled() bool { return dbCertLoader.enabled.Load() }

// dbCertLoaderConfig returns a JSON-ready fragment for the rendered TLS app.
func dbCertLoaderConfig() map[string]interface{} {
	s, _ := dbCertLoader.settings.Load().(dbCertLoaderSettings)
	cfg := map[string]interface{}{}
	if s.dbPath != "" {
		cfg["db_path"] = s.dbPath
	}
	if s.keyEnv != "" {
		cfg["key_env"] = s.keyEnv
	}
	if s.kmsEndpoint != "" {
		cfg["kms_endpoint"] = s.kmsEndpoint
	}
	if s.kmsTokenEnv != "" {
		cfg["kms_token_env"] = s.kmsTokenEnv
	}
	return cfg
}

// InitCertVault creates the vault tables and backfills existing certificate
// material. It is a no-op unless a DEK source is configured, so existing
// deployments and unit tests keep their prior behavior.
//
// The DEK itself is never written to disk or logs. Env mode is for dev/CI;
// production uses the KMS endpoint with optional mTLS client certificate.
func InitCertVault(ctx context.Context) error {
	endpoint := os.Getenv("LB_CERT_KMS_ENDPOINT")
	if endpoint == "" && os.Getenv("LB_CERT_DEK_B64") == "" {
		Logf("info", "证书库（甲路线）未启用：未配置 LB_CERT_DEK_B64 / LB_CERT_KMS_ENDPOINT，保留 load_files 路径")
		return nil
	}
	provider := certKeyProvider(endpoint)
	if err := caddydbcert.EnsureVaultTables(ctx, db.DB); err != nil {
		return fmt.Errorf("初始化证书库失败: %w", err)
	}
	wrapped := os.Getenv("LB_CERT_WRAPPED_DEK")
	count, err := caddydbcert.BackfillFromPlaintext(ctx, db.DB, provider, wrapped)
	if err != nil {
		return fmt.Errorf("证书库回填失败: %w", err)
	}
	Logf("info", "证书库回填完成：%d 条（密文列，明文未落新文件）", count)
	return nil
}

func certKeyProvider(endpoint string) caddydbcert.KeyProvider {
	if endpoint != "" {
		tokenEnv := os.Getenv("LB_CERT_KMS_TOKEN_ENV")
		return caddydbcert.KMSKeyProvider{
			Endpoint: endpoint,
			TokenEnv: tokenEnv,
			Client:   kmsHTTPClient(),
		}
	}
	return caddydbcert.EnvKeyProvider{Env: os.Getenv("LB_CERT_DEK_ENV")}
}

// kmsHTTPClient builds the mTLS client for KMS unwrapping when a client cert
// pair is configured. Missing files degrade to ordinary TLS (the KMS endpoint
// itself is still HTTPS) rather than silently disabling encryption.
func kmsHTTPClient() *http.Client {
	certFile := os.Getenv("LB_CERT_KMS_CLIENT_CERT")
	keyFile := os.Getenv("LB_CERT_KMS_CLIENT_KEY")
	if certFile == "" || keyFile == "" {
		return &http.Client{Timeout: 10 * time.Second}
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		Logf("error", "KMS mTLS 客户端证书加载失败，退回普通 TLS: %v", err)
		return &http.Client{Timeout: 10 * time.Second}
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		}},
	}
}

// ReloadFromDB is the single canonical "DB → render → validate → POST /load
// → save last-good" entry introduced by JJC-20261122-002. Callers must hold
// CaddyOpLock (or use the InLock variant at the call site). It is reused by
// applySnapshot and by certificate-change callbacks.
func ReloadFromDB(service *CaddyService, store, certSource caddyConfigStore) error {
	if service == nil {
		return fmt.Errorf("ReloadFromDB: Caddy 服务未初始化")
	}
	return service.ApplyConfigForce(generateCaddyConfigWithCertSource(store, certSource, true))
}

// CurrentCertVersion returns the monotonic certificate watermark, used by the
// dual-watermark sync state machine. Returns 0 when the vault is not enabled.
func CurrentCertVersion(ctx context.Context) (int64, error) {
	if !DBCertLoaderEnabled() || db.DB == nil {
		return 0, nil
	}
	return caddydbcert.CurrentVersion(ctx, db.DB)
}

// RecordAppliedWatermark records the config/cert dual watermark after a
// successful snapshot apply. The cert watermark is read from the local vault,
// never advanced by a failed /load; the next round replays from this value.
// Pull-side advancement of last_pulled_version on the master snapshot is a
// deployment-verification item (the vault is local to each node).
func RecordAppliedWatermark(ctx context.Context, configVersion int64) {
	if !DBCertLoaderEnabled() || db.DB == nil {
		return
	}
	certVersion, err := CurrentCertVersion(ctx)
	if err != nil {
		Logf("warn", "读取证书水位失败，跳过双水位记账: %v", err)
		return
	}
	if err := caddydbcert.SetWatermark(ctx, db.DB, "local", configVersion, certVersion, certVersion, certVersion); err != nil {
		Logf("warn", "双水位记账失败: %v", err)
	}
}
