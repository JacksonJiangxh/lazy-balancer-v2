package services

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

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
	dbPath        string
	keyEnv        string
	kmsEndpoint   string
	kmsTokenEnv   string
	kmsClientCert string
	kmsClientKey  string
}

var dbCertLoader struct {
	settings atomic.Value // dbCertLoaderSettings
	enabled  atomic.Bool
}

// ConfigureDBCertLoader enables the vault loader. Call after the vault has
// been migrated; enabling without a DEK is rejected by the Caddy loader's
// Provision step, so a misconfiguration fails visible at /load time.
func ConfigureDBCertLoader(dbPath, keyEnv, kmsEndpoint, kmsTokenEnv, kmsClientCert, kmsClientKey string) {
	dbCertLoader.settings.Store(dbCertLoaderSettings{
		dbPath: dbPath, keyEnv: keyEnv,
		kmsEndpoint: kmsEndpoint, kmsTokenEnv: kmsTokenEnv,
		kmsClientCert: kmsClientCert, kmsClientKey: kmsClientKey,
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
	if s.kmsClientCert != "" {
		cfg["kms_client_cert"] = s.kmsClientCert
	}
	if s.kmsClientKey != "" {
		cfg["kms_client_key"] = s.kmsClientKey
	}
	return cfg
}

const (
	// DefaultCertDEKEnv is the single, fixed env name for the env-mode DEK.
	// P1-4: there is deliberately no LB_CERT_DEK_ENV indirection any more —
	// a deployment that only set the indirection name used to silently stay
	// on the plaintext load_files path.
	DefaultCertDEKEnv = "LB_CERT_DEK_B64"
	kmsEndpointEnv    = "LB_CERT_KMS_ENDPOINT"
)

// CertVaultDEKSource is the single enable predicate for Route A (P1-4):
// Route A is on iff a DEK value (LB_CERT_DEK_B64) or a KMS endpoint
// (LB_CERT_KMS_ENDPOINT) is explicitly configured. It returns the NAME of the
// source variable, never its value, so startup logs can disclose which knob
// enabled the vault without ever emitting key material. Empty = Route A off.
func CertVaultDEKSource() string {
	if os.Getenv(kmsEndpointEnv) != "" {
		return kmsEndpointEnv
	}
	if os.Getenv(DefaultCertDEKEnv) != "" {
		return DefaultCertDEKEnv
	}
	return ""
}

// InitCertVault creates the vault tables and backfills existing certificate
// material. It is a no-op unless a DEK source is configured, so existing
// deployments and unit tests keep their prior behavior.
//
// The DEK itself is never written to disk or logs. Env mode is for dev/CI;
// production uses the KMS endpoint with optional mTLS client certificate.
func InitCertVault(ctx context.Context) error {
	source := CertVaultDEKSource()
	if source == "" {
		Logf("info", "证书库（甲路线）未启用：未配置 %s / %s，保留 load_files 路径", DefaultCertDEKEnv, kmsEndpointEnv)
		return nil
	}
	// P1-4: log the source VARIABLE NAME only, never its value.
	Logf("info", "证书库（甲路线）启用，DEK 来源变量：%s（仅变量名，不记录值）", source)
	endpoint := os.Getenv(kmsEndpointEnv)
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
	// P1-4: fixed env name; no LB_CERT_DEK_ENV indirection.
	return caddydbcert.EnvKeyProvider{Env: DefaultCertDEKEnv}
}

// kmsHTTPClient builds the mTLS client for KMS unwrapping when a client cert
// pair is configured. Missing files degrade to ordinary TLS (the KMS endpoint
// itself is still HTTPS) rather than silently disabling encryption. The actual
// construction lives in caddydbcert so the panel backfill and the Caddy
// runtime loader share one client builder.
func kmsHTTPClient() *http.Client {
	return caddydbcert.BuildKMSHTTPClient(
		os.Getenv("LB_CERT_KMS_CLIENT_CERT"),
		os.Getenv("LB_CERT_KMS_CLIENT_KEY"),
		Logf,
	)
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

// vaultAvailableRuleIDs returns the set of rule IDs that have an active
// certificate in the local vault. Under Route A the Caddy TLS readiness gate
// (availableCerts) is derived from cert_secrets rather than the plaintext
// cert_jobs/lb_rules columns — the vault is the single source of truth.
// A missing vault schema (fresh node before first import) yields an empty set,
// which fail-closes TLS publication until certs are imported.
func vaultAvailableRuleIDs(store caddyConfigStore) map[string]bool {
	out := make(map[string]bool)
	rows, err := store.Query(`SELECT rule_id, tags FROM cert_secrets WHERE deleted=0`)
	if err != nil {
		Logf("warn", "读取证书库就绪集失败（甲路线 TLS 暂不发布）: %v", err)
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var ruleID, tags string
		if err := rows.Scan(&ruleID, &tags); err != nil {
			continue
		}
		if ruleID != "" {
			out[ruleID] = true
		}
		for _, tag := range strings.Split(tags, ",") {
			if tag = strings.TrimSpace(tag); tag != "" {
				out[tag] = true
			}
		}
	}
	return out
}

// CurrentCertVersion returns the monotonic certificate watermark, used by the
// dual-watermark sync state machine. Returns 0 when the vault is not enabled.
func CurrentCertVersion(ctx context.Context) (int64, error) {
	if !DBCertLoaderEnabled() || db.DB == nil {
		return 0, nil
	}
	return caddydbcert.CurrentVersion(ctx, db.DB)
}

// RecordPulledWatermark advances last_pulled_version after a snapshot has been
// pulled and integrity-verified (P1-1). It never advances last_applied_version.
// configVersion is the cluster snapshot version; certVersion is the master's
// certificate watermark carried in the snapshot.
func RecordPulledWatermark(ctx context.Context, configVersion, certVersion int64) {
	if !DBCertLoaderEnabled() || db.DB == nil {
		return
	}
	if err := caddydbcert.RecordPulled(ctx, db.DB, "local", configVersion, certVersion, certVersion); err != nil {
		Logf("warn", "拉取水位记账失败: %v", err)
	}
}

// RecordAppliedWatermark advances last_applied_version only after a confirmed
// successful POST /load (P1-1). A failed reload leaves the applied watermark
// unchanged so the next round replays. Called from the confirmed-load hook,
// not from the pull side.
func RecordAppliedWatermark(ctx context.Context) {
	if !DBCertLoaderEnabled() || db.DB == nil {
		return
	}
	certVersion, err := CurrentCertVersion(ctx)
	if err != nil {
		Logf("warn", "读取证书水位失败，跳过应用水位记账: %v", err)
		return
	}
	if err := caddydbcert.RecordApplied(ctx, db.DB, "local", certVersion, certVersion); err != nil {
		Logf("warn", "应用水位记账失败: %v", err)
	}
}

// caddyLoadSuccessHook is invoked by CaddyService only after a confirmed
// successful POST /load (not on same-config short-circuit or failure). The
// service layer installs it to advance the applied watermark; keeping the
// seam in services avoids a caddy.go -> certdb ordering dependency.
var caddyLoadSuccessHook func()

func SetCaddyLoadSuccessHook(fn func()) { caddyLoadSuccessHook = fn }
