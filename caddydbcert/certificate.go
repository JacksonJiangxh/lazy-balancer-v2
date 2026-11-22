package caddydbcert

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddytls"
)

const defaultDBPath = "/app/data/lazy-balancer.db"

func init() {
	caddy.RegisterModule(&DBCertificateLoader{})
}

// DBCertificateLoader is a Caddy TLS certificate loader that reads the local
// SQLite certificate vault (ciphertext columns) and decrypts in memory.
//
// Config example (rendered by the panel into the TLS app):
//
//	"tls": {"certificates": {"lb_db": {
//	    "db_path": "/app/data/lazy-balancer.db",
//	    "key_env": "LB_CERT_DEK_B64"
//	}}}
//
// It replaces "load_files" on the route-A main path: no .crt/.key on any node,
// no inline private key in the rendered JSON, no plaintext at rest. This holds
// only when Route A is enabled cluster-wide (every node has a DEK/KMS configured
// and understands vault_certs); during rolling upgrade the whole cluster stays
// on the legacy load_files path with byte-identical baseline behavior.
type DBCertificateLoader struct {
	DBPath string `json:"db_path,omitempty"`
	KeyEnv string `json:"key_env,omitempty"`

	// KMSEndpoint, when set, selects the KMS unwrapping provider instead of the
	// env provider. Credentials are never embedded here; the HTTP client uses
	// standard TLS (mTLS is configured at deployment via the panel's client).
	KMSEndpoint string `json:"kms_endpoint,omitempty"`
	KMSTokenEnv string `json:"kms_token_env,omitempty"`
	// KMSClientCert/KMSClientKey are file paths to a client certificate pair
	// for mTLS to the KMS endpoint. Paths (never key bytes) cross the config
	// boundary; Provision builds an http.Client that presents the pair so the
	// runtime KMS DEK unwrap is authenticated, not just encrypted.
	KMSClientCert string `json:"kms_client_cert,omitempty"`
	KMSClientKey  string `json:"kms_client_key,omitempty"`

	db       *sql.DB
	provider KeyProvider
}

// CaddyModule implements caddy.Module.
func (*DBCertificateLoader) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "tls.certificates.lb_db",
		New: func() caddy.Module { return new(DBCertificateLoader) },
	}
}

// Provision implements caddy.Provisioner.
func (l *DBCertificateLoader) Provision(_ caddy.Context) error {
	if l.DBPath == "" {
		l.DBPath = defaultDBPath
	}
	if _, err := os.Stat(l.DBPath); err != nil {
		return fmt.Errorf("caddydbcert: open vault %q: %w", l.DBPath, err)
	}
	if l.KMSEndpoint != "" {
		// P1-5: the runtime loader must present the same mTLS client as the
		// panel-side backfill, otherwise KMS deployments that require client
		// certs fail every DEK unwrap at LoadCertificates time.
		l.provider = KMSKeyProvider{
			Endpoint: l.KMSEndpoint,
			TokenEnv: l.KMSTokenEnv,
			Client:   BuildKMSHTTPClient(l.KMSClientCert, l.KMSClientKey, nil),
		}
	} else {
		l.provider = EnvKeyProvider{Env: l.KeyEnv}
	}
	// P0-2: probe provider availability with Ping, never with an empty wrapped
	// DEK. KMS providers reject an empty wrapped DEK by design, so the previous
	// UnwrapDEK(ctx, "") probe made every KMS deployment fail Provision.
	// Fail visible at config-load time: a loader without a DEK cannot serve
	// any certificate and must not silently fall back to plaintext files.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := l.provider.Ping(ctx); err != nil {
		return err
	}
	database, err := sql.Open("sqlite", l.DBPath)
	if err != nil {
		return fmt.Errorf("caddydbcert: open database: %w", err)
	}
	database.SetMaxOpenConns(2)
	// Verify the vault table is present; a fresh DB without migration is a
	// configuration error, not an empty-but-valid state.
	var name string
	err = database.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name='cert_secrets'`).Scan(&name)
	if err != nil {
		_ = database.Close()
		if errors.Is(err, sql.ErrNoRows) {
			return errors.New("caddydbcert: cert_secrets table missing; run vault migration first")
		}
		return fmt.Errorf("caddydbcert: inspect vault: %w", err)
	}
	l.db = database
	return nil
}

// LoadCertificates implements caddytls.CertificateLoader. Caddy calls this at
// TLS app provision time; its own cache handles SNI selection from the loaded
// certificates' SANs. There is deliberately no DB access in the hot handshake
// path — that is what keeps Route A cheap and race-free.
func (l *DBCertificateLoader) LoadCertificates() ([]caddytls.Certificate, error) {
	if l.db == nil || l.provider == nil {
		return nil, errors.New("caddydbcert: loader not provisioned")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	secrets, err := LoadSecrets(ctx, l.db, l.provider)
	if err != nil {
		return nil, err
	}
	out := make([]caddytls.Certificate, 0, len(secrets))
	for _, secret := range secrets {
		pair, err := tls.X509KeyPair([]byte(secret.CertPEM), []byte(secret.KeyPEM))
		if err != nil {
			return nil, fmt.Errorf("caddydbcert: build key pair for domain %q: %w", secret.Domain, err)
		}
		tags := append([]string(nil), secret.Tags...)
		if len(tags) == 0 && secret.RuleID != "" {
			tags = []string{secret.RuleID}
		}
		out = append(out, caddytls.Certificate{Certificate: pair, Tags: tags})
	}
	return out, nil
}

// Cleanup implements caddy.CleanerUpper.
func (l *DBCertificateLoader) Cleanup() error {
	if l.db != nil {
		err := l.db.Close()
		l.db = nil
		return err
	}
	return nil
}

// Interface guards.
var (
	_ caddytls.CertificateLoader = (*DBCertificateLoader)(nil)
	_ caddy.Provisioner          = (*DBCertificateLoader)(nil)
	_ caddy.CleanerUpper         = (*DBCertificateLoader)(nil)
)
