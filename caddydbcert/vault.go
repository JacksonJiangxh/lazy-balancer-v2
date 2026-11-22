package caddydbcert

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	// Use the same driver package as the panel module: database/sql driver
	// registration happens once per binary, so importing the same package in
	// both modules avoids a duplicate "sqlite" registration panic.
	_ "github.com/glebarez/go-sqlite"
)

// Secret is a decrypted in-memory certificate record. It is never serialized
// to disk or logs by this package.
type Secret struct {
	Domain       string
	RuleID       string
	CertPEM      string
	KeyPEM       string
	Fingerprint  string
	Tags         []string
	SinceVersion int64
}

// EnsureVaultTables creates the certificate vault and dual-watermark state
// tables. It is additive: existing tables/columns are untouched, so JJC-001's
// "referenced certs ride with the snapshot" logic keeps working.
func EnsureVaultTables(ctx context.Context, database *sql.DB) error {
	if database == nil {
		return errors.New("caddydbcert: nil database")
	}
	statements := []string{
		`CREATE TABLE IF NOT EXISTS cert_secrets (
			domain TEXT NOT NULL,
			rule_id TEXT NOT NULL DEFAULT '',
			cert_ciphertext TEXT NOT NULL,
			key_ciphertext TEXT NOT NULL,
			wrapped_dek TEXT NOT NULL DEFAULT '',
			fingerprint TEXT NOT NULL,
			tags TEXT NOT NULL DEFAULT '',
			since_version INTEGER NOT NULL DEFAULT 0,
			deleted INTEGER NOT NULL DEFAULT 0,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (domain, rule_id)
		)`,
		`CREATE TABLE IF NOT EXISTS cert_version_seq (
			id INTEGER PRIMARY KEY CHECK (id = 1),
			version INTEGER NOT NULL DEFAULT 0
		)`,
		`INSERT OR IGNORE INTO cert_version_seq (id, version) VALUES (1, 0)`,
		// since_version advances on every insert and on any material field
		// change (including soft delete). SQLite recursive triggers are off by
		// default; the guard additionally protects deployments that enable them.
		`CREATE TRIGGER IF NOT EXISTS cert_secrets_version_insert
		 AFTER INSERT ON cert_secrets BEGIN
			UPDATE cert_version_seq SET version = version + 1 WHERE id = 1;
			UPDATE cert_secrets SET since_version = (SELECT version FROM cert_version_seq)
			 WHERE rowid = NEW.rowid AND since_version = 0;
		 END`,
		`CREATE TRIGGER IF NOT EXISTS cert_secrets_version_update
		 AFTER UPDATE OF cert_ciphertext, key_ciphertext, wrapped_dek, fingerprint, deleted
		 ON cert_secrets
		 WHEN NEW.cert_ciphertext <> OLD.cert_ciphertext
		   OR NEW.key_ciphertext <> OLD.key_ciphertext
		   OR NEW.wrapped_dek <> OLD.wrapped_dek
		   OR NEW.fingerprint <> OLD.fingerprint
		   OR NEW.deleted <> OLD.deleted
		 BEGIN
			UPDATE cert_version_seq SET version = version + 1 WHERE id = 1;
			UPDATE cert_secrets SET since_version = (SELECT version FROM cert_version_seq)
			 WHERE rowid = NEW.rowid;
		 END`,
		`CREATE INDEX IF NOT EXISTS idx_cert_secrets_since ON cert_secrets(since_version)`,
		`CREATE TABLE IF NOT EXISTS cert_sync_state (
			node_id TEXT PRIMARY KEY,
			config_version INTEGER NOT NULL DEFAULT 0,
			cert_version INTEGER NOT NULL DEFAULT 0,
			last_pulled_version INTEGER NOT NULL DEFAULT 0,
			last_applied_version INTEGER NOT NULL DEFAULT 0,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
		)`,
	}
	for _, stmt := range statements {
		if _, err := database.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("caddydbcert: create vault schema: %w", err)
		}
	}
	return nil
}

// DBReader is the read-only SQL view shared by *sql.DB, *sql.Tx and the
// cluster snapshot store. Export helpers only need reads.
type DBReader interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// DB is the full SQL executor (reader + writer) so import helpers can join the
// caller's snapshot apply transaction.
type DB interface {
	DBReader
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

// VaultRow is one ciphertext-only vault row as carried in the cluster
// snapshot. It contains no plaintext and can cross the wire safely.
type VaultRow struct {
	Domain         string
	RuleID         string
	CertCiphertext string
	KeyCiphertext  string
	WrappedDEK     string
	Fingerprint    string
	Tags           string
	SinceVersion   int64
	Deleted        bool
}

// ExportVaultRows reads every cert_secrets row verbatim (ciphertext columns
// only) plus the current cert watermark. Used by the master to build the
// Route A snapshot; never decrypts anything.
func ExportVaultRows(ctx context.Context, database DBReader) ([]VaultRow, int64, error) {
	rows, err := database.QueryContext(ctx, `SELECT domain, rule_id, cert_ciphertext, key_ciphertext,
		wrapped_dek, fingerprint, tags, since_version, deleted FROM cert_secrets
		ORDER BY domain, rule_id`)
	if err != nil {
		return nil, 0, fmt.Errorf("caddydbcert: export vault rows: %w", err)
	}
	defer rows.Close()
	out := make([]VaultRow, 0)
	for rows.Next() {
		var r VaultRow
		var deleted int
		if err := rows.Scan(&r.Domain, &r.RuleID, &r.CertCiphertext, &r.KeyCiphertext,
			&r.WrappedDEK, &r.Fingerprint, &r.Tags, &r.SinceVersion, &deleted); err != nil {
			return nil, 0, fmt.Errorf("caddydbcert: scan vault row: %w", err)
		}
		r.Deleted = deleted != 0
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("caddydbcert: iterate vault rows: %w", err)
	}
	version, err := CurrentVersionFrom(ctx, database)
	if err != nil {
		return nil, 0, err
	}
	return out, version, nil
}

// CurrentVersionFrom reads the cert watermark from any SQL executor (DB or Tx).
func CurrentVersionFrom(ctx context.Context, database DBReader) (int64, error) {
	var version int64
	if err := database.QueryRowContext(ctx, `SELECT version FROM cert_version_seq WHERE id=1`).Scan(&version); err != nil {
		return 0, fmt.Errorf("caddydbcert: read cert version: %w", err)
	}
	return version, nil
}

// ImportVaultRows upserts ciphertext rows verbatim into cert_secrets. It never
// decrypts or re-encrypts: the slave keeps the exact ciphertext the master
// sealed, so no plaintext key material is ever written on the slave. Rows are
// inserted with since_version=0 so the local trigger assigns the slave's own
// monotonic version (identical ciphertext produces no update/no version bump).
func ImportVaultRows(ctx context.Context, database DB, rows []VaultRow) error {
	for _, r := range rows {
		del := 0
		if r.Deleted {
			del = 1
		}
		if _, err := database.ExecContext(ctx, `INSERT INTO cert_secrets
			(domain, rule_id, cert_ciphertext, key_ciphertext, wrapped_dek, fingerprint, tags, since_version, deleted, updated_at)
			VALUES (?,?,?,?,?,?,?,0,?,CURRENT_TIMESTAMP)
			ON CONFLICT(domain, rule_id) DO UPDATE SET
				cert_ciphertext=excluded.cert_ciphertext,
				key_ciphertext=excluded.key_ciphertext,
				wrapped_dek=excluded.wrapped_dek,
				fingerprint=excluded.fingerprint,
				tags=excluded.tags,
				deleted=excluded.deleted,
				updated_at=CURRENT_TIMESTAMP`,
			r.Domain, r.RuleID, r.CertCiphertext, r.KeyCiphertext,
			r.WrappedDEK, r.Fingerprint, r.Tags, del); err != nil {
			return fmt.Errorf("caddydbcert: import vault row %s/%s: %w", r.Domain, r.RuleID, err)
		}
	}
	return nil
}

// Upsert encrypts and stores one certificate. The plaintext exists only in
// the caller's memory and in the wrapped DEK provider's return value.
func Upsert(ctx context.Context, database *sql.DB, provider KeyProvider, wrappedDEK, domain, ruleID, certPEM, keyPEM string, deleted bool, tags []string) (string, error) {
	if provider == nil {
		return "", ErrNoKey
	}
	if domain == "" || certPEM == "" || keyPEM == "" {
		return "", errors.New("caddydbcert: empty domain/cert/key")
	}
	dek, err := provider.UnwrapDEK(ctx, wrappedDEK)
	if err != nil {
		return "", err
	}
	defer clearBytes(dek)
	certCipher, err := Seal(dek, domain, "cert", []byte(certPEM))
	if err != nil {
		return "", err
	}
	keyCipher, err := Seal(dek, domain, "key", []byte(keyPEM))
	if err != nil {
		return "", err
	}
	fp := Fingerprint(certPEM, keyPEM, domain)
	del := 0
	if deleted {
		del = 1
	}
	// Idempotency guard: a repeated backfill with unchanged material must not
	// re-encrypt (random GCM nonce) and bump since_version on every reload.
	// Skip the write when the stored fingerprint and deleted flag already match.
	var storedFP string
	var storedDeleted int
	if err := database.QueryRowContext(ctx, `SELECT fingerprint, deleted FROM cert_secrets WHERE domain=? AND rule_id=?`, domain, ruleID).Scan(&storedFP, &storedDeleted); err == nil {
		if storedFP == fp && storedDeleted == del {
			return fp, nil
		}
	}
	_, err = database.ExecContext(ctx, `INSERT INTO cert_secrets
		(domain, rule_id, cert_ciphertext, key_ciphertext, wrapped_dek, fingerprint, tags, deleted, updated_at)
		VALUES (?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(domain, rule_id) DO UPDATE SET
			cert_ciphertext=excluded.cert_ciphertext,
			key_ciphertext=excluded.key_ciphertext,
			wrapped_dek=excluded.wrapped_dek,
			fingerprint=excluded.fingerprint,
			tags=excluded.tags,
			deleted=excluded.deleted,
			updated_at=CURRENT_TIMESTAMP`,
		domain, ruleID, certCipher, keyCipher, wrappedDEK, fp, strings.Join(tags, ","), del)
	if err != nil {
		return "", fmt.Errorf("caddydbcert: upsert secret: %w", err)
	}
	return fp, nil
}

// LoadSecrets decrypts every active vault row. Decryption failures reject the
// whole batch (GCM tag failure == corrupted or tampered material).
func LoadSecrets(ctx context.Context, database *sql.DB, provider KeyProvider) ([]Secret, error) {
	if provider == nil {
		return nil, ErrNoKey
	}
	rows, err := database.QueryContext(ctx, `SELECT domain, rule_id, cert_ciphertext, key_ciphertext,
		wrapped_dek, fingerprint, tags, since_version FROM cert_secrets WHERE deleted=0`)
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: query secrets: %w", err)
	}
	defer rows.Close()
	var out []Secret
	// Most deployments wrap all rows with the same KMS key; memoize per
	// wrapped-DEK value to avoid one KMS round trip per certificate.
	dekCache := make(map[string][]byte)
	for rows.Next() {
		var domain, ruleID, certCipher, keyCipher, wrapped, fp, tags string
		var since int64
		if err := rows.Scan(&domain, &ruleID, &certCipher, &keyCipher, &wrapped, &fp, &tags, &since); err != nil {
			return nil, fmt.Errorf("caddydbcert: scan secret: %w", err)
		}
		dek, cached := dekCache[wrapped]
		if !cached {
			var err error
			dek, err = provider.UnwrapDEK(ctx, wrapped)
			if err != nil {
				return nil, err
			}
			dekCache[wrapped] = dek
		}
		certPEM, err := Open(dek, domain, "cert", certCipher)
		if err != nil {
			clearDEKCache(dekCache)
			return nil, err
		}
		keyPEM, err := Open(dek, domain, "key", keyCipher)
		if err != nil {
			clearDEKCache(dekCache)
			return nil, err
		}
		if Fingerprint(string(certPEM), string(keyPEM), domain) != fp {
			clearBytes(certPEM)
			clearBytes(keyPEM)
			clearDEKCache(dekCache)
			return nil, fmt.Errorf("caddydbcert: fingerprint mismatch for domain %q", domain)
		}
		var tagList []string
		if tags != "" {
			tagList = strings.Split(tags, ",")
		}
		out = append(out, Secret{
			Domain: domain, RuleID: ruleID,
			CertPEM: string(certPEM), KeyPEM: string(keyPEM),
			Fingerprint: fp, Tags: tagList, SinceVersion: since,
		})
	}
	if err := rows.Err(); err != nil {
		clearDEKCache(dekCache)
		return nil, fmt.Errorf("caddydbcert: iterate secrets: %w", err)
	}
	clearDEKCache(dekCache)
	return out, nil
}

func clearDEKCache(cache map[string][]byte) {
	for _, dek := range cache {
		clearBytes(dek)
	}
}

// CurrentVersion returns the monotonic certificate change watermark.
func CurrentVersion(ctx context.Context, database *sql.DB) (int64, error) {
	var version int64
	if err := database.QueryRowContext(ctx, `SELECT version FROM cert_version_seq WHERE id=1`).Scan(&version); err != nil {
		return 0, fmt.Errorf("caddydbcert: read cert version: %w", err)
	}
	return version, nil
}

// RecordPulled records config_version/cert_version/last_pulled_version after a
// snapshot has been successfully pulled and verified, WITHOUT touching
// last_applied_version (which only advances after a confirmed /load). It is a
// partial upsert: the applied watermark survives a pure pull.
func RecordPulled(ctx context.Context, database DB, node string, configVersion, certVersion, pulled int64) error {
	_, err := database.ExecContext(ctx, `INSERT INTO cert_sync_state
		(node_id, config_version, cert_version, last_pulled_version, last_applied_version, updated_at)
		VALUES (?,?,?,?,0,CURRENT_TIMESTAMP)
		ON CONFLICT(node_id) DO UPDATE SET
			config_version=excluded.config_version,
			cert_version=excluded.cert_version,
			last_pulled_version=excluded.last_pulled_version,
			updated_at=CURRENT_TIMESTAMP`,
		node, configVersion, certVersion, pulled)
	if err != nil {
		return fmt.Errorf("caddydbcert: record pulled watermark: %w", err)
	}
	return nil
}

// RecordApplied advances last_applied_version (and cert_version) only after a
// confirmed successful POST /load. A failed reload leaves the applied
// watermark at the previous value so the next round replays.
func RecordApplied(ctx context.Context, database DB, node string, certVersion, applied int64) error {
	_, err := database.ExecContext(ctx, `INSERT INTO cert_sync_state
		(node_id, config_version, cert_version, last_pulled_version, last_applied_version, updated_at)
		VALUES (?,0,?,0,?,CURRENT_TIMESTAMP)
		ON CONFLICT(node_id) DO UPDATE SET
			cert_version=excluded.cert_version,
			last_applied_version=excluded.last_applied_version,
			updated_at=CURRENT_TIMESTAMP`,
		node, certVersion, applied)
	if err != nil {
		return fmt.Errorf("caddydbcert: record applied watermark: %w", err)
	}
	return nil
}

// SetWatermark records config/cert/pull/apply watermarks for one node.
// Pull must never advance last_applied_version; the caller controls that.
func SetWatermark(ctx context.Context, database *sql.DB, node string, configVersion, certVersion, pulled, applied int64) error {
	_, err := database.ExecContext(ctx, `INSERT INTO cert_sync_state
		(node_id, config_version, cert_version, last_pulled_version, last_applied_version, updated_at)
		VALUES (?,?,?,?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(node_id) DO UPDATE SET
			config_version=excluded.config_version,
			cert_version=excluded.cert_version,
			last_pulled_version=excluded.last_pulled_version,
			last_applied_version=excluded.last_applied_version,
			updated_at=CURRENT_TIMESTAMP`,
		node, configVersion, certVersion, pulled, applied)
	if err != nil {
		return fmt.Errorf("caddydbcert: set watermark: %w", err)
	}
	return nil
}

// BackfillFromPlaintext encrypts existing manual/ACME certificate material
// into the vault. It is intentionally one-way and additive: the legacy
// columns are left in place so JJC-001's snapshot cert sync and the panel's
// existing readers keep working during migration. Clearing legacy plaintext
// is a separate, post-verification operation (see deployment notes).
func BackfillFromPlaintext(ctx context.Context, database *sql.DB, provider KeyProvider, wrappedDEK string) (int, error) {
	if provider == nil {
		return 0, ErrNoKey
	}
	type row struct{ domain, ruleID, certPEM, keyPEM string }
	var rows []row
	collect := func(query string) error {
		r, err := database.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		defer r.Close()
		for r.Next() {
			var item row
			if err := r.Scan(&item.ruleID, &item.domain, &item.certPEM, &item.keyPEM); err != nil {
				return err
			}
			if item.certPEM != "" && item.keyPEM != "" {
				rows = append(rows, item)
			}
		}
		return r.Err()
	}
	// Manual / referenced certs are stored inline in lb_rules; the file path
	// columns are deliberately ignored (slave nodes must not read files).
	if err := collect(`SELECT caddy_id,
		COALESCE(domain, caddy_id), COALESCE(tls_cert,''), COALESCE(tls_key,'')
		FROM lb_rules WHERE enable_tls=1 AND tls_source IN ('manual','file')`); err != nil {
		return 0, fmt.Errorf("caddydbcert: backfill manual certs: %w", err)
	}
	// ACME certs live in cert_jobs; fall back to the rule id when domain is empty.
	if err := collect(`SELECT j.rule_id,
		COALESCE(NULLIF(j.domain,''), j.rule_id), COALESCE(j.cert_pem,''), COALESCE(j.key_pem,'')
		FROM cert_jobs j WHERE COALESCE(j.cert_pem,'')<>'' AND COALESCE(j.key_pem,'')<>''`); err != nil {
		return 0, fmt.Errorf("caddydbcert: backfill acme certs: %w", err)
	}
	count := 0
	// The same material can appear both inline in lb_rules and in cert_jobs
	// (ACME deployments write both). The vault PK is (domain, rule_id), so
	// dedupe before encrypting: re-encrypting the same bytes twice would bump
	// since_version twice and trigger a redundant reload.
	seen := make(map[string]bool, len(rows))
	for _, item := range rows {
		key := item.domain + "\x00" + item.ruleID
		if seen[key] {
			continue
		}
		seen[key] = true
		if _, err := Upsert(ctx, database, provider, wrappedDEK, item.domain, item.ruleID, item.certPEM, item.keyPEM, false, []string{item.ruleID}); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

func clearBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
