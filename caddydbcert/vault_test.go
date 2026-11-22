package caddydbcert

import (
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

func openTestDB(t *testing.T) *sql.DB {
	t.Helper()
	path := filepath.Join(t.TempDir(), "vault.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureVaultTables(context.Background(), db); err != nil {
		t.Fatalf("EnsureVaultTables: %v", err)
	}
	return db
}

func TestVaultUpsertLoadAndWatermark(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	dek := testDEK(t)
	// Inject the DEK via a local provider to keep this test independent of
	// process env. The wrapped field is empty for the env/dev key mode.
	var provider KeyProvider = staticProvider{dek: dek}
	wrapped := ""
	certPEM, keyPEM := newTestCertPair(t, "vault.example.test")

	fp, err := Upsert(ctx, db, provider, wrapped, "vault.example.test", "lb_1", certPEM, keyPEM, false, []string{"lb_1"})
	if err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if len(fp) != 64 {
		t.Fatalf("bad fingerprint %q", fp)
	}
	secrets, err := LoadSecrets(ctx, db, provider)
	if err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}
	if len(secrets) != 1 || secrets[0].CertPEM != certPEM || secrets[0].KeyPEM != keyPEM {
		t.Fatal("vault roundtrip mismatch")
	}
	if secrets[0].SinceVersion == 0 {
		t.Fatal("since_version trigger did not advance")
	}

	// Ciphertext columns must not contain plaintext PEM markers.
	var certCipher, keyCipher string
	if err := db.QueryRowContext(ctx, `SELECT cert_ciphertext, key_ciphertext FROM cert_secrets`).Scan(&certCipher, &keyCipher); err != nil {
		t.Fatalf("read ciphertext: %v", err)
	}
	if strings.Contains(certCipher, "BEGIN CERTIFICATE") || strings.Contains(keyCipher, "PRIVATE KEY") {
		t.Fatal("plaintext PEM found in vault columns")
	}

	// Soft delete removes the row from the active set but advances version.
	before := secrets[0].SinceVersion
	if _, err := Upsert(ctx, db, provider, wrapped, "vault.example.test", "lb_1", certPEM, keyPEM, true, nil); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	secrets, err = LoadSecrets(ctx, db, provider)
	if err != nil || len(secrets) != 0 {
		t.Fatalf("soft delete visible: %v %v", secrets, err)
	}
	after, err := CurrentVersion(ctx, db)
	if err != nil || after <= before {
		t.Fatalf("version did not advance on soft delete: before=%d after=%d err=%v", before, after, err)
	}

	if err := SetWatermark(ctx, db, "slave-1", 10, 20, 20, 15); err != nil {
		t.Fatalf("SetWatermark: %v", err)
	}
	var configV, certV, pulled, applied int64
	if err := db.QueryRowContext(ctx, `SELECT config_version, cert_version, last_pulled_version, last_applied_version
		FROM cert_sync_state WHERE node_id='slave-1'`).Scan(&configV, &certV, &pulled, &applied); err != nil {
		t.Fatalf("read watermark: %v", err)
	}
	if configV != 10 || certV != 20 || pulled != 20 || applied != 15 {
		t.Fatalf("watermark mismatch: %d %d %d %d", configV, certV, pulled, applied)
	}
}

// TestDualWatermarkPullVsApply closes P1-1 at the storage layer: a pull must
// advance last_pulled_version without touching last_applied_version, and only
// a confirmed apply advances the applied watermark.
func TestDualWatermarkPullVsApply(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)

	if err := RecordPulled(ctx, db, "local", 10, 7, 7); err != nil {
		t.Fatalf("RecordPulled: %v", err)
	}
	var configV, certV, pulled, applied int64
	read := func() {
		if err := db.QueryRowContext(ctx, `SELECT config_version, cert_version, last_pulled_version, last_applied_version
			FROM cert_sync_state WHERE node_id='local'`).Scan(&configV, &certV, &pulled, &applied); err != nil {
			t.Fatalf("read watermark: %v", err)
		}
	}
	read()
	if configV != 10 || certV != 7 || pulled != 7 || applied != 0 {
		t.Fatalf("after pull: %d %d %d %d (applied must stay 0)", configV, certV, pulled, applied)
	}

	// A second pull must not advance applied even though config/cert move.
	if err := RecordPulled(ctx, db, "local", 11, 9, 9); err != nil {
		t.Fatalf("RecordPulled 2: %v", err)
	}
	read()
	if applied != 0 {
		t.Fatalf("pull advanced applied watermark: %d", applied)
	}

	// Confirmed /load advances applied to the pulled cert version.
	if err := RecordApplied(ctx, db, "local", 9, 9); err != nil {
		t.Fatalf("RecordApplied: %v", err)
	}
	read()
	if configV != 11 || pulled != 9 || applied != 9 {
		t.Fatalf("after apply: %d %d %d %d", configV, certV, pulled, applied)
	}
}

func TestBackfillFromPlaintext(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	provider := staticProvider{dek: testDEK(t)}
	certPEM, keyPEM := newTestCertPair(t, "backfill.example.test")
	if _, err := db.ExecContext(ctx, `CREATE TABLE lb_rules (caddy_id TEXT, domain TEXT, enable_tls INTEGER, tls_source TEXT, tls_cert TEXT, tls_key TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE cert_jobs (rule_id TEXT, domain TEXT, cert_pem TEXT, key_pem TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO lb_rules VALUES ('lb_bf','backfill.example.test',1,'manual',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO cert_jobs VALUES ('lb_bf','backfill.example.test',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	n, err := BackfillFromPlaintext(ctx, db, provider, "")
	if err != nil {
		t.Fatalf("Backfill: %v", err)
	}
	// Same material in lb_rules and cert_jobs must be deduped by (domain, rule_id).
	if n != 1 {
		t.Fatalf("backfilled %d rows, want 1 (deduped)", n)
	}
	secrets, err := LoadSecrets(ctx, db, provider)
	if err != nil || len(secrets) != 1 {
		t.Fatalf("backfill load: %d %v", len(secrets), err)
	}
}

// TestExportImportVaultRowsVerbatim closes P0-1's ciphertext sync: rows cross
// the "wire" as ciphertext only, import writes them back verbatim, and the
// slave decrypts with its own (identical) provider.
func TestExportImportVaultRowsVerbatim(t *testing.T) {
	ctx := context.Background()
	master := openTestDB(t)
	slave := openTestDB(t)
	dek := testDEK(t)
	provider := staticProvider{dek: dek}
	certPEM, keyPEM := newTestCertPair(t, "sync.example.test")
	if _, err := Upsert(ctx, master, provider, "", "sync.example.test", "lb_sync", certPEM, keyPEM, false, []string{"lb_sync"}); err != nil {
		t.Fatal(err)
	}

	rows, version, err := ExportVaultRows(ctx, master)
	if err != nil || version == 0 || len(rows) != 1 {
		t.Fatalf("export: %d rows v=%d err=%v", len(rows), version, err)
	}
	if strings.Contains(rows[0].CertCiphertext, "BEGIN CERTIFICATE") || strings.Contains(rows[0].KeyCiphertext, "PRIVATE KEY") {
		t.Fatal("exported row carries plaintext PEM")
	}
	if err := ImportVaultRows(ctx, slave, rows); err != nil {
		t.Fatalf("import: %v", err)
	}
	secrets, err := LoadSecrets(ctx, slave, provider)
	if err != nil || len(secrets) != 1 || secrets[0].CertPEM != certPEM || secrets[0].KeyPEM != keyPEM {
		t.Fatalf("slave decrypt mismatch: %d %v", len(secrets), err)
	}
	// Re-import identical ciphertext must not bump the slave version.
	before, _ := CurrentVersionFrom(ctx, slave)
	if err := ImportVaultRows(ctx, slave, rows); err != nil {
		t.Fatal(err)
	}
	after, _ := CurrentVersionFrom(ctx, slave)
	if after != before {
		t.Fatalf("re-import bumped version: %d -> %d", before, after)
	}
}

// TestBackfillIdempotent guards the runtime vault refresh against version churn.
func TestBackfillIdempotent(t *testing.T) {
	ctx := context.Background()
	db := openTestDB(t)
	provider := staticProvider{dek: testDEK(t)}
	certPEM, keyPEM := newTestCertPair(t, "idem.example.test")
	for _, ddl := range []string{
		`CREATE TABLE lb_rules (caddy_id TEXT, domain TEXT, enable_tls INTEGER, tls_source TEXT, tls_cert TEXT, tls_key TEXT)`,
		`CREATE TABLE cert_jobs (rule_id TEXT, domain TEXT, cert_pem TEXT, key_pem TEXT)`,
	} {
		if _, err := db.ExecContext(ctx, ddl); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO lb_rules VALUES ('lb_i','idem.example.test',1,'manual',?,?)`, certPEM, keyPEM); err != nil {
		t.Fatal(err)
	}
	if _, err := BackfillFromPlaintext(ctx, db, provider, ""); err != nil {
		t.Fatal(err)
	}
	v1, _ := CurrentVersion(ctx, db)
	if _, err := BackfillFromPlaintext(ctx, db, provider, ""); err != nil {
		t.Fatal(err)
	}
	v2, _ := CurrentVersion(ctx, db)
	if v1 != v2 {
		t.Fatalf("idempotent backfill bumped version: %d -> %d", v1, v2)
	}
}

type staticProvider struct{ dek []byte }

func (p staticProvider) Ping(context.Context) error { return nil }

func (p staticProvider) UnwrapDEK(context.Context, string) ([]byte, error) {
	return append([]byte(nil), p.dek...), nil
}
