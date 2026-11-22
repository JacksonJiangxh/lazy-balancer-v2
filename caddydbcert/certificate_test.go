package caddydbcert

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

func testCaddyContext() caddy.Context {
	return caddy.Context{Context: context.Background()}
}

func TestDBCertificateLoaderLoadsFromVault(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "caddy-vault.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureVaultTables(ctx, db); err != nil {
		t.Fatal(err)
	}
	dek := testDEK(t)
	certPEM, keyPEM := newTestCertPair(t, "loader.example.test")
	if _, err := Upsert(ctx, db, staticProvider{dek: dek}, "", "loader.example.test", "lb_loader", certPEM, keyPEM, false, []string{"lb_loader"}); err != nil {
		t.Fatal(err)
	}

	t.Setenv("TEST_LOADER_DEK", base64.StdEncoding.EncodeToString(dek))
	loader := &DBCertificateLoader{DBPath: path, KeyEnv: "TEST_LOADER_DEK"}
	if err := loader.Provision(testCaddyContext()); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	defer loader.Cleanup()
	certs, err := loader.LoadCertificates()
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certificates, want 1", len(certs))
	}
	if len(certs[0].Leaf.DNSNames) == 0 || certs[0].Leaf.DNSNames[0] != "loader.example.test" {
		t.Fatalf("unexpected SNI names: %v", certs[0].Leaf.DNSNames)
	}
	if len(certs[0].Tags) != 1 || certs[0].Tags[0] != "lb_loader" {
		t.Fatalf("unexpected tags: %v", certs[0].Tags)
	}
}

// TestDBCertificateLoaderKMSProvision closes P0-2 at the loader level: a KMS
// that rejects an empty wrapped DEK on POST must not block Provision, because
// Provision probes availability via Ping (GET) instead.
func TestDBCertificateLoaderKMSProvision(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "kms-vault.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := EnsureVaultTables(ctx, db); err != nil {
		t.Fatal(err)
	}
	dek := testDEK(t)
	certPEM, keyPEM := newTestCertPair(t, "kms.example.test")
	if _, err := Upsert(ctx, db, staticProvider{dek: dek}, "wrapped-1", "kms.example.test", "lb_kms", certPEM, keyPEM, false, []string{"lb_kms"}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	encoded := base64.StdEncoding.EncodeToString(dek)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			// Simulate a real KMS: wrapped_dek="" is invalid, a real wrapped
			// DEK unwraps to the test key.
			var req struct {
				WrappedDEK string `json:"wrapped_dek"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req.WrappedDEK == "" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte("wrapped_dek required"))
				return
			}
			_, _ = w.Write([]byte(`{"dek":"` + encoded + `"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	loader := &DBCertificateLoader{DBPath: path, KMSEndpoint: srv.URL}
	if err := loader.Provision(testCaddyContext()); err != nil {
		t.Fatalf("KMS Provision must succeed via Ping, got: %v", err)
	}
	defer loader.Cleanup()
	certs, err := loader.LoadCertificates()
	if err != nil {
		t.Fatalf("LoadCertificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs, want 1", len(certs))
	}
}

func TestDBCertificateLoaderFailsWithoutDEK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureVaultTables(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	db.Close()
	t.Setenv("LB_CERT_DEK_B64", "")
	loader := &DBCertificateLoader{DBPath: path}
	if err := loader.Provision(testCaddyContext()); err == nil {
		t.Fatal("loader provisioned without a DEK")
	}
}
