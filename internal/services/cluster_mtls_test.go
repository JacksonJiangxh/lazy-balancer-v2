package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testClientCAPEM generates a self-signed certificate at test time. Only a
// syntactically valid PEM CERTIFICATE block is needed — AppendCertsFromPEM
// parses it into the pool; the guard logic under test does not verify chains.
func testClientCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "cluster-client-ca-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestConfigureClusterServerMTLSToggle(t *testing.T) {
	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caPath, testClientCAPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}

	// Empty path disables the guard and leaves TLS config untouched.
	if err := ConfigureClusterServerMTLS(""); err != nil {
		t.Fatalf("disable: %v", err)
	}
	if ClusterServerMTLSEnabled() {
		t.Fatal("guard enabled after configuring empty CA path")
	}
	cfg := &tls.Config{}
	ApplyClusterServerMTLS(cfg)
	if cfg.ClientAuth != tls.NoClientCert || cfg.ClientCAs != nil {
		t.Fatal("ApplyClusterServerMTLS mutated TLS config while disabled")
	}

	// A valid PEM CA enables the guard and sets VerifyClientCertIfGiven (not
	// RequireAndVerify, which would lock out browser UI on the shared listener).
	if err := ConfigureClusterServerMTLS(caPath); err != nil {
		t.Fatalf("enable: %v", err)
	}
	if !ClusterServerMTLSEnabled() {
		t.Fatal("guard not enabled after configuring CA")
	}
	ApplyClusterServerMTLS(cfg)
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth=%v, want VerifyClientCertIfGiven", cfg.ClientAuth)
	}
	if cfg.ClientCAs == nil {
		t.Fatal("ClientCAs not populated")
	}

	// A missing file fails visibly (never silently degrades to no mTLS).
	if err := ConfigureClusterServerMTLS(filepath.Join(dir, "missing.pem")); err == nil {
		t.Fatal("missing CA file did not return an error")
	}

	// Reset global state so other tests are unaffected.
	if err := ConfigureClusterServerMTLS(""); err != nil {
		t.Fatal(err)
	}
}
