package caddydbcert

import (
	"context"
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

func TestSealOpenRoundTripAndAADBinding(t *testing.T) {
	dek := testDEK(t)
	const domain = "vault.example.test"
	plain := []byte("certificate-or-key-material")

	sealed, err := Seal(dek, domain, "cert", plain)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	opened, err := Open(dek, domain, "cert", sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(opened) != string(plain) {
		t.Fatalf("roundtrip mismatch")
	}
	// A cert blob cannot be replayed as a key blob (AAD column binding).
	if _, err := Open(dek, domain, "key", sealed); err == nil {
		t.Fatal("column AAD binding not enforced")
	}
	// Nor can the same blob be used for another domain.
	if _, err := Open(dek, "other.example.test", "cert", sealed); err == nil {
		t.Fatal("domain AAD binding not enforced")
	}
	// Tampering with the GCM tag must be rejected.
	raw, _ := base64.StdEncoding.DecodeString(sealed)
	raw[len(raw)-1] ^= 0x01
	if _, err := Open(dek, domain, "cert", base64.StdEncoding.EncodeToString(raw)); err == nil {
		t.Fatal("GCM tag failure not rejected")
	}
	// Wrong key length must fail closed.
	if _, err := Open([]byte("short"), domain, "cert", sealed); err == nil {
		t.Fatal("short DEK accepted")
	}
}

func TestFingerprintIsDeterministicAndOrderSensitive(t *testing.T) {
	fp1 := Fingerprint("CERT", "KEY", "example.test")
	fp2 := Fingerprint("CERT", "KEY", "example.test")
	if fp1 != fp2 || len(fp1) != 64 {
		t.Fatalf("fingerprint unstable: %q %q", fp1, fp2)
	}
	if Fingerprint("KEY", "CERT", "example.test") == fp1 {
		t.Fatal("fingerprint must be order sensitive")
	}
	if Fingerprint("CERT", "KEY", "other.test") == fp1 {
		t.Fatal("fingerprint must bind domain")
	}
}

func TestEnvKeyProvider(t *testing.T) {
	const name = "TEST_LB_CERT_DEK_B64"
	dek := testDEK(t)
	t.Setenv(name, base64.StdEncoding.EncodeToString(dek))
	p := EnvKeyProvider{Env: name}
	got, err := p.UnwrapDEK(context.Background(), "")
	if err != nil {
		t.Fatalf("UnwrapDEK: %v", err)
	}
	if string(got) != string(dek) {
		t.Fatal("DEK mismatch")
	}
	t.Setenv(name, "not-base64")
	if _, err := p.UnwrapDEK(context.Background(), ""); err == nil {
		t.Fatal("invalid DEK accepted")
	}
	os.Unsetenv(name)
	if _, err := p.UnwrapDEK(context.Background(), ""); err != ErrNoKey {
		t.Fatalf("missing DEK: got %v, want ErrNoKey", err)
	}
}

func TestKMSErrorNeverEchoesBody(t *testing.T) {
	// A KMS error response may contain key material; ensure the error string
	// only reports the HTTP status.
	p := KMSKeyProvider{Endpoint: "http://127.0.0.1:1/unwrap"}
	_, err := p.UnwrapDEK(context.Background(), strings.Repeat("x", 16))
	if err == nil || strings.Contains(err.Error(), "xxx") {
		t.Fatalf("KMS error leaked or was nil: %v", err)
	}
}
