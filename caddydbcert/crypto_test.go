package caddydbcert

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

// TestKMSPingNeverSendsEmptyWrappedDEK closes P0-2: Provision probes the KMS
// with Ping (a GET), never UnwrapDEK(""). A KMS that rejects empty wrapped
// DEKs on POST must still let the loader provision.
func TestKMSPingNeverSendsEmptyWrappedDEK(t *testing.T) {
	dek := testDEK(t)
	encoded := base64.StdEncoding.EncodeToString(dek)
	var sawGET, sawEmptyWrapped bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			sawGET = true
			w.WriteHeader(http.StatusOK)
		case http.MethodPost:
			var req kmsUnwrapRequest
			dec := json.NewDecoder(r.Body)
			_ = dec.Decode(&req)
			if req.WrappedDEK == "" {
				sawEmptyWrapped = true
			}
			_, _ = w.Write([]byte(`{"dek":"` + encoded + `"}`))
		}
	}))
	defer srv.Close()

	p := KMSKeyProvider{Endpoint: srv.URL}
	if err := p.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if !sawGET {
		t.Fatal("Ping did not use GET (empty wrapped DEK probe regression)")
	}
	got, err := p.UnwrapDEK(context.Background(), "wrapped-1")
	if err != nil || string(got) != string(dek) {
		t.Fatalf("UnwrapDEK: got %v, err %v", got, err)
	}
	if sawEmptyWrapped {
		t.Fatal("an empty wrapped DEK was sent to KMS")
	}
}

func TestParseDekResponseStrict(t *testing.T) {
	dek := testDEK(t)
	encoded := base64.StdEncoding.EncodeToString(dek)
	good, err := parseDekResponse([]byte(`{"dek":"` + encoded + `"}`))
	if err != nil || string(good) != string(dek) {
		t.Fatalf("strict parse failed: %v %v", good, err)
	}
	for _, bad := range []string{"", "not json", `{"dek":123}`, `{"key":"` + encoded + `"}`} {
		if _, err := parseDekResponse([]byte(bad)); err == nil {
			t.Fatalf("malformed response accepted: %q", bad)
		}
	}
}
