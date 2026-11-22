// Package caddydbcert implements the Caddy tls.certificates.lb_db module:
// a CertificateLoader that reads certificate material from the local SQLite
// certificate vault (ciphertext columns only) and decrypts it in memory.
//
// Route A (imperial ruling for JJC-20261122-003): the stock Caddy
// certificates.load_files path is replaced by this custom loader, so slave
// nodes never need .crt/.key files and the rendered JSON never carries an
// inline private key. Caddy itself performs SNI selection from the returned
// certificates (its cert cache matches SANs); there is no per-handshake DB
// query — see the Caddy v2.11.9 caddytls.CertificateLoader interface.
//
// SECURITY: no plaintext certificate/key is ever returned by the vault helpers
// to disk, logs, or JSON. Errors never embed plaintext. The DEK is supplied by
// a KeyProvider (env for dev/test, KMS HTTP for production); no key material is
// hardcoded in this repository.
package caddydbcert

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// dekBytes is the AES-256 key length.
	dekBytes = 32
	// nonceBytes is the GCM nonce length recommended by NIST SP 800-38D.
	nonceBytes = 12
)

// ErrNoKey is returned when no DEK source is configured. Callers must treat
// this as "vault disabled" and keep the legacy load_files path, never as a
// fallback to reading plaintext files on a slave node.
var ErrNoKey = errors.New("caddydbcert: no DEK provider configured")

// KeyProvider unwraps a wrapped DEK into the raw 32-byte AES-256 key.
// Implementations must never log or persist the returned bytes.
type KeyProvider interface {
	// Ping checks provider availability without needing any wrapped DEK.
	// Caddy's loader calls it at Provision time; an empty wrapped DEK must
	// never be used as a probe (KMS rejects it by design).
	Ping(ctx context.Context) error
	UnwrapDEK(ctx context.Context, wrappedDEK string) ([]byte, error)
}

// EnvKeyProvider reads a base64-encoded 32-byte DEK from an environment
// variable. It is intended for development, CI and isolated tests only; the
// wrappedDEK field is ignored (production uses KMSKeyProvider).
type EnvKeyProvider struct {
	Env string
}

func (p EnvKeyProvider) name() string {
	if p.Env == "" {
		return "LB_CERT_DEK_B64"
	}
	return p.Env
}

// Ping implements KeyProvider: env mode is available iff the DEK variable is
// present and well-formed. The value is never logged.
func (p EnvKeyProvider) Ping(ctx context.Context) error {
	_, err := p.UnwrapDEK(ctx, "")
	return err
}

func (p EnvKeyProvider) UnwrapDEK(_ context.Context, _ string) ([]byte, error) {
	name := p.name()
	raw := os.Getenv(name)
	if raw == "" {
		return nil, ErrNoKey
	}
	dek, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: decode %s: %w", name, err)
	}
	if len(dek) != dekBytes {
		return nil, fmt.Errorf("caddydbcert: %s must decode to %d bytes (got %d)", name, dekBytes, len(dek))
	}
	return dek, nil
}

// KMSKeyProvider unwraps a DEK through an external KMS HTTP endpoint. The
// wrapped DEK is sent as-is; the KMS response is JSON {"dek":"<base64>"}.
// TLS/mTLS and authorization are configured by the caller's http.Client —
// this package deliberately does not embed credentials.
type KMSKeyProvider struct {
	Endpoint string
	Client   *http.Client
	TokenEnv string // optional: env var holding a bearer token
}

// KMSClientLogger is the optional logging seam used by BuildKMSHTTPClient.
// The panel injects services.Logf; standalone/test binaries may leave it nil.
type KMSClientLogger func(level, format string, args ...any)

// BuildKMSHTTPClient constructs the mTLS HTTP client for KMS DEK unwrap from a
// client certificate/key pair. Both files must be present; on a load error it
// degrades to ordinary TLS (the KMS endpoint is still HTTPS) rather than
// silently disabling encryption. No credential bytes live in this package —
// only file paths cross the config boundary.
func BuildKMSHTTPClient(certFile, keyFile string, logf KMSClientLogger) *http.Client {
	base := &http.Client{Timeout: 10 * time.Second}
	if certFile == "" || keyFile == "" {
		return base
	}
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		if logf != nil {
			logf("error", "KMS mTLS 客户端证书加载失败，退回普通 TLS: %v", err)
		}
		return base
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{pair},
		}},
	}
}

// client returns the configured HTTP client (mTLS when supplied), never a
// package-global default that would drop client certificates.
func (p KMSKeyProvider) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Ping implements KeyProvider without an empty wrapped DEK: a GET to the
// KMS endpoint (optionally /health) must return a non-5xx response. A 5xx or
// transport error fails Provision visibly — no plaintext fallback.
func (p KMSKeyProvider) Ping(ctx context.Context) error {
	if p.Endpoint == "" {
		return ErrNoKey
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint, nil)
	if err != nil {
		return fmt.Errorf("caddydbcert: build KMS ping: %w", err)
	}
	if p.TokenEnv != "" {
		if token := os.Getenv(p.TokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("caddydbcert: KMS ping: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("caddydbcert: KMS ping returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (p KMSKeyProvider) UnwrapDEK(ctx context.Context, wrappedDEK string) ([]byte, error) {
	if p.Endpoint == "" {
		return nil, ErrNoKey
	}
	if wrappedDEK == "" {
		return nil, errors.New("caddydbcert: empty wrapped DEK")
	}
	body, err := json.Marshal(kmsUnwrapRequest{WrappedDEK: wrappedDEK})
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: encode KMS request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: build KMS request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if p.TokenEnv != "" {
		if token := os.Getenv(p.TokenEnv); token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	resp, err := p.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: KMS unwrap: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// Never echo the response body: a KMS error may contain key material.
		return nil, fmt.Errorf("caddydbcert: KMS unwrap returned HTTP %d", resp.StatusCode)
	}
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: read KMS response: %w", err)
	}
	dek, err := parseDekResponse(payload)
	if err != nil {
		return nil, err
	}
	if len(dek) != dekBytes {
		return nil, fmt.Errorf("caddydbcert: KMS DEK length=%d, want %d", len(dek), dekBytes)
	}
	return dek, nil
}

// aad binds a ciphertext to its column and domain, so a cert blob cannot be
// replayed as a key blob (and rows cannot be swapped between domains).
func aad(domain, column string) []byte {
	return []byte("lazy-balancer-v2|cert-vault|v1|" + domain + "|" + column)
}

// Seal encrypts plaintext with DEK using AES-256-GCM and returns
// base64(nonce || ciphertext || tag). The caller must supply the domain and
// column ("cert" or "key") so the AAD binding is unambiguous.
func Seal(dek []byte, domain, column string, plaintext []byte) (string, error) {
	if len(dek) != dekBytes {
		return "", fmt.Errorf("caddydbcert: DEK length=%d, want %d", len(dek), dekBytes)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, nonceBytes)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, aad(domain, column))
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. It never returns decrypted bytes on error.
func Open(dek []byte, domain, column, encoded string) ([]byte, error) {
	if len(dek) != dekBytes {
		return nil, fmt.Errorf("caddydbcert: DEK length=%d, want %d", len(dek), dekBytes)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: decode %s ciphertext: %w", column, err)
	}
	if len(raw) <= nonceBytes {
		return nil, fmt.Errorf("caddydbcert: truncated %s ciphertext", column)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := gcm.Open(nil, raw[:nonceBytes], raw[nonceBytes:], aad(domain, column))
	if err != nil {
		// GCM tag failure is a hard reject; do not include underlying detail.
		return nil, fmt.Errorf("caddydbcert: %s GCM authentication failed", column)
	}
	return plain, nil
}

// Fingerprint computes the single authoritative digest:
//
//	SHA256( cert_plain || key_plain || domain )
//
// It is calculated in memory only; nothing is written to disk or logs.
func Fingerprint(certPEM, keyPEM, domain string) string {
	h := sha256.New()
	_, _ = h.Write([]byte(certPEM))
	_, _ = h.Write([]byte(keyPEM))
	_, _ = h.Write([]byte(domain))
	return hex.EncodeToString(h.Sum(nil))
}

// kmsUnwrapRequest / kmsUnwrapResponse are the strict KMS wire contract.
// encoding/json (not hand-rolled string scanning) is used so that escapes,
// duplicate keys and trailing garbage follow one well-defined decoder path.
type kmsUnwrapRequest struct {
	WrappedDEK string `json:"wrapped_dek"`
}

type kmsUnwrapResponse struct {
	DEK string `json:"dek"`
}

// parseDekResponse strictly decodes {"dek":"<base64>"} and base64-decodes the
// key. A missing/empty dek field is rejected; the decoded value must be a
// 32-byte AES-256 key (checked by the caller).
func parseDekResponse(payload []byte) ([]byte, error) {
	var resp kmsUnwrapResponse
	dec := json.NewDecoder(bytes.NewReader(payload))
	if err := dec.Decode(&resp); err != nil {
		return nil, fmt.Errorf("caddydbcert: decode KMS response: %w", err)
	}
	if resp.DEK == "" {
		return nil, errors.New("caddydbcert: KMS response has no dek field")
	}
	dek, err := base64.StdEncoding.DecodeString(resp.DEK)
	if err != nil {
		return nil, fmt.Errorf("caddydbcert: decode KMS dek: %w", err)
	}
	return dek, nil
}
