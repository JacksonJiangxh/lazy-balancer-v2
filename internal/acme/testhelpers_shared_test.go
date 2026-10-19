package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func newValidationTestClient(t *testing.T, server *httptest.Server, transport http.RoundTripper) *Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate account key: %v", err)
	}
	httpClient := server.Client()
	if transport != nil {
		httpClient = &http.Client{Transport: transport}
	}
	return &Client{
		DirectoryURL: server.URL + "/directory",
		Email:        "admin@example.com",
		acme: &acme.Client{
			Key:          key,
			DirectoryURL: server.URL + "/directory",
			HTTPClient:   httpClient,
			RetryBackoff: func(_ int, _ *http.Request, resp *http.Response) time.Duration {
				if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
					return 0
				}
				return min(time.Duration(1<<4)*time.Second, 10*time.Second)
			},
		},
	}
}
