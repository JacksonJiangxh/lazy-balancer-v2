package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
)

// 同一证书的签发者文案在任务列表与规则证书卡必须一致（此前任务列表只取
// Organization、证书卡取 "Org (CN)"）。单源=services.CertificateIssuerDisplay。
func TestCertificateIssuerDisplay_matchesRuleCertCard(t *testing.T) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Let's Encrypt"}, CommonName: "R3"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "issuer-display.test"},
		DNSNames:     []string{"issuer-display.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	want := "Let's Encrypt (R3)"
	if got := certificateIssuer(certPEM); got != want {
		t.Fatalf("任务列表 issuer=%q, want %q", got, want)
	}
	info := services.FormatRuleCertInfo(certPEM, "acme_dns", "issuer-display.test", "", 30, time.Now())
	if info.Issuer != want {
		t.Fatalf("规则证书卡 issuer=%q, want %q（同一证书两处文案必须一致）", info.Issuer, want)
	}
}
