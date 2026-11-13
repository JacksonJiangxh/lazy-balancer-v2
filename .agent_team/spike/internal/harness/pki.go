// Spike 辅助：本地自签 CA 与叶证书生成。仅测试用。
package harness

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// PKI 持有生成的证书路径。
type PKI struct {
	Dir      string
	CACert   string
	CAKey    string
	CAPool   *x509.CertPool
	Leaves   map[string]LeafPair
}

// LeafPair 是叶证书与私钥的 PEM 路径。
type LeafPair struct {
	Cert string
	Key  string
}

// NewPKI 在 dir 下生成一个自签 CA 与若干域名叶证书。
func NewPKI(dir string, dnsNames []string) (*PKI, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "spike-local-ca", Organization: []string{"spike"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}

	p := &PKI{
		Dir:    dir,
		CACert: filepath.Join(dir, "ca.pem"),
		CAKey:  filepath.Join(dir, "ca.key"),
		Leaves: map[string]LeafPair{},
	}
	if err := writePEM(p.CACert, "CERTIFICATE", caDER); err != nil {
		return nil, err
	}
	caKeyDER, err := x509.MarshalECPrivateKey(caKey)
	if err != nil {
		return nil, err
	}
	if err := writePEM(p.CAKey, "EC PRIVATE KEY", caKeyDER); err != nil {
		return nil, err
	}
	p.CAPool = x509.NewCertPool()
	p.CAPool.AddCert(caCert)

	for i, name := range dnsNames {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(int64(100 + i)),
			Subject:      pkix.Name{CommonName: name},
			DNSNames:     []string{name},
			IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &leafKey.PublicKey, caKey)
		if err != nil {
			return nil, err
		}
		certPath := filepath.Join(dir, name+".pem")
		keyPath := filepath.Join(dir, name+".key")
		if err := writePEM(certPath, "CERTIFICATE", der); err != nil {
			return nil, err
		}
		keyDER, err := x509.MarshalECPrivateKey(leafKey)
		if err != nil {
			return nil, err
		}
		if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
			return nil, err
		}
		p.Leaves[name] = LeafPair{Cert: certPath, Key: keyPath}
	}

	return p, nil
}

func writePEM(path, typ string, der []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &pem.Block{Type: typ, Bytes: der})
}