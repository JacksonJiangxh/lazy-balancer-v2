package services

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
)

// Cluster-server mTLS (JJC-20261122-003 P1-2, gap B). The admin HTTPS listener
// is shared with the browser UI, so a global RequireAndVerifyClientCert would
// lock browsers out. Instead:
//   - the TLS config requests + verifies a client cert against a configured CA
//     pool (VerifyClientCertIfGiven), which populates tls.ConnectionState.VerifiedChains;
//   - the cluster MACHINE routes additionally require a verified chain through
//     middleware (see middleware.clusterClientCertGuard).
//
// The effective posture on cluster endpoints is RequireAndVerifyClientCert,
// without breaking browser access. mTLS is ADDED to — never a replacement for —
// the existing TOFU pin + X-Cluster-Token checks; until a CA is configured the
// guard is a no-op and the token posture is unchanged.
var clusterServerMTLS struct {
	enabled atomic.Bool
	pool    atomic.Value // *x509.CertPool
}

// ConfigureClusterServerMTLS loads the CA bundle used to verify cluster client
// certificates. A non-empty caFile enables the server-side guard; empty clears
// it (legacy TLS+pin+token posture). No credentials are stored in the repo —
// only a path is accepted here.
func ConfigureClusterServerMTLS(caFile string) error {
	if caFile == "" {
		clusterServerMTLS.enabled.Store(false)
		clusterServerMTLS.pool.Store((*x509.CertPool)(nil))
		return nil
	}
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return fmt.Errorf("读取集群客户端 CA 失败: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return errors.New("集群客户端 CA 文件不含有效 PEM 证书")
	}
	clusterServerMTLS.pool.Store(pool)
	clusterServerMTLS.enabled.Store(true)
	return nil
}

// ApplyClusterServerMTLS mutates the admin server TLS config to request and
// verify client certificates against the configured CA. Safe to call with a
// nil config (no-op). Browsers without a client cert still connect; the machine
// route guard is what turns verification into a requirement.
func ApplyClusterServerMTLS(tlsCfg *tls.Config) {
	if tlsCfg == nil || !clusterServerMTLS.enabled.Load() {
		return
	}
	pool, _ := clusterServerMTLS.pool.Load().(*x509.CertPool)
	if pool == nil {
		return
	}
	tlsCfg.ClientCAs = pool
	tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven
}

// ClusterServerMTLSEnabled reports whether the machine-route guard must
// require a verified client certificate.
func ClusterServerMTLSEnabled() bool { return clusterServerMTLS.enabled.Load() }
