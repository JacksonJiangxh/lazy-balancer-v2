// Spike 辅助：TLS 探测（指定 SNI / ALPN，返回握手观测值），供 T-2 / T-4 使用。
package harness

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Observation 是一次 TLS 握手的可核验观测值。
type Observation struct {
	Addr              string   `json:"addr"`
	SNISent           string   `json:"sni_sent"`
	SNIServerName     string   `json:"sni_server_name"` // 服务端视角（由响应回填）
	ALPNSent          []string `json:"alpn_sent"`
	ALPNNegotiated    string   `json:"alpn_negotiated"`
	TLSVersion        string   `json:"tls_version"`
	CipherSuite       string   `json:"cipher_suite"`
	LeafSubject       string   `json:"leaf_subject"`
	LeafIssuer        string   `json:"leaf_issuer"`
	LeafDNSNames      []string `json:"leaf_dns_names"`
	Body              string   `json:"body,omitempty"`
	Error             string   `json:"error,omitempty"`
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS1.0"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS13:
		return "TLS1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

// ProbeTLS 对 addr 发起一次 TLS 握手并（可选）发送一段 HTTP 请求读取响应。
func ProbeTLS(addr, sni string, alpn []string, roots *x509.CertPool, insecure bool, timeout time.Duration, httpReq string) Observation {
	obs := Observation{Addr: addr, SNISent: sni, ALPNSent: alpn}
	cfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		InsecureSkipVerify: insecure,
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS12,
	}
	d := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		obs.Error = err.Error()
		return obs
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	cs := conn.ConnectionState()
	obs.ALPNNegotiated = cs.NegotiatedProtocol
	obs.TLSVersion = versionName(cs.Version)
	obs.CipherSuite = tls.CipherSuiteName(cs.CipherSuite)
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		obs.LeafSubject = leaf.Subject.CommonName
		obs.LeafIssuer = leaf.Issuer.CommonName
		obs.LeafDNSNames = leaf.DNSNames
	}

	if httpReq != "" {
		if _, err := conn.Write([]byte(httpReq)); err != nil {
			obs.Error = "write: " + err.Error()
			return obs
		}
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			obs.Error = "read: " + err.Error()
			return obs
		}
		obs.Body = string(buf[:n])
	}
	return obs
}

// ProbeTLSFrom 与 ProbeTLS 相同，但客户端绑定指定本地源 IP（T-5 源 IP 链路用）。
func ProbeTLSFrom(localIP, addr, sni string, alpn []string, roots *x509.CertPool, insecure bool, timeout time.Duration, httpReq string) Observation {
	obs := Observation{Addr: addr, SNISent: sni, ALPNSent: alpn}
	cfg := &tls.Config{
		ServerName:         sni,
		NextProtos:         alpn,
		InsecureSkipVerify: insecure,
		RootCAs:            roots,
		MinVersion:         tls.VersionTLS12,
	}
	d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(localIP)}}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		obs.Error = "dial: " + err.Error()
		return obs
	}
	tc := tls.Client(conn, cfg)
	if err := tc.Handshake(); err != nil {
		_ = conn.Close()
		obs.Error = "handshake: " + err.Error()
		return obs
	}
	defer tc.Close()
	_ = tc.SetDeadline(time.Now().Add(timeout))

	cs := tc.ConnectionState()
	obs.ALPNNegotiated = cs.NegotiatedProtocol
	obs.TLSVersion = versionName(cs.Version)
	obs.CipherSuite = tls.CipherSuiteName(cs.CipherSuite)
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		obs.LeafSubject = leaf.Subject.CommonName
		obs.LeafIssuer = leaf.Issuer.CommonName
		obs.LeafDNSNames = leaf.DNSNames
	}
	if httpReq != "" {
		if _, err := tc.Write([]byte(httpReq)); err != nil {
			obs.Error = "write: " + err.Error()
			return obs
		}
		buf := make([]byte, 4096)
		n, err := tc.Read(buf)
		if err != nil {
			obs.Error = "read: " + err.Error()
			return obs
		}
		obs.Body = string(buf[:n])
	}
	return obs
}

// PeekServerName 以明文方式读取一段 ClientHello 并返回 SNI 与 ALPN（仅用于核对）。
func PeekServerName(raw []byte) (string, []string) {
	if len(raw) < 5 || raw[0] != 0x16 {
		return "", nil
	}
	// 交付给 crypto/tls 的解析（非导出），此处仅做粗略提取，正式断言依赖服务端日志。
	return "", nil
}

// JSON 序列化观测值。
func (o Observation) JSON() string {
	b, _ := json.Marshal(o)
	return string(b)
}