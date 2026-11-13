// Spike 上游：一个真实的 TLS 终结服务器，模拟「透传上游自带反代与证书」。
// 记录每个连接的 SNI / ALPN / 客户端地址，供 T-2、T-4 断言 SNI/ALPN 保真。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"
)

type record struct {
	SNI        string `json:"sni"`
	ALPN       string `json:"alpn"`
	ALPNOffers string `json:"alpn_offers"`
	Remote     string `json:"remote"`
	TLSVersion string `json:"tls_version"`
	Cipher     string `json:"cipher"`
	Path       string `json:"path,omitempty"`
	UA         string `json:"ua,omitempty"`
	XFwdFor    string `json:"x_forwarded_for,omitempty"`
	At         string `json:"at"`
}

type store struct {
	mu   sync.Mutex
	recs []record
	file string
}

func (s *store) add(r record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recs = append(s.recs, r)
	if s.file != "" {
		f, err := os.OpenFile(s.file, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err == nil {
			b, _ := json.Marshal(r)
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
		}
	}
	log.Printf("UPSTREAM %s sni=%q alpn=%q remote=%s", r.Path, r.SNI, r.ALPN, r.Remote)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:10443", "listen address")
	certFile := flag.String("cert", "", "server cert PEM")
	keyFile := flag.String("key", "", "server key PEM")
	logFile := flag.String("log", "", "JSONL record file")
	flag.Parse()

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("load keypair: %v", err)
	}

	st := &store{file: *logFile}

	httpSrv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS != nil {
				st.add(record{
					SNI:        r.TLS.ServerName,
					ALPN:       r.TLS.NegotiatedProtocol,
					Remote:     r.RemoteAddr,
					TLSVersion: tls.VersionName(r.TLS.Version),
					Cipher:     tls.CipherSuiteName(r.TLS.CipherSuite),
					Path:       r.URL.Path,
					UA:         r.UserAgent(),
					XFwdFor:    r.Header.Get("X-Forwarded-For"),
					At:         time.Now().Format(time.RFC3339Nano),
				})
			}
			w.Header().Set("X-Spike-Identity", "upstream-passthrough")
			w.WriteHeader(200)
			_, _ = w.Write([]byte("UPSTREAM-OK"))
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2", "http/1.1"},
			MinVersion:   tls.VersionTLS12,
		},
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen %s: %v", *addr, err)
	}
	fmt.Printf("upstream listening on %s\n", ln.Addr())

	// 记录 ClientHello 中的 SNI / ALPN（即使后续 HTTP 层未走到）
	httpSrv.TLSConfig.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		st.add(record{
			SNI:        hello.ServerName,
			ALPNOffers: fmt.Sprint(hello.SupportedProtos),
			Remote:     hello.Conn.RemoteAddr().String(),
			Path:       "clienthello",
			TLSVersion: fmt.Sprintf("0x%04x", hello.SupportedVersions),
			At:         time.Now().Format(time.RFC3339Nano),
		})
		return nil, nil
	}

	tlsLn := tls.NewListener(ln, httpSrv.TLSConfig)
	if err := httpSrv.Serve(tlsLn); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

var _ = x509.NewCertPool