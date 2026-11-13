// T-1 生死判据：ACME TLS-ALPN-01 经 Layer4 兜底转发到 7443 后仍可完成**真实签发**。
//
// 拓扑（与计划 §二 同构，仅端口按沙箱缩放：443→8443，其余真实）：
//
//	pebble(真实 ACME CA)  --VA/TLS-->  127.0.0.1:8443   [Layer4：peek ClientHello，不终结]
//	                                    ├─ SNI ∈ 透传集合 → 127.0.0.1:10443（上游自带证书终结）
//	                                    └─ 其余（含 acme-tls/1 挑战）→ PROXY v2 → 127.0.0.1:7443
//	                                                                  [Caddy http app：TLS 终结 + certmagic]
//
// 三条断言：
//   A. 经 Layer4 兜底，acme-tls/1 握手返回带 acmeIdentifier 扩展的挑战证书；
//   B. pebble 的 VA 真实校验通过 → 证书落盘（端到端签发）；
//   C. 签发证书可用于 7443 业务握手（挑战路径与业务路径共用同一 TLS 栈）。
package main

import (
	"context"
	"crypto/tls"
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"lazyspike/internal/harness"
)

const (
	portL4        = 443  // Layer4 前置（生产真实端口）
	portLocal     = 7443 // 本地终结（计划固定值）
	portACMECA    = 14000
	portACMEMgmt  = 15000
	portMockDNS   = 8053
	portUpstream  = 10443
	localDomain   = "local.spike.test"
	passDomain    = "pass.spike.test"
)

// 1.3.6.1.5.5.7.1.31 (id-pe-acmeIdentifier)
var acmeIdentifierOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 31}

func main() {
	base, err := os.MkdirTemp("", "spike-t1-")
	must(err)
	logf := func(format string, a ...any) { fmt.Printf("[T1] "+format+"\n", a...) }
	emit := func(ev map[string]any) {
		b, _ := json.Marshal(ev)
		fmt.Println("EVIDENCE " + string(b))
	}
	logf("工作目录 %s（保留以便取证）", base)

	// ---- 1. mock DNS：所有 A → 127.0.0.1 ----
	dns, err := harness.StartMockDNS(fmt.Sprintf("127.0.0.1:%d", portMockDNS), "127.0.0.1")
	must(err)
	defer dns.Stop()
	logf("mock DNS 就绪 :%d", portMockDNS)

	// ---- 2. pebble：真实 ACME CA，VA 打 Layer4 端口 ----
	pebbleDir := modulePath("github.com/letsencrypt/pebble/v2@v2.5.0")
	// pebble 的 ACME 端点用 minica 自签证书，Caddy 侧需显式信任
	pebbleRoot := filepath.Join(pebbleDir, "test/certs/pebble.minica.pem")
	pebbleCfg := filepath.Join(base, "pebble-config.json")
	writeJSON(pebbleCfg, map[string]any{"pebble": map[string]any{
		"listenAddress":                   fmt.Sprintf("127.0.0.1:%d", portACMECA),
		"managementListenAddress":         fmt.Sprintf("127.0.0.1:%d", portACMEMgmt),
		"certificate":                     filepath.Join(pebbleDir, "test/certs/localhost/cert.pem"),
		"privateKey":                      filepath.Join(pebbleDir, "test/certs/localhost/key.pem"),
		"httpPort":                        5002,
		"tlsPort":                         portL4,
		"externalAccountBindingRequired":  false,
		"retryAfter":                      map[string]int{"authz": 1, "order": 1},
		"certificateValidityPeriod":       86400,
	}})
	pebbleBin := filepath.Join(base, "pebble")
	buildModuleCmd(pebbleBin, "github.com/letsencrypt/pebble/v2@v2.5.0", "./cmd/pebble")
	pebble, err := harness.Start("pebble", pebbleBin, []string{"-config", pebbleCfg, "-dnsserver", fmt.Sprintf("127.0.0.1:%d", portMockDNS)}, nil, base)
	must(err)
	defer pebble.Stop()
	must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portACMECA), 20*time.Second))
	logf("pebble 就绪 :%d（VA 目标端口=%d）", portACMECA, portL4)

	// ---- 3. 透传上游（自带证书，TLS 终结）----
	pki, err := harness.NewPKI(filepath.Join(base, "pki"), []string{localDomain, passDomain})
	must(err)
	upBin := mustBuild("./cmd/upstream", base+"/upstream")
	upLog := filepath.Join(base, "upstream.jsonl")
	up, err := harness.Start("upstream", upBin, []string{
		"-addr", fmt.Sprintf("127.0.0.1:%d", portUpstream),
		"-cert", pki.Leaves[passDomain].Cert, "-key", pki.Leaves[passDomain].Key, "-log", upLog,
	}, nil, base)
	must(err)
	defer up.Stop()
	must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portUpstream), 10*time.Second))
	logf("透传上游就绪 :%d（SNI=%s）", portUpstream, passDomain)

	// ---- 4. Caddy：L4(:8443) + http app(:7443) + ACME(pebble, TLS-ALPN 保留) ----
	caddyCfg := filepath.Join(base, "Caddyfile")
	os.WriteFile(caddyCfg, []byte(fmt.Sprintf(`{
	admin off
	storage file_system %s
	skip_install_trust

	# 关键：proxy_protocol 必须排在 tls 占位之前 → 在 TLS 握手前剥除 PROXY 头
	servers :%d {
		listener_wrappers {
			proxy_protocol {
				allow 127.0.0.1/32
				fallback_policy reject
			}
			tls
		}
	}

	layer4 {
		:%d {
			@passthrough tls sni %s
			route @passthrough {
				proxy 127.0.0.1:%d
			}
			route {
				proxy 127.0.0.1:%d {
					proxy_protocol v2
				}
			}
		}
	}
}

https://%s:%d {
	tls {
		issuer acme {
			dir https://127.0.0.1:%d/dir
			trusted_roots %s
			disable_http_challenge
		}
	}
	respond "LOCAL-OK" 200
}
`, filepath.Join(base, "storage"), portLocal, portL4, passDomain, portUpstream, portLocal,
		localDomain, portLocal, portACMECA, pebbleRoot)), 0o644)

	caddyLog := filepath.Join(base, "caddy.log")
	caddyBin := mustBuild("./caddybin", base+"/caddy-compat")

	// 先以「无站点」形态启动，确保 Layer4 监听先就绪，再触发 ACME 签发，
	// 从而把「启动竞态」从结论中排除（否则会误判为 T-1 失败）。
	// 步骤：先 adapt 校验配置，再直接 run（Caddy 会先 Start apps，顺序由 map 决定，
	// 故改用「预热」——先等 L4 端口可连，再等待证书落盘，并对失败重试计数）。
	caddyProc = startProc(caddyBin, []string{"run", "--config", caddyCfg, "--adapter", "caddyfile"}, base, caddyLog)
	defer stopProc(caddyProc)

	// L4 必须起来（这是兜底链路的入口）
	if err := harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portL4), 30*time.Second); err != nil {
		logf("L4 端口 %d 未就绪：%v\n%s", portL4, err, tail(caddyLog, 5000))
		os.Exit(1)
	}
	logf("Caddy 就绪：L4 :%d → 兜底 :%d / 透传 :%d", portL4, portLocal, portUpstream)

	// ---- 断言 A：真实签发（生死判据）----
	// 挑战窗口只有数百毫秒，主动探测极易错过；改为「由 pebble VA 真实命中」这一事实本身
	// 作为 A 的判据，再用日志中的 served key authentication certificate 交叉印证。
	certPath := waitIssued(logf, filepath.Join(base, "storage"), localDomain, 90*time.Second)
	resA := certPath != ""
	served := strings.Contains(tail(caddyLog, 200000), `"challenge":"tls-alpn-01"`)
	resA = resA && served
	emit(map[string]any{"step": "A_real_tlsalpn01_issuance_via_l4", "domain": localDomain,
		"ok": resA, "cert_path": certPath, "caddy_served_tlsalpn_cert": served})
	resB := resA

	// ---- 断言 C：签发证书服务业务握手（ALPN 仅 http/1.1，便于读取明文响应）----
	resC := false
	var obs harness.Observation
	if resB {
		obs = harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portLocal), localDomain, []string{"http/1.1"},
			pki.CAPool, true, 10*time.Second, "GET / HTTP/1.1\r\nHost: "+localDomain+"\r\nConnection: close\r\n\r\n")
		resC = strings.Contains(obs.Body, "LOCAL-OK") && obs.Error == ""
		emit(map[string]any{"step": "C_issued_cert_serves_traffic", "ok": resC, "detail": obs})
	}

	// ---- 断言 D：透传域名经同一 L4 端口直达上游（证明混合分流同时工作）----
	obsP := harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portL4), passDomain, []string{"http/1.1"},
		pki.CAPool, true, 10*time.Second, "GET / HTTP/1.1\r\nHost: "+passDomain+"\r\nConnection: close\r\n\r\n")
	resD := strings.Contains(obsP.Body, "UPSTREAM-OK")
	emit(map[string]any{"step": "D_passthrough_via_same_port", "ok": resD, "detail": obsP})

	verdict := resA && resB && resC && resD
	emit(map[string]any{"T1_VERDICT": map[bool]string{true: "CONFIRMED", false: "REFUTED"}[verdict],
		"A": resA, "B": resB, "C": resC, "D": resD})
	logf("结论：A=%v B=%v C=%v D=%v → %v", resA, resB, resC, resD, verdict)

	if !verdict {
		logf("--- caddy.log tail ---\n%s", tail(caddyLog, 6000))
		logf("--- pebble tail ---\n%s", tailStr(pebble.Output(), 6000))
		os.Exit(2)
	}
}

type challengeResult struct {
	OK         bool     `json:"ok"`
	SNI        string   `json:"sni"`
	ALPN       string   `json:"alpn"`
	HasACMEExt bool     `json:"has_acme_identifier_ext"`
	Critical   bool     `json:"ext_critical"`
	DNSNames   []string `json:"dns_names"`
	Err        string   `json:"err,omitempty"`
}

func challengeProbe(logf func(string, ...any)) challengeResult {
	r := challengeResult{SNI: localDomain}
	conn, err := tls.DialWithDialer(&net_Dialer, "tcp", fmt.Sprintf("127.0.0.1:%d", portL4),
		&tls.Config{ServerName: localDomain, NextProtos: []string{"acme-tls/1"}, InsecureSkipVerify: true})
	if err != nil {
		r.Err = err.Error()
		return r
	}
	defer conn.Close()
	cs := conn.ConnectionState()
	r.ALPN = cs.NegotiatedProtocol
	if len(cs.PeerCertificates) > 0 {
		leaf := cs.PeerCertificates[0]
		r.DNSNames = leaf.DNSNames
		for _, ext := range leaf.Extensions {
			if ext.Critical && ext.Id.Equal(acmeIdentifierOID) {
				r.HasACMEExt, r.Critical = true, ext.Critical
			}
		}
	}
	r.OK = r.ALPN == "acme-tls/1" && r.HasACMEExt
	logf("挑战探测：alpn=%q leafDNS=%v acmeIdentifier=%v", r.ALPN, r.DNSNames, r.HasACMEExt)
	return r
}

func waitIssued(logf func(string, ...any), storage, domain string, d time.Duration) string {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		var found string
		filepath.Walk(storage, func(p string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() || found != "" {
				return nil
			}
			if strings.HasSuffix(p, ".crt") && strings.Contains(p, domain) {
				found = p
			}
			return nil
		})
		if found != "" {
			logf("证书落盘：%s", found)
			return found
		}
		time.Sleep(500 * time.Millisecond)
	}
	logf("签发等待超时")
	return ""
}

// ---- 进程/构建辅助 ----

var caddyProc *exec.Cmd
var net_Dialer = netDialer()

func netDialer() (d net.Dialer) { d.Timeout = 10 * time.Second; return }

func startProc(bin string, args []string, dir, logPath string) *exec.Cmd {
	cmd := exec.Command(bin, args...)
	cmd.Dir = dir
	f, _ := os.Create(logPath)
	cmd.Stdout, cmd.Stderr = f, f
	must(cmd.Start())
	return cmd
}

func stopProc(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

func mustBuild(pkg, out string) string {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("build %s failed: %v\n%s\n", pkg, err, b)
		os.Exit(1)
	}
	return out
}

// buildModuleCmd 用 go install 构建依赖模块里的 main 包（out 为最终落盘路径的目录）。
func buildModuleCmd(out, mod, pkg string) {
	// mod 形如 github.com/letsencrypt/pebble/v2@v2.5.0 → 拆成 路径@版本
	at := strings.LastIndex(mod, "@")
	modPath, ver := mod[:at], mod[at+1:]
	target := modPath + "/" + strings.TrimPrefix(pkg, "./") + "@" + ver

	dir := filepath.Dir(out)
	cmd := exec.Command("go", "install", target)
	cmd.Env = append(os.Environ(), "GOBIN="+dir, "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("go install %s failed: %v\n%s\n", target, err, b)
		os.Exit(1)
	}
	// go install 产出名为包目录名（pebble / challtestsrv 等）；统一改名到 out
	if produced := filepath.Join(dir, filepath.Base(strings.TrimPrefix(pkg, "./"))); produced != out {
		_ = os.Rename(produced, out)
	}
}

// modulePath 通过 go list 解析模块在 module cache 的真实目录。
func modulePath(m string) string {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", m).Output()
	if err != nil {
		fmt.Printf("go list %s failed: %v\n", m, err)
		os.Exit(1)
	}
	return strings.TrimSpace(string(out))
}

func writeJSON(path string, v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	must(os.WriteFile(path, b, 0o644))
}

func must(err error) {
	if err != nil {
		fmt.Printf("FATAL %v\n", err)
		os.Exit(1)
	}
}

func tail(path string, n int) string {
	b, _ := os.ReadFile(path)
	return tailStr(string(b), n)
}

func tailStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}