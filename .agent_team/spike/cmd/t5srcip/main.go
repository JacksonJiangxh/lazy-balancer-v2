// T-5 生死判据：源 IP 链路端到端
//
// 链路：客户端(127.0.0.2:随机) → L4(:443) 注入 PROXY v2 → 127.0.0.1:7443
//       → caddy.listeners.proxy_protocol 还原 → Caddy 访问日志 remote_ip
//
// 断言：
//   A. 还原：日志中 remote_ip == 真实来源 127.0.0.2（而非 L4 的 127.0.0.1）
//   B. 反伪造：非 127.0.0.1 来源直连 7443 并伪造 PROXY 头 → 被拒（fallback_policy reject）
//   C. 直连绕过面：7443 若监听全部网卡，外部可直连 7443 不经 L4（安全边界实测）
//   D. 绑定收口：仅绑 127.0.0.1 时，非本机来源无法直连 7443
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"lazyspike/internal/harness"
)

const (
	portL4       = 443
	portLocal    = 7443
	portUpstream = 10443
	localDomain  = "local.spike.test"
	passDomain   = "pass.spike.test"
)

func main() {
	base, err := os.MkdirTemp("", "spike-t5-")
	must(err)
	logf := func(f string, a ...any) { fmt.Printf("[T5] "+f+"\n", a...) }
	emit := func(m map[string]any) {
		b, _ := json.Marshal(m)
		fmt.Println("EVIDENCE " + string(b))
	}
	logf("工作目录 %s", base)

	pki, err := harness.NewPKI(filepath.Join(base, "pki"), []string{localDomain, passDomain})
	must(err)

	// 上游（透传目标）
	upBin := buildHere("./cmd/upstream", filepath.Join(base, "upstream"))
	up, err := harness.Start("upstream", upBin, []string{
		"-addr", fmt.Sprintf("127.0.0.1:%d", portUpstream),
		"-cert", pki.Leaves[passDomain].Cert, "-key", pki.Leaves[passDomain].Key,
	}, nil, base)
	must(err)
	defer up.Stop()
	must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portUpstream), 10*time.Second))

	caddyBin := buildHere("./caddybin", filepath.Join(base, "caddy-compat"))
	logPath := filepath.Join(base, "access.log")
	currentLogPath = logPath
	pkiPool = pki.CAPool

	// 阶段 1：7443 绑全部网卡（照抄方案 §五 渲染形态 tcp/:7443）
	cfg1 := filepath.Join(base, "Caddyfile.all")
	// serversKey 必须与站点实际监听键逐字一致：bind tcp/:7443 经 NetworkAddress.String()
	// 剥除 tcp/ 前缀后，server.Listen 实为 ":7443"（见 listeners.go:293）。
	// siteAddr 必须"域名:7443"带端口：否则站点默认落 https 443/80，bind 的端口被丢弃，
	// 会与 layer4 的 :443 冲突（实测：7443 不监听 + 莫名起 :80 redirects server）。
	writeCfg(cfg1, pki, logPath, fmt.Sprintf(":%d", portLocal), fmt.Sprintf(":%d", portLocal), fmt.Sprintf("%s:%d", localDomain, portLocal))
	caddy1 := startCaddy(caddyBin, cfg1, base, filepath.Join(base, "caddy1.log"))
	defer stop(caddy1)
	must(waitPort(fmt.Sprintf("127.0.0.1:%d", portL4), 30*time.Second))
	must(waitPort(fmt.Sprintf("127.0.0.1:%d", portLocal), 20*time.Second))
	logf("阶段1 就绪（7443 绑全部网卡）")

	// ---- 断言 A：从 127.0.0.2 发起，日志应还原为 127.0.0.2 ----
	resA, detailA := restoreIP(logf)
	emit(map[string]any{"step": "A_restore_real_ip", "ok": resA, "detail": detailA})

	// ---- 断言 B：非 127.0.0.1 来源直连 7443 伪造 PROXY 头 → 必须被拒 ----
	resB, detailB := forgeRejected(logf)
	emit(map[string]any{"step": "B_forged_header_rejected", "ok": resB, "detail": detailB})

	// ---- 断言 C：7443 绑 0.0.0.0 时，外部（非 loopback 源）可直连绕过 L4 ----
	resC, detailC := bypassCheck(logf)
	emit(map[string]any{"step": "C_direct_bypass_when_bind_all", "ok": resC, "detail": detailC})

	// ---- 断言 D：改为仅绑 127.0.0.1 后，非 loopback 源无法直连 ----
	stop(caddy1)
	time.Sleep(1 * time.Second)
	cfg2 := filepath.Join(base, "Caddyfile.loopback")
	// 仅绑环回：serversKey == bindSpec == "127.0.0.1:7443"（与 server.Listen 逐字一致，wrapper 才生效）。
	// siteAddr 必须写域名（localDomain:7443）：Caddy 把站点地址的 host 部分当 host matcher 字面量，
	// 若写 127.0.0.1:7443，请求 Host: local.spike.test 不匹配 → NOP 空响应 status=0
	// （实测 D 断言 via_l4 失败根因，见 access.log "msg":"NOP"）。
	// server.Listen 推导：addresses.go:333-337 取 bind 的 host + 站点端口 → "127.0.0.1:7443"。
	writeCfg(cfg2, pki, logPath,
		fmt.Sprintf("127.0.0.1:%d", portLocal),
		fmt.Sprintf("127.0.0.1:%d", portLocal),
		fmt.Sprintf("%s:%d", localDomain, portLocal))
	caddy2 := startCaddy(caddyBin, cfg2, base, filepath.Join(base, "caddy2.log"))
	defer stop(caddy2)
	must(waitPort(fmt.Sprintf("127.0.0.1:%d", portL4), 30*time.Second))
	time.Sleep(1 * time.Second)
	resD, detailD := loopbackOnly(logf)
	emit(map[string]any{"step": "D_loopback_only_blocks_external", "ok": resD, "detail": detailD})

	emit(map[string]any{"T5_VERDICT": map[bool]string{true: "CONFIRMED", false: "REFUTED"}[resA && resB],
		"A_restore": resA, "B_antiforgery": resB, "C_bindall_bypass_exposed": resC, "D_loopback_hardened": resD})
	logf("结论：还原=%v 反伪造=%v 全绑绕过=%v 仅环回=%v", resA, resB, resC, resD)
	if !(resA && resB) {
		os.Exit(2)
	}
}

// restoreIP：客户端绑 127.0.0.2 连接 L4，断言 Caddy 看到的 remote_ip 为其真实地址。
// SNI 必须用 localDomain：passDomain 会命中 L4 透传路由直达上游，根本不进 7443 兜底链路。
// ALPN 仅 http/1.1：避开 acme-tls/1 保留值，便于读取明文响应确认 200。
func restoreIP(logf func(string, ...any)) (bool, map[string]any) {
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", portL4))
	if err != nil {
		return false, map[string]any{"err": err.Error()}
	}
	conn := tls.Client(raw, &tls.Config{ServerName: localDomain, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := conn.Handshake(); err != nil {
		return false, map[string]any{"handshake_err": err.Error()}
	}
	fmt.Fprintf(conn, "GET /restore-probe HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", localDomain)
	body, _ := io.ReadAll(conn)
	_ = conn.Close()
	logf("A 探测完成（源 127.0.0.2），响应 %d 字节", len(body))

	ok, logged := waitLogFor(logf, "/restore-probe", "127.0.0.2")
	return ok, map[string]any{"client_source": "127.0.0.2", "log_line": logged, "status_ok": strings.Contains(string(body), "200")}
}

// forgeRejected：从 127.0.0.2 直连 7443 并发送伪造 v1 PROXY 头（声明 1.2.3.4）。
// fallback_policy=reject 时应拒绝该连接（读取即错 / 握手失败）。
func forgeRejected(logf func(string, ...any)) (bool, map[string]any) {
	addr := fmt.Sprintf("127.0.0.1:%d", portLocal)
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}, Timeout: 5 * time.Second}
	raw, err := d.Dial("tcp", addr)
	if err != nil {
		return false, map[string]any{"dial_err": err.Error()}
	}
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(5 * time.Second))
	// v1 头：PROXY TCP4 1.2.3.4 5.6.7.8 40000 7443
	hdr := "PROXY TCP4 1.2.3.4 5.6.7.8 40000 7443\r\n"
	if _, err := raw.Write([]byte(hdr)); err != nil {
		return true, map[string]any{"write_err": err.Error(), "note": "连接已被拒（write 失败）"}
	}
	// 随后尝试 TLS 握手：若头被接受则应能继续（错误行为）；若被拒则应失败/关闭
	conn := tls.Client(raw, &tls.Config{ServerName: localDomain, InsecureSkipVerify: true})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	herr := conn.Handshake()
	_ = conn.Close()
	rejected := herr != nil
	logf("B 伪造头握手结果：err=%v → 拒绝=%v", herr, rejected)
	return rejected, map[string]any{"forged_source": "1.2.3.4", "handshake_err": fmt.Sprint(herr), "rejected": rejected}
}

// bypassCheck：从非 loopback 的本机地址（eth0 IP）直连 7443，验证是否能绕过 L4。
// C 是事实测量（绕过面有多大），ok=bypassed，verdict 不含它。
func bypassCheck(logf func(string, ...any)) (bool, map[string]any) {
	ip := firstNonLoopbackIP()
	if ip == "" {
		return false, map[string]any{"skipped": "无非环回地址"}
	}
	addr := net.JoinHostPort(ip, fmt.Sprint(portLocal))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP(ip)}}, "tcp", addr,
		&tls.Config{ServerName: localDomain, InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}})
	bypassed := err == nil
	if bypassed {
		_ = conn.Close()
	}
	logf("C 从 %s 直连 :%d → 成功=%v（=绕过 L4）", ip, portLocal, bypassed)
	return bypassed, map[string]any{"from_ip": ip, "target": addr, "bypassed_l4": bypassed, "err": fmt.Sprint(err)}
}

// loopbackOnly：7443 仅绑 127.0.0.1 后，同一非环回地址应连不上。
func loopbackOnly(logf func(string, ...any)) (bool, map[string]any) {
	ip := firstNonLoopbackIP()
	if ip == "" {
		return false, map[string]any{"skipped": "无非环回地址"}
	}
	addr := net.JoinHostPort(ip, fmt.Sprint(portLocal))
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	blocked := err != nil
	if c != nil {
		_ = c.Close()
	}
	// 同时确认仍能通过 L4 正常访问（功能未破坏）
	obs := harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portL4), localDomain, []string{"http/1.1"},
		pkiPool, true, 10*time.Second, "GET / HTTP/1.1\r\nHost: "+localDomain+"\r\nConnection: close\r\n\r\n")
	stillWorks := strings.Contains(obs.Body, "LOCAL-OK")
	logf("D 从 %s 直连 :%d 被阻断=%v；经 L4 仍可用=%v", ip, portLocal, blocked, stillWorks)
	return blocked && stillWorks, map[string]any{"from_ip": ip, "blocked": blocked, "via_l4_still_works": stillWorks, "err": fmt.Sprint(err)}
}

// ---- helpers ----

var pkiPool *x509.CertPool // 由 main 注入（localDomain 证书已由 L4 透传/本地终结两种路径共用）

// writeCfg 生成 Caddyfile。
// serversKey / bindSpec / siteAddr 三元必须与站点实际监听键逐字一致，
// 否则 listener_wrappers 不会应用到目标 listener（实测静默失效 → PROXY 头被当 TLS 数据）。
// 查证（caddy v2.11.9 module cache）：
//   - serveroptions.go:430  slices.Contains(server.Listen, s.ListenerAddress) → 逐字匹配
//   - listeners.go:293-298  NetworkAddress.String() 剥除 tcp/ 前缀 → server.Listen 存 ":7443" 形态
//   - addresses.go:333-337  bind 的 host 部分拼进站点地址端口 → 站点写 localDomain:7443 + bind tcp/:7443
//     （与 t1 已跑通的形态一致）；端口不能写在 bind 里（Split 后端口被丢弃，以站点端口为准）。
func writeCfg(path string, pki *harness.PKI, logPath, serversKey, bindSpec, siteAddr string) {
	cfg := fmt.Sprintf(`{
	admin off
	skip_install_trust
	storage file_system %s
	log {
		output file %s
		format json
	}
	servers %s {
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

%s {
	bind %s
	tls %s %s
	log {
		output file %s
		format json
	}
	respond "LOCAL-OK" 200
}
`, filepath.Join(filepath.Dir(path), "storage"), logPath, serversKey,
		portL4, passDomain, portUpstream, portLocal,
		siteAddr, bindSpec, pki.Leaves[localDomain].Cert, pki.Leaves[localDomain].Key, logPath)
	must(os.WriteFile(path, []byte(cfg), 0o644))
}

func waitLogFor(logf func(string, ...any), needle, wantIP string) (bool, string) {
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		lines := grepLog(needle)
		for _, ln := range lines {
			if strings.Contains(ln, wantIP) {
				logf("A 日志命中：%s", trim(ln, 400))
				return true, trim(ln, 400)
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	lines := grepLog(needle)
	return false, fmt.Sprintf("未在日志中找到 remote_ip=%s；样本=%v", wantIP, trim(strings.Join(lines, "\n"), 600))
}

var currentLogPath string

func grepLog(needle string) []string {
	if currentLogPath == "" {
		return nil
	}
	b, err := os.ReadFile(currentLogPath)
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.Contains(ln, needle) {
			out = append(out, ln)
		}
	}
	return out
}

func startCaddy(bin, cfg, dir, logPath string) *exec.Cmd {
	cmd := exec.Command(bin, "run", "--config", cfg, "--adapter", "caddyfile")
	cmd.Dir = dir
	f, _ := os.Create(logPath)
	cmd.Stdout, cmd.Stderr = f, f
	must(cmd.Start())
	return cmd
}

func stop(cmd *exec.Cmd) {
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
}

func waitPort(addr string, d time.Duration) error {
	return harness.WaitPort(context.Background(), addr, d)
}

func firstNonLoopbackIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() || ipn.IP.To4() == nil {
			continue
		}
		return ipn.IP.String()
	}
	return ""
}

func buildHere(pkg, out string) string {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("build %s failed: %v\n%s\n", pkg, err, b)
		os.Exit(1)
	}
	return out
}

func must(err error) {
	if err != nil {
		fmt.Printf("FATAL %v\n", err)
		os.Exit(1)
	}
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}