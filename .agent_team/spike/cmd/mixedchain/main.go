// S4：混布池（http 明文 + https TLS 车道）chain_proxy race/wrr 两模式
// **真进程真流量**取证。复用 .agent_team/spike/internal/harness（T-4 体例），
// 真 Caddy 二进制（bin/caddy-spike，编入 caddychain 模块）跑 JSON 配置，
// 断言全部来自进程输出与端口探针（✅实测级证据，非单测输出）。
//
// 运行：cd .agent_team/spike && go run ./cmd/mixedchain
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"lazyspike/internal/harness"
)

const tlsDomain = "tls-up.spike.test"

type upstream struct {
	server *http.Server
	addr   string
	hits   *atomic.Int64
	kind   string
}

func main() {
	base, err := os.MkdirTemp("", "spike-mixedchain-")
	must(err)
	logf := func(f string, a ...any) { fmt.Printf("[MC] "+f+"\n", a...) }
	emit := func(ev map[string]any) { b, _ := json.Marshal(ev); fmt.Println("EVIDENCE " + string(b)) }

	pki, err := harness.NewPKI(filepath.Join(base, "pki"), []string{tlsDomain})
	must(err)
	cert, err := tls.LoadX509KeyPair(pki.Leaves[tlsDomain].Cert, pki.Leaves[tlsDomain].Key)
	must(err)

	// ---- 1. 真上游：明文车道 ×2（Host 三态第二/第三档）、TLS 车道 ×1
	//（第一档 origin_domain），race 专用快/慢车道，双挂起车道 ----
	plain1 := startUpstream("plain-rule-host", "rule-level.spike.test", false, cert, 0)
	defer plain1.server.Close()
	plain2 := startUpstream("plain-dial-host", "", false, cert, 0)
	defer plain2.server.Close()
	tlsUp := startUpstream("tls-origin-host", "origin-tls.spike.test", true, cert, 0)
	defer tlsUp.server.Close()
	raceSlow := startUpstream("race-slow-tls", "origin-tls.spike.test", true, cert, 350*time.Millisecond)
	defer raceSlow.server.Close()
	raceFast := startUpstream("race-fast-plain", "", false, cert, 0)
	defer raceFast.server.Close()
	hang1 := startUpstream("hang1", "", false, cert, -1)
	defer hang1.server.Close()
	hang2 := startUpstream("hang2", "", false, cert, -1)
	defer hang2.server.Close()

	portWRR, portRace, portTunnel, portTunnelRace := freePort(), freePort(), freePort(), freePort()
	portDead, portTimeout := freePort(), freePort()
	deadAddr := fmt.Sprintf("127.0.0.1:%d", freePort()) // 必然拒连

	// ---- 2. 真 Caddy 二进制（含 chain_proxy 模块）跑 JSON 配置 ----
	caddyBin := filepath.Join(base, "caddy-spike")
	build("./caddybin", caddyBin)
	caddyBinAbs, _ := filepath.Abs(caddyBin)
	versionOut, err := exec.Command(caddyBinAbs, "version").CombinedOutput()
	must(err)
	logf("Caddy 二进制版本：%s", strings.TrimSpace(string(versionOut)))

	cfg := map[string]any{
		"admin": map[string]any{"disabled": true},
		"apps": map[string]any{"http": map[string]any{"servers": map[string]any{
			"wrr":     server(portWRR, chainProxy("wrr", []lane{{tlsUp.addr, "https", "origin-tls.spike.test", 2}, {plain1.addr, "", "rule-level.spike.test", 1}, {plain2.addr, "", "", 1}}, 3000)),
			"race":    server(portRace, chainProxy("", []lane{{raceSlow.addr, "https", "origin-tls.spike.test", 2}, {raceFast.addr, "", "", 1}}, 3000)),
			"dead":    server(portDead, chainProxy("wrr", []lane{{deadAddr, "", "", 1}, {deadAddr, "", "", 1}}, 3000)),
			"timeout": server(portTimeout, chainProxy("wrr", []lane{{hang1.addr, "", "", 1}, {hang2.addr, "", "", 1}}, 300)),
			"tunnel":  server(portTunnel, chainProxy("wrr", []lane{{plain2.addr, "", "", 1}}, 3000)),
			// race 模式隧道（S4-fix 必验：两模式都要真测；死车道→活车道切换）
			"tunnelrace": server(portTunnelRace, chainProxy("", []lane{{deadAddr, "", "", 1}, {plain2.addr, "", "", 1}}, 3000)),
		}}},
	}
	cfgPath := filepath.Join(base, "caddy.json")
	cfgBody, err := json.MarshalIndent(cfg, "", "  ")
	must(err)
	must(os.WriteFile(cfgPath, cfgBody, 0o600))

	proc, err := harness.Start("caddy", caddyBinAbs, []string{"run", "--config", cfgPath}, nil, base)
	must(err)
	defer proc.Stop()
	must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portWRR), 20*time.Second))
	for _, port := range []int{portRace, portDead, portTimeout, portTunnel, portTunnelRace} {
		must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", port), 20*time.Second))
	}

	client := &http.Client{Timeout: 5 * time.Second}
	// ---- 3. wrr 真观测：权重 2:1:1 的确定性分布 + scheme 混布 + Host 三档 ----
	const total = 16
	hits := map[string]int{}
	for i := 0; i < total; i++ {
		body := get(client, fmt.Sprintf("http://127.0.0.1:%d/", portWRR))
		hits[body]++
	}
	logf("wrr 分布：%v", hits)
	want := map[string]int{
		"TLS|origin-tls.spike.test":                  8,
		"PLAIN|rule-level.spike.test":                4,
		"PLAIN|127.0.0.1:" + plain2Port(plain2.addr): 4,
	}
	for body, n := range want {
		if hits[body] != n {
			fatalf("wrr 分布断言失败：body=%q got=%d want=%d（全量=%v）", body, hits[body], n, hits)
		}
	}
	emit(map[string]any{"case": "wrr-distribution", "total": total, "hits": hits, "want": want})

	// ---- 4. race 真观测：慢 TLS 与快明文同时扇出，快车道胜出但两路均命中 ----
	raceBeforeSlow, raceBeforeFast := raceSlow.hits.Load(), raceFast.hits.Load()
	body := get(client, fmt.Sprintf("http://127.0.0.1:%d/", portRace))
	if !strings.Contains(body, "PLAIN|") {
		fatalf("race 胜者应为快明文车道，got %q", body)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && raceSlow.hits.Load() <= raceBeforeSlow {
		time.Sleep(10 * time.Millisecond)
	}
	if raceSlow.hits.Load() <= raceBeforeSlow || raceFast.hits.Load() <= raceBeforeFast {
		fatalf("race 未真扇出两车道：slow %d→%d fast %d→%d",
			raceBeforeSlow, raceSlow.hits.Load(), raceBeforeFast, raceFast.hits.Load())
	}
	emit(map[string]any{"case": "race-fanout", "winner": body,
		"slow_hits": raceSlow.hits.Load() - raceBeforeSlow, "fast_hits": raceFast.hits.Load() - raceBeforeFast})

	// ---- 5. 车道全灭 502 / 全超时 504（真实状态码）----
	statusDead := status(client, fmt.Sprintf("http://127.0.0.1:%d/", portDead))
	statusTimeout := status(client, fmt.Sprintf("http://127.0.0.1:%d/", portTimeout))
	if statusDead != http.StatusBadGateway || statusTimeout != http.StatusGatewayTimeout {
		fatalf("收尾状态码错误：all-dead=%d want 502；all-timeout=%d want 504", statusDead, statusTimeout)
	}
	emit(map[string]any{"case": "terminal-status", "all_dead": statusDead, "all_timeout": statusTimeout})

	// ---- 6. 升级请求隧道：真 101 握手 + echo——wrr 与 race 两模式都真测
	//（S4-fix 必验：race 模式为死车道→活车道切换，覆盖原 502 用例转绿）----
	logf("隧道目标口 wrr=%d race=%d", portTunnel, portTunnelRace)
	echoWRR := websocketEcho(fmt.Sprintf("127.0.0.1:%d", portTunnel))
	if echoWRR != "echo:ping" {
		fmt.Printf("[MC] caddy 输出尾部：\n%s\n", tailOf(proc.Output(), 3000))
		fatalf("wrr 隧道回显=%q, want echo:ping", echoWRR)
	}
	echoRace := websocketEcho(fmt.Sprintf("127.0.0.1:%d", portTunnelRace))
	if echoRace != "echo:ping" {
		fmt.Printf("[MC] caddy 输出尾部：\n%s\n", tailOf(proc.Output(), 3000))
		fatalf("race 隧道回显=%q, want echo:ping（死车道→活车道切换）", echoRace)
	}
	emit(map[string]any{"case": "upgrade-tunnel", "wrr": echoWRR, "race": echoRace})

	// ---- 7. HC 真进程取证（JJC-20261119-001 S4 / T-7）：可控健康上游翻转 →
	// wrr 观测摘除 → 恢复回池——全部为真上游命中计数与真探针记录（非断言
	// 自证）；探针口径（Host=回源 Host 单源 / UA 标识 / TLS 跟车道）一并取证。----
	hcA := startHCUpstream(true, cert)
	defer hcA.server.Close()
	hcB := startHCUpstream(false, cert)
	defer hcB.server.Close()
	portHC := freePort()
	hc := chainProxy("wrr", []lane{{hcA.addr, "https", "hc-origin.spike.test", 1}, {hcB.addr, "", "", 1}}, 3000)
	hc["health_check"] = map[string]any{
		"interval_ms": 150, "timeout_ms": 500, "path": "/hc",
		"unhealthy_lag": 1, "healthy_lag": 1,
	}
	cfg["apps"].(map[string]any)["http"].(map[string]any)["servers"].(map[string]any)["hc"] = server(portHC, hc)
	// HC 配置为运行期注入：重写配置文件并热重载（真进程二阶段启动）。
	cfgBody2, err := json.MarshalIndent(cfg, "", "  ")
	must(err)
	must(os.WriteFile(cfgPath, cfgBody2, 0o600))
	// 重载方式：重启进程（重载即新实例，与生产重载窗口同语义）。
	proc.Stop()
	proc2, err := harness.Start("caddy", caddyBinAbs, []string{"run", "--config", cfgPath}, nil, base)
	must(err)
	defer proc2.Stop()
	must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portHC), 20*time.Second))

	hcClient := &http.Client{Timeout: 5 * time.Second}
	hcURL := fmt.Sprintf("http://127.0.0.1:%d/", portHC)
	// 初态基线：全 healthy（初始态裁决）——两车道都接业务流量。
	time.Sleep(400 * time.Millisecond) // 等 ≥2 轮探针（150ms interval）
	baseA, baseB := hcA.bizHits.Load(), hcB.bizHits.Load()
	for i := 0; i < 6; i++ {
		get(hcClient, hcURL)
	}
	midA, midB := hcA.bizHits.Load(), hcB.bizHits.Load()
	if midA-baseA <= 0 || midB-baseB <= 0 {
		fatalf("HC 初态基线失败：初值应全 healthy 两车道放行（A %d→%d B %d→%d）", baseA, midA, baseB, midB)
	}
	// 探针口径取证（真探针在 /hc 留下的记录）：
	if hcA.probeHost.Load() != "hc-origin.spike.test" {
		fatalf("探针 Host=%v, want hc-origin.spike.test（回源 Host 单源）", hcA.probeHost.Load())
	}
	if hcA.probeUA.Load() != "chain_proxy-health-check" {
		fatalf("探针 UA=%v, want chain_proxy-health-check", hcA.probeUA.Load())
	}
	if !hcA.probeTLS.Load() {
		fatalf("探针未走 TLS（https 车道 scheme 口径失败）")
	}
	if hcB.probeTLS.Load() {
		fatalf("明文车道探针不应走 TLS")
	}
	// 翻转不健康 → 观测摘除。
	hcA.healthy.Store(false)
	time.Sleep(500 * time.Millisecond) // ≥2 轮探针（lag=1 首败即摘）
	remA, remB := hcA.bizHits.Load(), hcB.bizHits.Load()
	for i := 0; i < 8; i++ {
		get(hcClient, hcURL)
	}
	afterA, afterB := hcA.bizHits.Load(), hcB.bizHits.Load()
	if afterA != remA {
		fatalf("wrr 未观测摘除：摘除后 A 车道业务命中 %d→%d（应冻结）", remA, afterA)
	}
	if afterB-remB < 8 {
		fatalf("wrr 摘除后未全量落健康车道：B %d→%d（want +%d）", remB, afterB, 8)
	}
	// 恢复 → 观测回池。
	hcA.healthy.Store(true)
	time.Sleep(500 * time.Millisecond)
	recA, recB := hcA.bizHits.Load(), hcB.bizHits.Load()
	for i := 0; i < 8; i++ {
		get(hcClient, hcURL)
	}
	endA, endB := hcA.bizHits.Load(), hcB.bizHits.Load()
	if endA-recA <= 0 {
		fatalf("恢复未观测回池：A 车道业务命中 %d→%d（应增长）", recA, endA)
	}
	if endB-recB <= 0 {
		fatalf("恢复后 B 车道停服异常: %d→%d", recB, endB)
	}
	emit(map[string]any{"case": "health-check-flip",
		"probe": map[string]any{"host": hcA.probeHost.Load(), "ua": hcA.probeUA.Load(),
			"tls_lane": hcA.probeTLS.Load(), "plain_lane_tls": hcB.probeTLS.Load(),
			"path": "/hc", "interval_ms": 150, "unhealthy_lag": 1, "healthy_lag": 1},
		"baseline_all_healthy": map[string]any{"a": baseA, "b": baseB, "a_delta": midA - baseA, "b_delta": midB - baseB},
		"removed":              map[string]any{"a_frozen": remA, "b": remB, "a_delta": afterA - remA, "b_delta": afterB - remB},
		"recovered":            map[string]any{"a": recA, "b": recB, "a_delta": endA - recA, "b_delta": endB - recB}})

	emit(map[string]any{"case": "done", "caddy": strings.TrimSpace(string(versionOut)), "ports": []int{portWRR, portRace, portDead, portTimeout, portTunnel, portTunnelRace, portHC}})
	logf("全部断言通过")
}

// hcUpstream 可控健康上游：/hc 探针路径按 healthy 开关应答（探针命中计数 +
// Host/UA/TLS 记录），其余路径业务应答（业务命中计数）。
type hcUpstream struct {
	server    *http.Server
	addr      string
	healthy   atomic.Bool
	probes    atomic.Int64
	bizHits   atomic.Int64
	probeHost atomic.Value
	probeUA   atomic.Value
	probeTLS  atomic.Bool
}

func startHCUpstream(secure bool, cert tls.Certificate) *hcUpstream {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	if secure {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	up := &hcUpstream{}
	up.healthy.Store(true)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/hc" {
			up.probes.Add(1)
			up.probeHost.Store(r.Host)
			up.probeUA.Store(r.Header.Get("User-Agent"))
			up.probeTLS.Store(r.TLS != nil)
			if !up.healthy.Load() {
				w.WriteHeader(http.StatusBadGateway)
				fmt.Fprint(w, "hc-down")
				return
			}
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hc-ok")
			return
		}
		up.bizHits.Add(1)
		marker := "PLAIN"
		if r.TLS != nil {
			marker = "TLS"
		}
		fmt.Fprintf(w, "%s|%s", marker, r.Host)
	})
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	up.server = srv
	up.addr = ln.Addr().String()
	return up
}

type lane struct {
	dial, scheme, host string
	weight             int
}

func server(port int, handler map[string]any) map[string]any {
	return map[string]any{
		"listen":          []string{fmt.Sprintf("127.0.0.1:%d", port)},
		"automatic_https": map[string]any{"disable": true},
		"routes":          []any{map[string]any{"handle": []any{handler}}},
	}
}

func chainProxy(mode string, lanes []lane, requestTimeoutMS int) map[string]any {
	ups := make([]any, 0, len(lanes))
	for _, l := range lanes {
		up := map[string]any{"dial": l.dial, "weight": l.weight}
		if l.scheme != "" {
			up["scheme"] = l.scheme
		}
		if l.host != "" {
			up["host"] = l.host
		}
		ups = append(ups, up)
	}
	h := map[string]any{
		"handler": "chain_proxy", "upstreams": ups,
		"race_interval_ms": 40, "request_timeout_ms": requestTimeoutMS,
		"dial_timeout_ms": 500, "body_replay_limit_bytes": 1024 * 1024,
	}
	if mode != "" {
		h["mode"] = mode
	}
	return h
}

// startUpstream 起一个真 HTTP（可选 TLS）上游；delay<0 表示永不响应（挂起）。
func startUpstream(kind, host string, secure bool, cert tls.Certificate, delay time.Duration) *upstream {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	if secure {
		ln = tls.NewListener(ln, &tls.Config{Certificates: []tls.Certificate{cert}})
	}
	hits := &atomic.Int64{}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Upgrade") != "" && r.URL.Path == "/ws" {
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, rw, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			fmt.Fprint(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			buf := make([]byte, 32)
			n, _ := rw.Read(buf)
			fmt.Fprintf(conn, "echo:%s", buf[:n])
			return
		}
		if delay < 0 {
			<-r.Context().Done()
			return
		}
		if delay > 0 {
			time.Sleep(delay)
		}
		marker := "PLAIN"
		if r.TLS != nil {
			marker = "TLS"
		}
		fmt.Fprintf(w, "%s|%s", marker, r.Host)
	})
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(ln) }()
	return &upstream{server: srv, addr: ln.Addr().String(), hits: hits, kind: kind}
}

func freePort() int {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	port := ln.Addr().(*net.TCPAddr).Port
	must(ln.Close())
	return port
}

func get(client *http.Client, url string) string {
	resp, err := client.Get(url)
	must(err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	must(err)
	if resp.StatusCode != http.StatusOK {
		fatalf("GET %s status=%d body=%q", url, resp.StatusCode, b)
	}
	return string(b)
}

func status(client *http.Client, url string) int {
	resp, err := client.Get(url)
	must(err)
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode
}

func websocketEcho(addr string) string {
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	must(err)
	defer conn.Close()
	_, err = conn.Write([]byte("GET /ws HTTP/1.1\r\nHost: ws.spike.test\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	must(err)
	must(conn.SetReadDeadline(time.Now().Add(3 * time.Second)))
	head := make([]byte, 0, 256)
	buf := make([]byte, 1)
	for !strings.Contains(string(head), "\r\n\r\n") {
		n, err := conn.Read(buf)
		must(err)
		head = append(head, buf[:n]...)
	}
	if !strings.Contains(string(head), " 101 ") {
		fatalf("升级握手=%q, want 101", head)
	}
	_, err = conn.Write([]byte("ping"))
	must(err)
	echo := make([]byte, 32)
	n, err := conn.Read(echo)
	must(err)
	return string(echo[:n])
}

func build(pkg, out string) {
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod")
	if b, err := cmd.CombinedOutput(); err != nil {
		fatalf("build %s: %v\n%s", pkg, err, b)
	}
}

func must(err error) {
	if err != nil {
		fatalf("%v", err)
	}
}

func tailOf(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func fatalf(f string, a ...any) {
	fmt.Printf("FATAL "+f+"\n", a...)
	os.Exit(1)
}

func plain2Port(addr string) string {
	_, port, err := net.SplitHostPort(addr)
	must(err)
	return port
}
