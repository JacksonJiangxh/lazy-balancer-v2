// T-2：SNI 嗅探保真——Layer4 peek ClientHello 后转发不破坏 TLS 握手，
// 且 TLS 版本 / 协商 ALPN / 服务端所见 SNI 与「直连上游」三项全一致。
//
// 拓扑（端口对齐生产替身）：
//
//	客户端 ──SNI=pass.spike.test──▶ 127.0.0.1:443  [layer4 peek]
//	                                 ├─ @passthrough → proxy 127.0.0.1:10443（上游自带证书终结）
//	                                 └─ 其余 → proxy 127.0.0.1:7443（PROXY v2，本地终结）
//
// 断言：
//   A. 直连 10443（baseline）与经 L4 :443 同 SNI 握手，TLS 版本 / ALPN / 服务端所见 SNI 三项一致；
//   B. 经 L4 后 upstream JSONL 记录的 remote/sni/alpn 与客户端视角吻合。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"lazyspike/internal/harness"
)

const (
	portL4       = 443  // Layer4 前置（生产真实端口）
	portLocal    = 7443 // 本地终结（计划固定值）
	portUpstream = 10443
	passDomain   = "pass.spike.test"
	localDomain  = "local.spike.test"
)

func main() {
	base, err := os.MkdirTemp("", "spike-t2-")
	must(err)
	logf := func(f string, a ...any) { fmt.Printf("[T2] "+f+"\n", a...) }
	emit := func(ev map[string]any) { b, _ := json.Marshal(ev); fmt.Println("EVIDENCE " + string(b)) }
	logf("工作目录 %s", base)

	// ---- 1. PKI（上游用 pass 域名叶证书）----
	pki, err := harness.NewPKI(filepath.Join(base, "pki"), []string{passDomain, localDomain})
	must(err)

	// ---- 2. 透传上游（自带证书终结，JSONL 记录 remote/sni/alpn）----
	upBin := mustBuild("./cmd/upstream", filepath.Join(base, "upstream"))
	upLog := filepath.Join(base, "upstream.jsonl")
	up, err := harness.Start("upstream", upBin, []string{
		"-addr", fmt.Sprintf("127.0.0.1:%d", portUpstream),
		"-cert", pki.Leaves[passDomain].Cert,
		"-key", pki.Leaves[passDomain].Key,
		"-log", upLog,
	}, nil, base)
	must(err)
	defer up.Stop()
	must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portUpstream), 10*time.Second))
	logf("透传上游就绪 :%d（SNI=%s）", portUpstream, passDomain)

	// ---- 3. Caddy：layer4 :443（全局块，端口块写法）+ 本地终结 :7443 ----
	lab := harness.L4Lab{
		StorageDir: filepath.Join(base, "storage"), CaddyLogPath: filepath.Join(base, "caddy.log"),
		L4Port: portL4, LocalPort: portLocal, UpPort: portUpstream,
		PassDomain: passDomain, LocalDomain: localDomain,
	}
	cfgPath := filepath.Join(base, "Caddyfile")
	must(lab.WriteCaddyfile(cfgPath))
	caddyBin := mustBuild("./caddybin", filepath.Join(base, "caddy"))
	caddy, err := harness.StartCaddy(caddyBin, cfgPath, base, lab.CaddyLogPath, portL4, portLocal)
	must(err)
	defer caddy.Stop()
	logf("caddy 就绪：L4 :%d → 透传 :%d / 兜底终结 :%d", portL4, portUpstream, portLocal)

	httpReq := "GET / HTTP/1.1\r\nHost: " + passDomain + "\r\nConnection: close\r\n\r\n"
	alpn := []string{"http/1.1"}

	// ---- 4a. 断言 A：直连 vs 经 L4 三项对照 ----
	direct := harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portUpstream), passDomain, alpn, pki.CAPool, false, 10*time.Second, httpReq)
	via := harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portL4), passDomain, alpn, pki.CAPool, false, 10*time.Second, httpReq)

	okVersion := direct.Error == "" && via.Error == "" && direct.TLSVersion == via.TLSVersion
	okALPN := direct.Error == "" && via.Error == "" && direct.ALPNNegotiated == via.ALPNNegotiated
	okSNI := direct.Error == "" && via.Error == "" &&
		len(direct.LeafDNSNames) > 0 && len(via.LeafDNSNames) > 0 &&
		direct.LeafDNSNames[0] == via.LeafDNSNames[0] && direct.LeafDNSNames[0] == passDomain
	okBody := strings.Contains(direct.Body, "UPSTREAM-OK") && strings.Contains(via.Body, "UPSTREAM-OK")
	okA := okVersion && okALPN && okSNI && okBody
	emit(map[string]any{"step": "A_direct_vs_via_l4", "ok": okA,
		"direct": direct, "via_l4": via,
		"ok_version": okVersion, "ok_alpn": okALPN, "ok_sni": okSNI, "ok_body": okBody})
	logf("断言A：直连 ver=%s alpn=%q sni=%v | 经L4 ver=%s alpn=%q sni=%v → %v",
		direct.TLSVersion, direct.ALPNNegotiated, direct.LeafDNSNames,
		via.TLSVersion, via.ALPNNegotiated, via.LeafDNSNames, okA)

	// ---- 4b. 断言 B：upstream JSONL（remote/sni/alpn 与客户端视角吻合）----
	// JSONL 每行一记录：clienthello 行来自 GetConfigForClient（含 sni/alpn_offers/remote），
	// HTTP 行来自 handler（含 sni/alpn/remote）。断言至少存在一条与客户端视角吻合的记录。
	okB := false
	var matched map[string]any
	if f, err := os.Open(upLog); err == nil {
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			var rec map[string]any
			if json.Unmarshal(sc.Bytes(), &rec) != nil {
				continue
			}
			sni, _ := rec["sni"].(string)
			alpnGot, _ := rec["alpn"].(string)
			remote, _ := rec["remote"].(string)
			if sni != passDomain {
				continue
			}
			// 客户端视角：SNI=passDomain；ALPN 协商结果（客户端可接受 h2 或 http/1.1）
			alpnOK := alpnGot == via.ALPNNegotiated
			// remote 是 L4 出向代理连接的源地址（127.0.0.1:ephemeral），仅校验回环前缀
			remoteOK := strings.HasPrefix(remote, "127.0.0.1:")
			if alpnOK && remoteOK {
				okB = true
				matched = rec
				break
			}
		}
		f.Close()
	}
	emit(map[string]any{"step": "B_upstream_jsonl_matches_client_view", "ok": okB, "matched_record": matched})
	logf("断言B：JSONL 记录 sni/alpn/remote 吻合客户端视角 → %v", okB)

	verdict := okA && okB
	emit(map[string]any{"T2_VERDICT": map[bool]string{true: "CONFIRMED", false: "REFUTED"}[verdict],
		"A": okA, "B": okB})
	logf("结论：A=%v B=%v → %v", okA, okB, verdict)

	if !verdict {
		fmt.Printf("--- caddy.log tail ---\n%s\n", tail(caddy.Output(), 4000))
		fmt.Printf("--- upstream tail ---\n%s\n", tail(up.Output(), 2000))
		os.Exit(2)
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

func must(err error) {
	if err != nil {
		fmt.Printf("FATAL %v\n", err)
		os.Exit(1)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
