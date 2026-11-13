// T-4：混合并发——同端口（layer4 :443）透传 route 与终结 route 并发互不影响。
//
// 拓扑与 T-2 完全一致（复用 harness.L4Lab）：
//
//	20 客户端 ──SNI=pass.spike.test──▶ 127.0.0.1:443 [layer4] → proxy 127.0.0.1:10443（上游终结）
//	20 客户端 ──SNI=local.spike.test──▶ 127.0.0.1:443 [layer4] → 兜底 proxy 127.0.0.1:7443（PROXY v2，Caddy TLS 终结）
//
// 断言：并发 40 条连接全部完成 TLS 握手 + 一次 HTTP 请求；
// 透传侧响应体含 UPSTREAM-OK，终结侧含 LOCAL-OK；成功数=40，失败数=0。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazyspike/internal/harness"
)

const (
	portL4       = 443
	portLocal    = 7443
	portUpstream = 10443
	passDomain   = "pass.spike.test"
	localDomain  = "local.spike.test"
	connsPerSide = 20 // 每侧并发连接数
)

func main() {
	base, err := os.MkdirTemp("", "spike-t4-")
	must(err)
	logf := func(f string, a ...any) { fmt.Printf("[T4] "+f+"\n", a...) }
	emit := func(ev map[string]any) { b, _ := json.Marshal(ev); fmt.Println("EVIDENCE " + string(b)) }
	logf("工作目录 %s", base)

	// ---- 1. PKI ----
	pki, err := harness.NewPKI(filepath.Join(base, "pki"), []string{passDomain, localDomain})
	must(err)

	// ---- 2. 透传上游 ----
	upBin := mustBuild("./cmd/upstream", filepath.Join(base, "upstream"))
	up, err := harness.Start("upstream", upBin, []string{
		"-addr", fmt.Sprintf("127.0.0.1:%d", portUpstream),
		"-cert", pki.Leaves[passDomain].Cert,
		"-key", pki.Leaves[passDomain].Key,
		"-log", filepath.Join(base, "upstream.jsonl"),
	}, nil, base)
	must(err)
	defer up.Stop()
	must(harness.WaitPort(context.Background(), fmt.Sprintf("127.0.0.1:%d", portUpstream), 10*time.Second))
	logf("透传上游就绪 :%d", portUpstream)

	// ---- 3. Caddy（与 T-2 同一拓扑）----
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
	logf("caddy 就绪：L4 :%d → 透传 :%d / 终结 :%d", portL4, portUpstream, portLocal)

	// ---- 4. 预热：各先来一次串行握手，排除首次加载抖动 ----
	// 终结路径（tls internal）首次握手会触发 Caddy 内部签发，签发完成前会回 tls internal error，
	// 故对终结路径做重试等待（最多 30s）；透传路径一次即可。
	warmPass := harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portL4), passDomain, []string{"http/1.1"},
		pki.CAPool, false, 10*time.Second, "GET / HTTP/1.1\r\nHost: "+passDomain+"\r\nConnection: close\r\n\r\n")
	must(errIf(warmPass.Error, "透传预热"))
	if !strings.Contains(warmPass.Body, "UPSTREAM-OK") {
		fmt.Printf("透传预热响应异常：%q\n", warmPass.Body)
		os.Exit(2)
	}
	var warmLocal harness.Observation
	deadline := time.Now().Add(30 * time.Second)
	for {
		warmLocal = harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portL4), localDomain, []string{"http/1.1"},
			pki.CAPool, true, 10*time.Second, "GET / HTTP/1.1\r\nHost: "+localDomain+"\r\nConnection: close\r\n\r\n")
		if warmLocal.Error == "" && strings.Contains(warmLocal.Body, "LOCAL-OK") {
			break
		}
		if time.Now().After(deadline) {
			fmt.Printf("终结预热超时：err=%q body=%q\n--- caddy.log tail ---\n%s\n",
				warmLocal.Error, warmLocal.Body, tail(caddy.Output(), 4000))
			os.Exit(2)
		}
		time.Sleep(500 * time.Millisecond)
	}
	logf("预热通过（透传 UPSTREAM-OK / 终结 LOCAL-OK）")

	// ---- 5. 并发 40 条：20 透传 + 20 终结，同时发起 ----
	type result struct {
		Idx  int    `json:"idx"`
		Kind string `json:"kind"`
		OK   bool   `json:"ok"`
		Err  string `json:"err,omitempty"`
		Body string `json:"body,omitempty"`
	}
	results := make([]result, connsPerSide*2)
	var passOK, passFail, localOK, localFail atomic.Int64
	start := time.Now()

	var wg sync.WaitGroup
	launch := func(idx int, kind, sni string) {
		defer wg.Done()
		req := "GET / HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n"
		obs := harness.ProbeTLS(fmt.Sprintf("127.0.0.1:%d", portL4), sni,
			[]string{"http/1.1"}, pki.CAPool,
			kind == "local", // 终结侧证书由 Caddy 本地 CA 签发，无法用 spike-local-ca 验证 → insecure
			15*time.Second, req)
		r := result{Idx: idx, Kind: kind, Body: obs.Body}
		if obs.Error != "" {
			r.Err = obs.Error
		}
		switch kind {
		case "passthrough":
			r.OK = obs.Error == "" && strings.Contains(obs.Body, "UPSTREAM-OK")
			if r.OK {
				passOK.Add(1)
			} else {
				passFail.Add(1)
			}
		case "local":
			r.OK = obs.Error == "" && strings.Contains(obs.Body, "LOCAL-OK")
			if r.OK {
				localOK.Add(1)
			} else {
				localFail.Add(1)
			}
		}
		results[idx] = r
	}

	wg.Add(connsPerSide * 2)
	for i := 0; i < connsPerSide; i++ {
		go launch(i, "passthrough", passDomain)
	}
	for i := 0; i < connsPerSide; i++ {
		go launch(connsPerSide+i, "local", localDomain)
	}
	wg.Wait()
	elapsed := time.Since(start)

	totalOK := passOK.Load() + localOK.Load()
	totalFail := passFail.Load() + localFail.Load()
	ok := totalOK == connsPerSide*2 && totalFail == 0
	emit(map[string]any{"step": "T4_mixed_concurrency", "ok": ok,
		"concurrency": map[string]any{"passthrough": connsPerSide, "local": connsPerSide, "total": connsPerSide * 2},
		"success":      map[string]any{"passthrough": passOK.Load(), "local": localOK.Load(), "total": totalOK},
		"failure":      map[string]any{"passthrough": passFail.Load(), "local": localFail.Load(), "total": totalFail},
		"elapsed_ms":   elapsed.Milliseconds(),
		"results":      results})
	logf("并发数=%d（透传%d+终结%d） 成功=%d 失败=%d 耗时=%s → %v",
		connsPerSide*2, connsPerSide, connsPerSide, totalOK, totalFail, elapsed, ok)

	if !ok {
		for _, r := range results {
			if !r.OK {
				fmt.Printf("FAIL idx=%d kind=%s err=%q\n", r.Idx, r.Kind, r.Err)
			}
		}
		fmt.Printf("--- caddy.log tail ---\n%s\n", tail(caddy.Output(), 4000))
		os.Exit(2)
	}
}

func errIf(errText, what string) error {
	if errText == "" {
		return nil
	}
	return fmt.Errorf("%s: %s", what, errText)
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
