package acme

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// 历史问题（历史）：递归共识探测必须并行（每台独立 ctx 超时）。
//
// 判定形态：4 台递归各自「进入后阻塞直至 4 台同时在途」——并行时 4 台同时
// 进入即解锁，串行时任一时刻仅 1 台在途 → 各台各自烧满 700ms 兜底超时。
// 不依赖墙钟阈值扫射，构造上二分串行/并行。
func TestIssuer_waitForDNS_probesResolversInParallel(t *testing.T) {
	const expected = "parallel-value"
	const fqdn = "_acme-challenge.parallel.example.com."

	var (
		mu       sync.Mutex
		inFlight int
		release  = make(chan struct{})
		once     sync.Once
	)
	responder := func(query *dns.Msg) *dns.Msg {
		mu.Lock()
		inFlight++
		if inFlight >= 4 {
			once.Do(func() { close(release) })
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
		select {
		case <-release:
		case <-time.After(700 * time.Millisecond):
		}
		m := new(dns.Msg)
		m.SetReply(query)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{expected},
		})
		return m
	}

	auth := startFakeDNSServer(t, txtResponder(false, expected))
	rec := []string{
		startFakeDNSServer(t, responder),
		startFakeDNSServer(t, responder),
		startFakeDNSServer(t, responder),
		startFakeDNSServer(t, responder),
	}
	logger := setupPropagationSeams(t, []string{auth})
	propagationRecursiveResolvers = rec

	issuer := &Issuer{Logger: logger}
	// 4 台命中 → 需连续 2 轮共识；并行时两轮各为「同时进入即解锁」的瞬时，
	// 串行时首轮即 4×700ms 兜底、预算耗尽不达共识。
	if err := issuer.waitForDNS(context.Background(), fqdn, expected, 3*time.Second); err != nil {
		t.Fatalf("并行探测应在两轮共识内放行（串行形态会烧满预算超时）: %v", err)
	}
	if !strings.Contains(strings.Join(logger.lines, "\n"), "递归共识放行") {
		t.Fatalf("放行依据须为递归共识, got %v", logger.lines)
	}
}

// A85 历史问题：权威服务器与递归服务器一样必须同轮并行。四台服务器只有在
// 全部同时在途时才返回命中；串行实现会逐台等待兜底并全部返回 NODATA。
func TestIssuer_probeAuthServersLogged_probesAuthoritativeInParallel(t *testing.T) {
	const expected = "parallel-auth-value"
	const fqdn = "_acme-challenge.parallel-auth.example.com."
	var (
		mu       sync.Mutex
		inFlight int
		release  = make(chan struct{})
		once     sync.Once
	)
	responder := func(query *dns.Msg) *dns.Msg {
		mu.Lock()
		inFlight++
		if inFlight >= 4 {
			once.Do(func() { close(release) })
		}
		mu.Unlock()
		defer func() {
			mu.Lock()
			inFlight--
			mu.Unlock()
		}()
		parallel := false
		select {
		case <-release:
			parallel = true
		case <-time.After(700 * time.Millisecond):
		}
		m := new(dns.Msg)
		m.SetReply(query)
		if parallel {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{expected},
			})
		}
		return m
	}
	servers := []string{
		startFakeDNSServer(t, responder),
		startFakeDNSServer(t, responder),
		startFakeDNSServer(t, responder),
		startFakeDNSServer(t, responder),
	}
	issuer := &Issuer{Logger: &captureLogger{}}

	alive, ready, _, _ := issuer.probeAuthServersLogged(context.Background(), servers, fqdn, expected, &dnsLogState{})
	if !ready || len(alive) != len(servers) {
		t.Fatalf("authoritative parallel probes ready=%v alive=%d, want true/%d", ready, len(alive), len(servers))
	}
}

// A85 历史问题 超时边界：每台权威使用独立短超时。应答慢于该超时时须按
// 查询失败处理（不进入 alive），而不是串行等到服务端 NODATA 后当作存活未命中。
func TestIssuer_probeAuthServersLogged_appliesPerServerTimeout(t *testing.T) {
	oldTimeout := propagationResolverProbeTimeout
	propagationResolverProbeTimeout = 40 * time.Millisecond
	t.Cleanup(func() { propagationResolverProbeTimeout = oldTimeout })
	const expected = "slow-auth-value"
	responder := func(query *dns.Msg) *dns.Msg {
		time.Sleep(150 * time.Millisecond)
		m := new(dns.Msg)
		m.SetReply(query)
		return m
	}
	servers := []string{startFakeDNSServer(t, responder), startFakeDNSServer(t, responder)}
	logger := &captureLogger{}
	issuer := &Issuer{Logger: logger}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	alive, ready, _, _ := issuer.probeAuthServersLogged(ctx, servers, "_acme-challenge.slow-auth.example.com.", expected, &dnsLogState{})
	if ready || len(alive) != 0 {
		t.Fatalf("slow authoritative probes ready=%v alive=%v, want false/empty on per-server timeout", ready, alive)
	}
	if got := strings.Count(strings.Join(logger.lines, "\n"), "权威 DNS 查询失败"); got != len(servers) {
		t.Fatalf("timeout error logs=%d, want %d; lines=%v", got, len(servers), logger.lines)
	}
}

// 边界基线：空集合不就绪；单台命中/未命中语义在并行化后保持不变。
func TestIssuer_probeAuthServersLogged_emptyAndSingleServerBoundaries(t *testing.T) {
	issuer := &Issuer{}
	alive, ready, _, _ := issuer.probeAuthServersLogged(context.Background(), nil, "_acme-challenge.empty.example.com.", "value", nil)
	if ready || len(alive) != 0 {
		t.Fatalf("empty servers ready=%v alive=%v, want false/empty", ready, alive)
	}
	for _, tc := range []struct {
		name      string
		hit       bool
		wantReady bool
	}{
		{"single-hit", true, true},
		{"single-nodata", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := startFakeDNSServer(t, txtResponder(tc.hit, "value"))
			alive, ready, _, _ := issuer.probeAuthServersLogged(context.Background(), []string{server}, "_acme-challenge.single.example.com.", "value", nil)
			if ready != tc.wantReady || len(alive) != 1 {
				t.Fatalf("%s ready=%v alive=%v, want %v/one alive", tc.name, ready, alive, tc.wantReady)
			}
		})
	}
}

// 历史问题（历史）：逐台命中/未命中行按状态变化收敛——同一状态跨轮不重复
// 打印（镜像 waitForValidation 的 lastChalStatus 先例），避免 5min 预算内
// 逐台刷屏。放行/诊断行（递归共识放行、分歧诊断）不受影响。
func TestIssuer_waitForDNS_convergesRepeatedProbeLogs(t *testing.T) {
	const expected = "converge-value"
	const fqdn = "_acme-challenge.converge.example.com."

	// 恒返回陈旧值的递归（非期望值 → 未命中行；值不变 → 状态不变）。
	staleResponder := func(query *dns.Msg) *dns.Msg {
		m := new(dns.Msg)
		m.SetReply(query)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{"stale-value"},
		})
		return m
	}
	auth := startFakeDNSServer(t, txtResponder(false, expected))
	recHit := startFakeDNSServer(t, txtResponder(true, expected))
	recMiss := startFakeDNSServer(t, staleResponder)
	logger := setupPropagationSeams(t, []string{auth})
	propagationRecursiveResolvers = []string{recHit, recMiss}

	issuer := &Issuer{Logger: logger}
	// 1 台命中不足共识 → 必然超时；500ms/20ms≈25 轮，旧形态每轮各刷一行。
	if err := issuer.waitForDNS(context.Background(), fqdn, expected, 500*time.Millisecond); err == nil {
		t.Fatal("单台命中不得放行（M9 底线）")
	}

	countContaining := func(substr string) int {
		n := 0
		for _, line := range logger.lines {
			if strings.Contains(line, substr) {
				n++
			}
		}
		return n
	}
	if got := countContaining("递归 DNS 已命中"); got != 1 {
		t.Fatalf("恒定命中的递归行应仅打印一次（状态变化收敛），got %d 行: %v", got, logger.lines)
	}
	if got := countContaining("DNS 未命中"); got != 1 {
		t.Fatalf("恒定未命中的递归行应仅打印一次（状态变化收敛），got %d 行: %v", got, logger.lines)
	}
}
