package acme

// 权威 NS 解析按本机 IPv6 可达性预筛 AAAA。

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Given：4 台公共递归解析器，前 3 台各耗时 200ms 未命中，第 4 台命中；
// 调用 ctx 500ms 到期。
// When：checkRecursiveDNS。
// Then：并行探测在单台耗时量级内完成并命中（串行需 ~800ms，ctx 到期后
// 第 4 台探测直接被取消 → 判失败）。
func TestIssuer_checkRecursiveDNS_probesResolversInParallel(t *testing.T) {
	const expected = "recursive-parallel-value"
	const fqdn = "_acme-challenge.recursive-parallel.example.com."
	const probeDelay = 200 * time.Millisecond

	miss := func(query *dns.Msg) *dns.Msg {
		time.Sleep(probeDelay)
		m := new(dns.Msg)
		m.SetReply(query)
		return m
	}
	hit := func(query *dns.Msg) *dns.Msg {
		time.Sleep(probeDelay)
		m := new(dns.Msg)
		m.SetReply(query)
		m.Answer = append(m.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: query.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: []string{expected},
		})
		return m
	}
	resolvers := []string{
		startFakeDNSServer(t, miss),
		startFakeDNSServer(t, miss),
		startFakeDNSServer(t, miss),
		startFakeDNSServer(t, hit),
	}
	originalResolvers := propagationRecursiveResolvers
	originalInterval := recursiveDNSPollInterval
	t.Cleanup(func() {
		propagationRecursiveResolvers = originalResolvers
		recursiveDNSPollInterval = originalInterval
	})
	propagationRecursiveResolvers = resolvers
	recursiveDNSPollInterval = 10 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	issuer := &Issuer{}

	if !issuer.checkRecursiveDNS(ctx, fqdn, expected) {
		t.Fatal("并行探测应在 ctx 预算内命中（串行形态会拖到 ctx 到期）")
	}
}

func nsReply(query *dns.Msg, answer ...dns.RR) *dns.Msg {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true
	response.Answer = append(response.Answer, answer...)
	return response
}

func header(name string, qtype uint16) dns.RR_Header {
	return dns.RR_Header{Name: name, Rrtype: qtype, Class: dns.ClassINET, Ttl: 60}
}

// Given：权威域同时公布 A 与 AAAA；本机无 IPv6 出口。
// When：resolveAuthoritativeNS。
// Then：AAAA 地址不参与探测清单（纯 v6 权威在无 v6 出口网络里每台白耗 16s），
// 且不发起 AAAA 查询。
func TestResolveAuthoritativeNS_skipsIPv6WhenNoLocalEgress(t *testing.T) {
	var mu sync.Mutex
	queries := map[uint16]int{}
	addr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		mu.Lock()
		queries[query.Question[0].Qtype]++
		mu.Unlock()
		name := "example.com."
		switch query.Question[0].Qtype {
		case dns.TypeNS:
			return nsReply(query, &dns.NS{Hdr: header(name, dns.TypeNS), Ns: "ns1.example.com."})
		case dns.TypeA:
			return nsReply(query, &dns.A{Hdr: header("ns1.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.10")})
		case dns.TypeAAAA:
			return nsReply(query, &dns.AAAA{Hdr: header("ns1.example.com.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::10")})
		}
		return nsReply(query)
	})
	original := ipv6EgressAvailable
	ipv6EgressAvailable = func() bool { return false }
	t.Cleanup(func() { ipv6EgressAvailable = original })

	servers := resolveAuthoritativeNS(context.Background(), "_acme-challenge.example.com.", addr)

	if len(servers) != 1 || servers[0] != "192.0.2.10:53" {
		t.Fatalf("servers=%v, want 仅 IPv4 权威", servers)
	}
	mu.Lock()
	aaaaQueries := queries[dns.TypeAAAA]
	mu.Unlock()
	if aaaaQueries != 0 {
		t.Fatalf("AAAA 查询次数=%d, want 0（无 v6 出口应预筛）", aaaaQueries)
	}
}

// Given：权威域同时公布 A 与 AAAA；本机有 IPv6 出口。
// When：resolveAuthoritativeNS。
// Then：两类地址都进入探测清单（回归形状：预筛不得误删 v6）。
func TestResolveAuthoritativeNS_keepsIPv6WhenLocalEgressAvailable(t *testing.T) {
	addr := startFakeDNSServer(t, func(query *dns.Msg) *dns.Msg {
		name := "example.com."
		switch query.Question[0].Qtype {
		case dns.TypeNS:
			return nsReply(query, &dns.NS{Hdr: header(name, dns.TypeNS), Ns: "ns1.example.com."})
		case dns.TypeA:
			return nsReply(query, &dns.A{Hdr: header("ns1.example.com.", dns.TypeA), A: net.ParseIP("192.0.2.10")})
		case dns.TypeAAAA:
			return nsReply(query, &dns.AAAA{Hdr: header("ns1.example.com.", dns.TypeAAAA), AAAA: net.ParseIP("2001:db8::10")})
		}
		return nsReply(query)
	})
	original := ipv6EgressAvailable
	ipv6EgressAvailable = func() bool { return true }
	t.Cleanup(func() { ipv6EgressAvailable = original })

	servers := resolveAuthoritativeNS(context.Background(), "_acme-challenge.example.com.", addr)

	seen := map[string]bool{}
	for _, server := range servers {
		seen[server] = true
	}
	if !seen["192.0.2.10:53"] || !seen["[2001:db8::10]:53"] {
		t.Fatalf("servers=%v, want 同时含 IPv4 与 IPv6 权威", servers)
	}
}
