package services

// 规则传输归一的同族收敛（「没有就都应该没有」）：TCP 的 upstreams.origin_domain
// 与 HTTP 的跨模式 TLS 残留都必须与保存族/启动迁移/导入归一同口径——否则同一
// 终态在主端库、导出 canonical、从端落库三面分叉（rules 节哈希恒不等），且
// TCP 残留会让自身备份在导入校验被整包拒绝。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestNormalizeUpstreamForTransport_tcpClearsOriginDomain(t *testing.T) {
	tcp := models.Upstream{Host: "10.0.0.1", Port: 8080, DynamicDNS: true, OriginDomain: "stale.example.test"}
	normalizeUpstreamForTransport(&tcp, "tcp")
	if tcp.OriginDomain != "" {
		t.Fatalf("tcp upstream origin=%q, want 清零", tcp.OriginDomain)
	}
	if tcp.DynamicDNS {
		t.Fatal("dynamic_dns 废弃列必须恒 0")
	}

	httpUpstream := models.Upstream{Host: "10.0.0.2", Port: 443, OriginDomain: "keep.example.test"}
	normalizeUpstreamForTransport(&httpUpstream, "http")
	if httpUpstream.OriginDomain != "keep.example.test" {
		t.Fatalf("http upstream origin=%q, want 保留", httpUpstream.OriginDomain)
	}
}

func TestNormalizeRuleForTransport_httpCrossModeTLSResidue(t *testing.T) {
	// acme_dns 携带内联材料：材料清零，CA 引用保留。
	acme := models.LbRule{Protocol: "http", TLSSource: "acme_dns", TLSCert: "CERT", TLSKey: "KEY", CAProviderID: 4, ACMEConfigID: 2}
	normalizeRuleForTransport(&acme)
	if acme.TLSCert != "" || acme.TLSKey != "" {
		t.Fatalf("acme rule cert=%q key=%q, want 清零（非 manual 不保留材料）", acme.TLSCert, acme.TLSKey)
	}
	if acme.CAProviderID != 4 {
		t.Fatalf("acme rule ca_provider_id=%d, want 4（acme 源保留）", acme.CAProviderID)
	}

	// manual 携带 ACME/CA 引用：两引用清零，材料保留。
	manual := models.LbRule{Protocol: "http", TLSSource: "manual", TLSCert: "CERT2", TLSKey: "KEY2", ACMEConfigID: 7, CAProviderID: 9}
	normalizeRuleForTransport(&manual)
	if manual.ACMEConfigID != 0 || manual.CAProviderID != 0 {
		t.Fatalf("manual rule acme=%d ca=%d, want 0/0", manual.ACMEConfigID, manual.CAProviderID)
	}
	if manual.TLSCert != "CERT2" || manual.TLSKey != "KEY2" {
		t.Fatalf("manual rule cert=%q key=%q, want 保留", manual.TLSCert, manual.TLSKey)
	}
}

// TCP 传输归一的清零清单必须与保存族/迁移 SQL 同口径：domain /
// log_enabled / dns_family 对 TCP 均零消费，带外脏行不得经快照带到从端。
func TestNormalizeRuleForTransport_tcpClearsDomainLogAndDnsFamily(t *testing.T) {
	rule := models.LbRule{
		Protocol: "tcp", Domain: "stale.example.test", LogEnabled: true, DnsFamily: "ipv6",
		Strategy: "weighted_round_robin",
	}
	normalizeRuleForTransport(&rule)
	if rule.Domain != "" {
		t.Fatalf("tcp domain=%q, want 清零", rule.Domain)
	}
	if rule.LogEnabled {
		t.Fatal("tcp log_enabled 必须归 0")
	}
	if rule.DnsFamily != "ipv4" {
		t.Fatalf("tcp dns_family=%q, want ipv4（与建库默认同形）", rule.DnsFamily)
	}

	// HTTP 行不受影响（三列均有消费语义）。
	httpRule := models.LbRule{Protocol: "http", Domain: "keep.example.test", LogEnabled: true, DnsFamily: "ipv6"}
	normalizeRuleForTransport(&httpRule)
	if httpRule.Domain != "keep.example.test" || !httpRule.LogEnabled || httpRule.DnsFamily != "ipv6" {
		t.Fatalf("http 行被误清: domain=%q log=%v dns=%q", httpRule.Domain, httpRule.LogEnabled, httpRule.DnsFamily)
	}
}

// 三面同构的落库侧：从端插入快照上游前必须归零 TCP 回源域名。
func TestInsertSnapshotRules_tcpUpstreamOriginCleared(t *testing.T) {
	_, database := newClusterTestService(t)
	ctx := context.Background()
	rule := models.LbRule{
		CaddyID: "lb_tcporigin2", Name: "tcporigin", Protocol: "tcp", ListenPort: 9500,
		Strategy: "weighted_round_robin", Enabled: true,
		Upstreams: []models.Upstream{{Host: "10.1.1.1", Port: 8080, Weight: 1, Enabled: true, Protocol: "http", OriginDomain: "stale.example.test"}},
	}
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := insertSnapshotRules(ctx, tx, []models.LbRule{rule}); err != nil {
		t.Fatalf("insertSnapshotRules: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var origin string
	if err := database.QueryRow(`SELECT COALESCE(origin_domain,'') FROM upstreams WHERE rule_id='lb_tcporigin2'`).Scan(&origin); err != nil {
		t.Fatalf("read upstream: %v", err)
	}
	if origin != "" {
		t.Fatalf("tcp upstream origin=%q, want 清零（落库与导出 canonical 同形）", origin)
	}
}
