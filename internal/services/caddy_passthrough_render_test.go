package services

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
)

// ── TLS 透传渲染（JJC-20261112-01 S1-b）────────────────────────────────────
//
// 本文件钉住「Layer4 SNI 分流 + 内部端口迁移」的渲染形态，以及最高优先的
// **R5 零回归**：无透传规则时渲染产物必须与改造前（main@c45efb06）逐字节一致。
//
// R5 的做法（为什么是 sha256 常量而不是读外部基线文件）：基线产物由
// main@c45efb06 的同一 fixture 渲染一次得到，取其 sha256 作为常量内嵌——测试
// 不依赖 worktree、不依赖网络，任何渲染字节漂移（含字段增删、数组顺序变化）
// 立即红。基线生成方法见文件末尾注释。

// r5FixtureSHA256 是 main@c45efb06 对 seedPassthroughRenderBaseline 同一 fixture
// 渲染产物的 sha256（见 TestPassthroughRender_无透传规则时与改造前逐字节一致）。
const r5FixtureSHA256 = "dcfc99ece8c3ecb761cbaac68d1a2145e93926713c89e0bc8cc2955f9c6a8aad"

// r5FixtureCertPEM / r5FixtureKeyPEM：R5 基线 fixture 的**确定性**证书材料。
// 必须内嵌常量而非 matchingCertificatePair(t,...) ——后者每次随机生成 RSA 密钥，
// 产物字节恒不同，R5 的「逐字节一致」断言将失去意义（也无法跨树复用基线）。
// 材料仅用于渲染（无握手），私钥为公开测试值，无安全含义。
const r5FixtureCertPEM = `-----BEGIN CERTIFICATE-----
MIIDRjCCAi6gAwIBAgIUYrZX9+ImeIo8KoqZ27sov6+fhEcwDQYJKoZIhvcNAQEL
BQAwGjEYMBYGA1UEAwwPcjUuZXhhbXBsZS50ZXN0MCAXDTI2MTExMjE5MDMwNloY
DzIxMjYxMDE5MTkwMzA2WjAaMRgwFgYDVQQDDA9yNS5leGFtcGxlLnRlc3QwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDL7CrMbGw08tqw1f+n23WmNmy6
snqqIpc7hNYzmjBa0EgxAPm/PR+MuiIdMaKuo3yJJNdJyrt9WizOo1qs/B4I/Gpz
ccGJOEUK5i5VM1DNQXxdZ7r+RKJcVW4bKBnxkjnzm8OJ4DHxb2G5Z3LrtsMbV2Rz
Ed9ES4adgjhQAtWb1md/kSlC3Rz7CPIaItkmCqzj3oaCK2w0kD2xl4/yayphdS9p
RIZ0RiisdgX1eZRmUnNbCmMKT82HTVeDqOnZnz50ULUQITQ+C+ICUxuuAXEQxtBX
TLqpCmwRYveOdjSBqUGVc+9jVEqhg2T13zFCRLTmuSCQ5qTwLmc9L6kR17iBAgMB
AAGjgYEwfzAdBgNVHQ4EFgQUfyNWb1ym6FoP5L4q9WXR3I1pve0wHwYDVR0jBBgw
FoAUfyNWb1ym6FoP5L4q9WXR3I1pve0wDwYDVR0TAQH/BAUwAwEB/zAsBgNVHREE
JTAjgg9yNS5leGFtcGxlLnRlc3SCEHRscy5leGFtcGxlLnRlc3QwDQYJKoZIhvcN
AQELBQADggEBAFmwLzmCAE+slCg3b9Ez//YV12QasEsevJFuHF3LJJ64hhsGTQ3r
rbDgpkTwCv6QnZcj4gI7i3oxrDWB6yeNj83/KJI1FrRqKO4cFq66yhKJ8fSli4YX
syS2dW3r4KlXIUgIRqTRtty2nQnDxraT+LtBHWZ06/FG5ufOb6ElIyEvl9fP1Enn
MJ3UCNjAIygNY+YHV5RWURc9WMx8dLMuuoiolXUwhGWCicsHoTX0LRP86tqYHfv7
ancR1TsmlKqO+HgQ7HGESj3hhj5+v5rqnXEYDg4of6Cagbvq/IB3/4/tZKWtpTXB
XN0398/+r0m4zhmL9QonLe2Jqw1cNUXYKXE=
-----END CERTIFICATE-----
`

const r5FixtureKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDL7CrMbGw08tqw
1f+n23WmNmy6snqqIpc7hNYzmjBa0EgxAPm/PR+MuiIdMaKuo3yJJNdJyrt9WizO
o1qs/B4I/GpzccGJOEUK5i5VM1DNQXxdZ7r+RKJcVW4bKBnxkjnzm8OJ4DHxb2G5
Z3LrtsMbV2RzEd9ES4adgjhQAtWb1md/kSlC3Rz7CPIaItkmCqzj3oaCK2w0kD2x
l4/yayphdS9pRIZ0RiisdgX1eZRmUnNbCmMKT82HTVeDqOnZnz50ULUQITQ+C+IC
UxuuAXEQxtBXTLqpCmwRYveOdjSBqUGVc+9jVEqhg2T13zFCRLTmuSCQ5qTwLmc9
L6kR17iBAgMBAAECggEARGzB7ach5eBpZjXgW4wlnXicoka6JzWFJmkL0PPXbtl9
p8fKhZN2byuTv9UEX/ImmwQcIzweDlFAQLQKfIn6cAx2kbcleCxD6oTTHi6iWcUz
/EmOsrwH+NCHqiAaGHd275mgErcCOx+jHGmsY5CHRjjcUUo5bvqiuF5WE+7niyrc
NHUGkuLv/traGMDLGFgdcvlPuDLV7eRbLuThZCBghgk4bSZcH+xdVLOwsHQ7EHQM
ikfR2vxTbkI2DiLhU5XCGmbQLDA/fgnUL+Eh13k6hDnXanLe416yRCAhbe72Uc1m
MF7utTDJsVuI2RZ9HMbABjBhPxrUMs73C/Q4GfPOGwKBgQDwpJkfEBMBwjXXsXZ1
UlxpeY9m2j9FpfJAzYxmdKs/soR50bF2qeO4eVtx6OrQqVK36uX4Q9MfMBuLSP/A
+K4QsazQexyIJi8Xk0uhLJYF/hCVTuyUD1aiFsNldFsa/qi7l9SMxlziuqdWpwl8
ng6hbQdnEK357gC8G/jfU29pPwKBgQDY76okH/KgJVI9Rgwf68mffeeB2FsXcaTr
X5fK5iWD5Y8P0fhco03zyY0UF025VCe/4ZhVq/i+ieKjc30tzyitSLiMt/vtbVvi
DTnmkMYWW/YMC3CUJKEyM1vdHkxLEOh185kTHNdhuuweXaZ93Bvlm+dRBn+Dk9hf
qlW5cxyuPwKBgB7LwbjC8tu/weo3kMRU5PSulNaByaUdJpJ6e6RE/AFr1B5O4pog
Bb9+8F/0gdBwSuC0k/egnm0YV/4MOoa0jHogctA/YRhfYpluxTf8H7rml7Kz5fzQ
tbKKnTjnmh0rR+ax+IaHgC2X24BwYftrss2fyVm8PbeFaNyp68CQyeo7AoGAEXAS
aRz4T88wMSS0TMyTRHLGbTWK/PNxokno1bJySYvmWAs0v52Q4ovM/1RwNvmAyHfF
2v0b3ZUP1rut0ETarDMwQn93jLpBrIYLpXD1u05hFM7GmeHn4zUlqTyKPW56gSC3
qUWkOoLgAADfJTbQN0C081pmXZlAx0/V3DZYk9kCgYEAsCX7RbOZve3Fu/cd7su/
SARGAGgAGmxkqOgNAVY61KcnHBRbFHsrZmY3/H8WPtMAyjpSLVreQHu8TtmV6NBi
EKeYsWb6gFR4WEdf0Ym/xhilGus8FgWK9wo96+TUeOSev8A9OwWjWMlj+77EeU5q
qxbl8vgzxHrkOJcqNwQVwFQ=
-----END PRIVATE KEY-----
`

// seedPassthroughRenderFixture 构造 R5 基线 fixture：混合协议（HTTP TLS 规则 /
// HTTP 明文规则 / TCP 规则）、多端口、日志启用——覆盖面足以让「改造时误改
// 公共渲染路径」暴露为字节差异。**不含任何 passthrough 规则**（R5 的前提）。
// 当前树与基线树（main@c45efb06）跑同一份种子，产物应逐字节相同。
func seedPassthroughRenderFixture(t *testing.T, database *sql.DB) {
	t.Helper()
	useTemporaryCertDir(t)

	// HTTP + TLS（固定手动证书）：进 publishedHTTPRules、
	// tls_connection_policies、tls.certificates.load_files、logger_names。
	seedHTTPRuleForGeneration(t, database, "lb_r5_tls", "tls.example.test", 18443)
	if _, err := database.Exec(`UPDATE lb_rules SET enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1, log_enabled=1
		WHERE caddy_id='lb_r5_tls'`, r5FixtureCertPEM, r5FixtureKeyPEM); err != nil {
		t.Fatalf("配置 R5 TLS 规则: %v", err)
	}

	// HTTP 明文（80 端口）：覆盖默认站 + 跳转路由落点分支。
	seedHTTPRuleForGeneration(t, database, "lb_r5_plain", "plain.example.test", DefaultHTTPPort())

	// TCP 规则：layer4 tcp_<port> server（含健康检查族）。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,enable_active_health_check,tcp_health_check_port)
		VALUES ('lb_r5_tcp','lb_r5_tcp','tcp','',19000,'weighted_round_robin',1,1,19001)`); err != nil {
		t.Fatalf("seed R5 TCP 规则: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_r5_tcp','127.0.0.1',19002,1,1,'tcp')`); err != nil {
		t.Fatalf("seed R5 TCP 上游: %v", err)
	}
}

// 用生产渲染链渲染 seedPassthroughRenderFixture 的库，返回 (归一化 sha256,
// 归一化字节)。全量断言（布局/字段）走各自的钉测，本函数只服务 R5 字节比对与
// 可选导出。
//
// **归一化只做一件事**：把证书落盘目录（certDir = t.TempDir()，每次随机）替换为
// 固定占位符。这是唯一与渲染逻辑无关的非确定性来源（load_files 的
// certificate/key 路径）；除此之外**一个字节都不放过**——字段增删、数组顺序
// 变化、数值差异都会改变 sha256。基线常量同样按此口径生成（见文件末尾）。
func passthroughRenderFixtureDigest(t *testing.T, database *sql.DB) (string, []byte) {
	t.Helper()
	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("渲染失败: %s", message)
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal 渲染产物: %v", err)
	}
	data = normalizeCertDirInRender(data, certDir)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), data
}

// normalizeCertDirInRender 把产物中的证书落盘目录替换为固定占位符
// （理由见 passthroughRenderFixtureDigest）。
func normalizeCertDirInRender(data []byte, dir string) []byte {
	if dir == "" {
		return data
	}
	return bytes.ReplaceAll(data, []byte(dir), []byte("<CERT_DIR>"))
}

// emitFixtureIfRequested 在设置 CADDY_PT_FIXTURE_OUT 时把渲染产物落盘
// （仅用于人工生成/复核 R5 基线；常规 go test 不产生文件）。
func emitFixtureIfRequested(t *testing.T, data []byte) {
	t.Helper()
	out := os.Getenv("CADDY_PT_FIXTURE_OUT")
	if out == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
		t.Fatalf("mkdir for emit: %v", err)
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		t.Fatalf("emit fixture to %s: %v", out, err)
	}
	t.Logf("fixture 产物已写出 %d 字节 → %s", len(data), out)
}

// ── R5 零回归（红线）─────────────────────────────────────────────────────────

// Given: 无任何 passthrough 规则的固定混合态库（HTTP TLS / HTTP 明文 / TCP）
// When: 用生产渲染链生成配置
// Then: 产物 sha256 与 main@c45efb06 的同 fixture 产物常量一致——**逐字节零变化**
//
// 红了不许放宽断言：先确认差异是「透传特性引入的公共路径改动」还是「常量过期」，
// 前者必须修代码，后者必须重跑基线并写明原因。
func TestPassthroughRender_noPassthroughRulesByteIdenticalToBaseline(t *testing.T) {
	_, database := newClusterTestService(t)
	seedPassthroughRenderFixture(t, database)

	digest, data := passthroughRenderFixtureDigest(t, database)
	emitFixtureIfRequested(t, data)

	if r5FixtureSHA256 == "R5_PLACEHOLDER_TO_BE_FILLED" {
		t.Fatalf("R5 基线常量未填充：当前 fixture 产物 sha256=%s\n把该值写入 r5FixtureSHA256（来源须为 main@c45efb06 的同 fixture 渲染）", digest)
	}
	if digest != r5FixtureSHA256 {
		t.Fatalf("R5 红线：无透传规则的渲染产物与改造前不一致\n got sha256=%s\nwant sha256=%s\n产物=%s",
			digest, r5FixtureSHA256, truncateForLog(data))
	}
}

// ── Layer4 渲染形态 ─────────────────────────────────────────────────────────

// Given: 一条启用的透传规则（SNI → 上游 host:port）
// When: 渲染
// Then: layer4 出现 tls_<port> server；SNI 路由 matcher 正确、dial 正确；
// 兜底路由注 PROXY v2 指向内部终结口；且该端口 HTTP server 完成监听迁移
// 与 listener_wrappers 挂载（wrapper 顺序 proxy_protocol 先于 tls）。
func TestPassthroughRender_layer4SNISplitAndInternalPortMigration(t *testing.T) {
	_, database := newClusterTestService(t)
	seedPassthroughRuleForRender(t, database, "lb_pt_main", "pass.example.test", "10.0.0.9:10443", DefaultHTTPSPort(), true)

	cfg := mustRenderOK(t, database)
	port := DefaultHTTPSPort()

	// Layer4：tls_<port> server
	l4Servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["layer4"], "layer4")["servers"], "servers")
	serverName := fmt.Sprintf("tls_%d", port)
	serverVal, exists := l4Servers[serverName]
	if !exists {
		t.Fatalf("layer4 servers 缺少 %s；键集=%v", serverName, mapKeys(l4Servers))
	}
	l4Server := mustMap(t, serverVal, serverName)
	listen, _ := l4Server["listen"].([]string)
	if !reflect.DeepEqual(listen, []string{fmt.Sprintf(":%d", port)}) {
		t.Fatalf("%s listen=%v, want [\":%d\"]", serverName, listen, port)
	}
	routes := mustSlice(t, l4Server["routes"], "routes")
	if len(routes) != 2 {
		t.Fatalf("%s routes 条数=%d, want 2（SNI 路由 + 兜底）", serverName, len(routes))
	}

	// routes[0]：SNI 分流
	sniRoute := mustMap(t, routes[0], "routes[0]")
	if got, _ := sniRoute["@id"].(string); got != "lb_pt_main" {
		t.Fatalf("routes[0].@id=%q, want lb_pt_main", got)
	}
	match := mustSlice(t, sniRoute["match"], "match")
	if len(match) != 1 {
		t.Fatalf("routes[0].match 条数=%d, want 1", len(match))
	}
	tlsMatch := mustMap(t, mustMap(t, match[0], "match[0]")["tls"], "tls")
	sni, _ := tlsMatch["sni"].([]string)
	if !reflect.DeepEqual(sni, []string{"pass.example.test"}) {
		t.Fatalf("matcher sni=%v, want [pass.example.test]", sni)
	}
	sniHandler := mustMap(t, mustSlice(t, sniRoute["handle"], "handle")[0], "handle[0]")
	if sniHandler["handler"] != "proxy" {
		t.Fatalf("SNI 路由 handler=%v, want proxy", sniHandler["handler"])
	}
	if dial := mustDial(t, sniHandler); dial != "10.0.0.9:10443" {
		t.Fatalf("SNI 路由 dial=%q, want 10.0.0.9:10443", dial)
	}

	// routes[1]：兜底 → 内部终结口 + PROXY v2
	fallbackRoute := mustMap(t, routes[1], "routes[1]")
	if _, hasMatch := fallbackRoute["match"]; hasMatch {
		t.Fatalf("兜底路由不得带 match（须恒匹配）: %v", fallbackRoute["match"])
	}
	fallbackHandler := mustMap(t, mustSlice(t, fallbackRoute["handle"], "handle")[0], "handle[0]")
	if got := mustDial(t, fallbackHandler); got != internalTerminateAddr() {
		t.Fatalf("兜底路由 dial=%q, want %q", got, internalTerminateAddr())
	}
	if got, _ := fallbackHandler["proxy_protocol"].(string); got != "v2" {
		t.Fatalf("兜底路由 proxy_protocol=%q, want v2（注入真实源 IP）", got)
	}

	// HTTP app：该端口 listen 迁移 + listener_wrappers
	httpServers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	httpServer := mustMap(t, httpServers[fmt.Sprintf("http_%d", port)], "http server")
	httpListen, _ := httpServer["listen"].([]string)
	wantListen := []string{"tcp/127.0.0.1:" + strconv.Itoa(internalTerminatePort), fmt.Sprintf("udp/:%d", port)}
	if !reflect.DeepEqual(httpListen, wantListen) {
		t.Fatalf("http_%d listen=%v, want %v（TCP 退内部回环、UDP 留公网给 HTTP/3）", port, httpListen, wantListen)
	}

	wrappers := mustSlice(t, httpServer["listener_wrappers"], "listener_wrappers")
	if len(wrappers) != 2 {
		t.Fatalf("listener_wrappers 条数=%d, want 2（proxy_protocol + tls）", len(wrappers))
	}
	ppWrapper := mustMap(t, wrappers[0], "listener_wrappers[0]")
	if ppWrapper["wrapper"] != "proxy_protocol" {
		t.Fatalf("listener_wrappers[0]=%v, want proxy_protocol 在前（须先于 TLS 握手剥头）", ppWrapper)
	}
	allow, _ := ppWrapper["allow"].([]string)
	if !reflect.DeepEqual(allow, []string{"127.0.0.1/32"}) {
		t.Fatalf("proxy_protocol allow=%v, want [127.0.0.1/32]（仅信 Layer4 出站）", allow)
	}
	if got, _ := ppWrapper["fallback_policy"].(string); got != "reject" {
		t.Fatalf("proxy_protocol fallback_policy=%q, want reject（外部伪造头必须被拒）", got)
	}
	if tlsWrapper := mustMap(t, wrappers[1], "listener_wrappers[1]"); tlsWrapper["wrapper"] != "tls" {
		t.Fatalf("listener_wrappers[1]=%v, want tls", tlsWrapper)
	}
}

// ── 混合态：同端口 HTTP 规则与透传规则共存 ───────────────────────────────────

// Given: 同端口（HTTPS 默认口）一条 HTTP TLS 规则 + 一条透传规则
// When: 渲染
// Then: HTTP 规则的路由完整性不变（只是监听地址迁移），且透传规则不产生
// 任何 HTTP 路由 / TLS 连接策略 / 错误归因路由。
func TestPassthroughRender_mixedPortKeepsHTTPRoutesIntact(t *testing.T) {
	_, database := newClusterTestService(t)
	port := DefaultHTTPSPort()
	useTemporaryCertDir(t)
	certPEM, keyPEM := matchingCertificatePair(t, "term.example.test")
	seedHTTPRuleForGeneration(t, database, "lb_pt_term", "term.example.test", port)
	// 该 HTTP 规则启用 TLS + 手动证书，使其真正进入 publishedHTTPRules。
	if _, err := database.Exec(`UPDATE lb_rules SET enable_tls=1, tls_source='manual', tls_cert=?, tls_key=? WHERE caddy_id='lb_pt_term'`, certPEM, keyPEM); err != nil {
		t.Fatalf("配置 HTTP 规则手动证书: %v", err)
	}
	seedPassthroughRuleForRender(t, database, "lb_pt_mix", "pass.example.test", "10.0.0.9:10443", port, true)

	cfg := mustRenderOK(t, database)

	httpServers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	httpServer := mustMap(t, httpServers[fmt.Sprintf("http_%d", port)], "http server")
	routes := mustSlice(t, httpServer["routes"], "routes")

	// HTTP 规则的路由必须在，且只由 HTTP 规则产生（透传零 HTTP 路由）。
	var httpRouteIDs []string
	for _, rv := range routes {
		if id, ok := mustMap(t, rv, "route")["@id"].(string); ok && id != "" {
			httpRouteIDs = append(httpRouteIDs, id)
		}
	}
	foundTerm := false
	for _, id := range httpRouteIDs {
		if id == "lb_pt_term" {
			foundTerm = true
		}
		if id == "lb_pt_mix" {
			t.Fatalf("透传规则泄漏进 HTTP 路由（@id=lb_pt_mix）——其流量应在 Layer4 按 SNI 分走")
		}
	}
	if !foundTerm {
		t.Fatalf("同端口 HTTP 规则路由丢失：@id 集合=%v", httpRouteIDs)
	}

	// TLS 连接策略只服务本地终结规则。
	tlsPolicies := mustSlice(t, httpServer["tls_connection_policies"], "tls_connection_policies")
	if len(tlsPolicies) != 1 {
		t.Fatalf("tls_connection_policies 条数=%d, want 1（仅本地终结规则）", len(tlsPolicies))
	}
	if tags := mustMap(t, mustMap(t, tlsPolicies[0], "policy")["certificate_selection"], "certificate_selection")["any_tag"]; !reflect.DeepEqual(tags, []interface{}{"lb_pt_term"}) && !reflect.DeepEqual(tags, []string{"lb_pt_term"}) {
		t.Fatalf("tls_connection_policies[0].any_tag=%v, want [lb_pt_term]", tags)
	}

	// Layer4 同时存在该端口的分流 server。
	l4Servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["layer4"], "layer4")["servers"], "servers")
	if _, exists := l4Servers[fmt.Sprintf("tls_%d", port)]; !exists {
		t.Fatalf("layer4 servers 缺少 tls_%d（透传端口必须插入前置）", port)
	}
}

// ── 多 SNI 聚合 ─────────────────────────────────────────────────────────────

// Given: 同端口三条透传规则（不同 SNI，其中一条禁用）
// When: 渲染
// Then: 仅启用规则各成一条 SNI 路由，聚合进同一 Layer4 server；禁用规则缺席。
// 这与 TCP 的「同端口多规则即全部跳过」语义相反——SNI 分流天然支持多域名。
func TestPassthroughRender_multipleSNIsAggregateInOneServer(t *testing.T) {
	_, database := newClusterTestService(t)
	port := DefaultHTTPSPort()
	seedPassthroughRuleForRender(t, database, "lb_pt_a", "a.example.test", "10.0.0.9:10443", port, true)
	seedPassthroughRuleForRender(t, database, "lb_pt_w", "*.wild.example.test", "10.0.0.10:10443", port, true)
	seedPassthroughRuleForRender(t, database, "lb_pt_off", "off.example.test", "10.0.0.11:10443", port, false)

	cfg := mustRenderOK(t, database)
	l4Servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["layer4"], "layer4")["servers"], "servers")
	serverName := fmt.Sprintf("tls_%d", port)
	l4Server := mustMap(t, l4Servers[serverName], serverName)
	routes := mustSlice(t, l4Server["routes"], "routes")

	gotSNI := map[string]string{} // sni -> dial
	fallbackCount := 0
	for _, rv := range routes {
		route := mustMap(t, rv, "route")
		match, hasMatch := route["match"]
		if !hasMatch {
			fallbackCount++
			continue
		}
		tlsMatch := mustMap(t, mustMap(t, mustSlice(t, match, "match")[0], "match[0]")["tls"], "tls")
		sniList, _ := tlsMatch["sni"].([]string)
		if len(sniList) != 1 {
			t.Fatalf("单规则 SNI 集合=%v, want 恰一项（聚合按 route 分列，不合并）", sniList)
		}
		handler := mustMap(t, mustSlice(t, route["handle"], "handle")[0], "handle[0]")
		gotSNI[sniList[0]] = mustDial(t, handler)
	}

	want := map[string]string{
		"a.example.test":      "10.0.0.9:10443",
		"*.wild.example.test": "10.0.0.10:10443",
	}
	if !reflect.DeepEqual(gotSNI, want) {
		t.Fatalf("聚合 SNI→dial 映射=%v, want %v（禁用规则必须缺席）", gotSNI, want)
	}
	if fallbackCount != 1 {
		t.Fatalf("兜底路由条数=%d, want 恰 1（多 SNI 共用一条兜底）", fallbackCount)
	}
}

// ── 上游地址形态（含 IPv6 字面量）──────────────────────────────────────────

// Given: 透传上游为 IPv6 字面量（两种书写形态）与常规 host:port
// When: 渲染
// Then: dial 统一为 net.JoinHostPort 口径（IPv6 带方括号），与
// joinUpstreamAddress 同源，避免 Caddy 端解析歧义。
func TestPassthroughRender_upstreamDialUsesJoinHostPort(t *testing.T) {
	for _, tc := range []struct {
		name, stored, want string
	}{
		{name: "IPv4 host:port", stored: "10.0.0.9:10443", want: "10.0.0.9:10443"},
		{name: "IPv6 bracketed", stored: "[::1]:10443", want: "[::1]:10443"},
		{name: "IPv6 full bracketed", stored: "[2001:db8::5]:10443", want: "[2001:db8::5]:10443"},
		{name: "surrounding spaces", stored: "  10.0.0.9:10443  ", want: "10.0.0.9:10443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := passthroughDialAddress(tc.stored)
			if err != nil {
				t.Fatalf("passthroughDialAddress(%q) 出错: %v", tc.stored, err)
			}
			if got != tc.want {
				t.Fatalf("passthroughDialAddress(%q)=%q, want %q", tc.stored, got, tc.want)
			}
			// 与既有 joinUpstreamAddress 同口径：拆回 host/port 再拼必须幂等。
			host, portText, splitErr := net.SplitHostPort(got)
			if splitErr != nil {
				t.Fatalf("结果 %q 不是合法 host:port: %v", got, splitErr)
			}
			port, _ := strconv.Atoi(portText)
			if rebuilt := joinUpstreamAddress(host, port); rebuilt != got {
				t.Fatalf("%q 经 joinUpstreamAddress 往返变 %q（口径分叉）", got, rebuilt)
			}
		})
	}

	// 非法形态显性报错，不静默产出坏 dial。
	// 裸 IPv6 末段（"::1:10443"）同样必须拒绝：多个冒号下 host/port 边界有歧义
	// （net.SplitHostPort 报 too many colons），保存门同样要求方括号写法。
	for _, bad := range []string{"", "   ", "no-port", "host:0", "host:70000", "host:abc", ":10443", "::1:10443"} {
		if got, err := passthroughDialAddress(bad); err == nil {
			t.Fatalf("passthroughDialAddress(%q) 应报错，却返回 %q", bad, got)
		}
	}
}

// ── 透传规则的 TCP 字段语义（proxy_protocol / 健康检查）────────────────────

// Given: 透传规则开启 tcp_proxy_protocol 与主动 TCP 健康检查
// When: 渲染
// Then: SNI 路由的 proxy handler 带上 proxy_protocol=v2 与
// health_checks.active（TCP 连接探测），参数与 TCP 路径同源。
func TestPassthroughRender_proxyProtocolAndHealthCheck(t *testing.T) {
	_, database := newClusterTestService(t)
	port := DefaultHTTPSPort()
	seedPassthroughRuleForRender(t, database, "lb_pt_hc", "hc.example.test", "10.0.0.9:10443", port, true)
	if _, err := database.Exec(`UPDATE lb_rules SET tcp_proxy_protocol=1, enable_active_health_check=1, health_check_interval=7, health_check_timeout=3, health_check_unhealthy_threshold=4, health_check_healthy_threshold=2, tcp_health_check_port=18443 WHERE caddy_id='lb_pt_hc'`); err != nil {
		t.Fatalf("配置透传健康检查: %v", err)
	}

	cfg := mustRenderOK(t, database)
	handler := passthroughRouteHandler(t, cfg, port, "hc.example.test")
	if got, _ := handler["proxy_protocol"].(string); got != "v2" {
		t.Fatalf("透传 SNI 路由 proxy_protocol=%q, want v2（复用 tcp_proxy_protocol 语义）", got)
	}
	active := mustMap(t, mustMap(t, handler["health_checks"], "health_checks")["active"], "active")
	if active["interval"] != "7s" || active["timeout"] != "3s" || active["fall"] != 4 || active["rise"] != 2 {
		t.Fatalf("active 健康检查=%v, want interval=7s timeout=3s rise=2 fall=4", active)
	}
	if active["port"] != 18443 {
		t.Fatalf("active.port=%v, want 18443（tcp_health_check_port）", active["port"])
	}
}

// ── 无透传规则端口保持原形态（分端口零回归）────────────────────────────────

// Given: HTTPS 端口有透传规则，而另一端口（8080）只有 HTTP 规则
// When: 渲染
// Then: 8080 的 listen 仍为公网 `:8080`、无 listener_wrappers；只有透传端口
// 被迁移——R5「分端口启用」语义。
func TestPassthroughRender_otherPortsKeepPublicListen(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_pt_plain", "plain.example.test", 8080)
	seedPassthroughRuleForRender(t, database, "lb_pt_scope", "scope.example.test", "10.0.0.9:10443", DefaultHTTPSPort(), true)

	cfg := mustRenderOK(t, database)
	httpServers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")

	plain := mustMap(t, httpServers["http_8080"], "http_8080")
	if listen, _ := plain["listen"].([]string); !reflect.DeepEqual(listen, []string{":8080"}) {
		t.Fatalf("http_8080 listen=%v, want [\":8080\"]（无透传规则的端口零变化）", listen)
	}
	if _, has := plain["listener_wrappers"]; has {
		t.Fatalf("http_8080 不得挂 listener_wrappers（该端口无 Layer4 前置）")
	}
}

// ── 数据完整性 fail-closed ─────────────────────────────────────────────────

// Given: 带外写入的启用透传行缺 passthrough_upstream
// When: 渲染
// Then: 该规则被跳过并告警，整份配置仍生成成功（不拖垮其他规则）；
// 该端口不出现 Layer4 server（无有效透传规则）。
func TestPassthroughRender_missingUpstreamSkipsRuleNotWholeConfig(t *testing.T) {
	_, database := newClusterTestService(t)
	seedHTTPRuleForGeneration(t, database, "lb_pt_ok", "ok.example.test", 8080)
	// 直接 INSERT 绕过保存门，构造带外脏行。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,passthrough_upstream) VALUES ('lb_pt_dirty','dirty','passthrough','dirty.example.test',?,'weighted_round_robin',1,'')`, DefaultHTTPSPort()); err != nil {
		t.Fatalf("seed 脏透传行: %v", err)
	}

	cfg := mustRenderOK(t, database)
	// 健康的 HTTP 规则仍在。
	httpServers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["http"], "http")["servers"], "servers")
	if _, exists := httpServers["http_8080"]; !exists {
		t.Fatalf("脏透传行不得拖垮其他端口的规则：http_8080 缺失")
	}
	// 该端口无有效透传规则 → 不插入 Layer4 前置。
	if layer4, has := cfg["apps"].(map[string]interface{})["layer4"]; has {
		l4Servers, _ := layer4.(map[string]interface{})["servers"].(map[string]interface{})
		if _, exists := l4Servers[fmt.Sprintf("tls_%d", DefaultHTTPSPort())]; exists {
			t.Fatalf("缺上游的透传规则不应产出 Layer4 server")
		}
	}
}

// ── 测试辅助 ───────────────────────────────────────────────────────────────

// seedPassthroughRuleForRender 种一条 passthrough 规则（upstreams 表零行，
// 上游走 passthrough_upstream 单值列——与保存链同终态）。
func seedPassthroughRuleForRender(t *testing.T, database *sql.DB, caddyID, domain, upstream string, listenPort int, enabled bool) {
	t.Helper()
	enabledVal := 0
	if enabled {
		enabledVal = 1
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,passthrough_upstream)
		VALUES (?,?,'passthrough',?,?,'weighted_round_robin',?,?)`, caddyID, caddyID, domain, listenPort, enabledVal, upstream); err != nil {
		t.Fatalf("seed passthrough rule %s: %v", caddyID, err)
	}
}

func mustRenderOK(t *testing.T, database *sql.DB) map[string]interface{} {
	t.Helper()
	cfg := generateCaddyConfigFromStore(database)
	if message, failed := cfg[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("渲染失败: %s", message)
	}
	return cfg
}

// passthroughRouteHandler 取指定端口下指定 SNI 的透传 proxy handler。
func passthroughRouteHandler(t *testing.T, cfg map[string]interface{}, port int, sni string) map[string]interface{} {
	t.Helper()
	l4Servers := mustMap(t, mustMap(t, mustMap(t, cfg["apps"], "apps")["layer4"], "layer4")["servers"], "servers")
	serverName := fmt.Sprintf("tls_%d", port)
	l4Server := mustMap(t, l4Servers[serverName], serverName)
	for _, rv := range mustSlice(t, l4Server["routes"], "routes") {
		route := mustMap(t, rv, "route")
		match, hasMatch := route["match"]
		if !hasMatch {
			continue
		}
		tlsMatch := mustMap(t, mustMap(t, mustSlice(t, match, "match")[0], "match[0]")["tls"], "tls")
		sniList, _ := tlsMatch["sni"].([]string)
		if len(sniList) == 1 && sniList[0] == sni {
			return mustMap(t, mustSlice(t, route["handle"], "handle")[0], "handle[0]")
		}
	}
	t.Fatalf("%s 下找不到 SNI=%s 的透传路由", serverName, sni)
	return nil
}

// mustDial 取 proxy handler 的首个 upstream dial。
func mustDial(t *testing.T, handler map[string]interface{}) string {
	t.Helper()
	ups := mustSlice(t, handler["upstreams"], "upstreams")
	if len(ups) != 1 {
		t.Fatalf("upstreams 条数=%d, want 1（透传上游单值）", len(ups))
	}
	dials, ok := mustMap(t, ups[0], "upstream")["dial"].([]string)
	if !ok || len(dials) != 1 {
		t.Fatalf("upstream.dial 形态非法: %v", mustMap(t, ups[0], "upstream")["dial"])
	}
	return dials[0]
}

// mustSlice 是测试内断言辅助：把渲染产物里的 JSON 数组断言为 []interface{}
// （panic 位置即断言失败点，测试内可接受）。
func mustSlice(t *testing.T, value interface{}, label string) []interface{} {
	t.Helper()
	slice, ok := value.([]interface{})
	if !ok {
		t.Fatalf("%s 类型=%T, want []interface{}", label, value)
	}
	return slice
}
