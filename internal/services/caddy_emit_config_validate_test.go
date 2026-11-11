package services

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// ── 渲染产物 → Caddy 真实解码链（跨模块常驻钉子）─────────────────────────────
//
// 为什么落在本包：**Caddy 解码链只能在能 import caddy 的模块里跑**。本仓主模块
// （`lazy-balancer-v2`）刻意不依赖 `github.com/caddyserver/caddy/v2`（Caddy 由
// xcaddy `--with` 单独编译，见 Dockerfile:29-72），`internal/services` 因此拿不到
// `caddyhttp.Route` / `caddy.Context.LoadModule`。解码断言的执行体落在
// `caddygeoip/caddy_decode_generated_config_test.go`（该模块必然依赖 caddy）。
//
// 本文件承担另一半：**产出**。用生产渲染链生成完整 Caddy 配置（混合态 +
// 自定义路由，即 P 组场景），序列化到 `CADDY_DECODE_CONFIG_OUT` 指定的临时文件。
// caddygeoip 侧的钉子 `TestCaddyDecodeChain_generatedConfigLoads` 通过
// `go test ... -exec` 包装器把「本包生成」与「对端解码」串成一条链——任一侧
// 断了，对端用例红。
//
// 常驻性：`go test ./internal/services/` 会跑本文件（渲染断言），
// 解码侧由 `go test ./internal/services/ ./caddygeoip/` 与
// `/bin/bash scripts/gate.sh` 覆盖（gate 的模块循环执行全部模块测试）。
//
// 历史教训（TASK-2026-1111-02 r1 风控 P1-1）：上一轮把「配置可被 Caddy 加载」
// 写成 §7 里一条**仓库内不存在**的命令 + 一个无来源的 /tmp 产物 → 证据不可
// 复现。本文件把该证据变成仓库内可跑、跟着测试一起跑的资产。

// caddyDecodeEmitEnv 为「生成给对端解码」的开关（值为输出文件路径）。
// 默认不写真值：常规 `go test` 不产生多余文件；钉子用包装器显式打开。
const caddyDecodeEmitEnv = "CADDY_DECODE_CONFIG_OUT"

// buildMixedOriginScenarioDB 构造本特性最难的一段渲染产物来源：规则级 B.com，
// 三条上游（192.168.42.2 无逐上游值 / C.com 与 D.com 各带自己的 origin_domain），
// 四条自定义路由（/img/ → C.com、/ → 192.168.42.2、/admin → D.com、/api → 表外
// X.com）。回源 Host 全部由渲染期内部推导（规则设定零回源 Host 字段，
// 董事长 2026-10-10 裁定 0c8ec276）。
func buildMixedOriginScenarioDB(t *testing.T, ruleID string) map[string]interface{} {
	t.Helper()
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, ruleID, true)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='A.com', host_header='B.com', listen_port=18471 WHERE caddy_id=?`, ruleID); err != nil {
		t.Fatalf("update rule: %v", err)
	}
	if _, err := database.Exec(`DELETE FROM upstreams WHERE rule_id=?`, ruleID); err != nil {
		t.Fatalf("clear upstreams: %v", err)
	}
	for _, u := range []struct {
		host, protocol, originDomain string
		port                         int
	}{
		{"192.168.42.2", "http", "", 40080},
		{"C.com", "https", "C.com", 443},
		{"D.com", "https", "D.com", 443},
	} {
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain) VALUES (?,?,?,1,1,?,?)`,
			ruleID, u.host, u.port, u.protocol, u.originDomain); err != nil {
			t.Fatalf("seed upstream %s: %v", u.host, err)
		}
	}
	pathRules := []struct {
		path, host, protocol string
		port                 int
	}{
		{"/img/", "C.com", "https", 443},
		{"/", "192.168.42.2", "http", 40080},
		{"/admin", "D.com", "https", 443},
		{"/api", "X.com", "https", 443},
	}
	for index, pr := range pathRules {
		upstreamsJSON := fmt.Sprintf(`[{"address":%q,"port":%d,"weight":100,"protocol":%q}]`, pr.host, pr.port, pr.protocol)
		if _, err := database.Exec(`INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstream_path,upstreams_json,response_mode,response_status,response_body,response_content_type,redirect_to,updated_at)
			VALUES (?,?, 'prefix', ?, '', ?, 'proxy', 0, '', '', '', datetime('now'))`, ruleID, index, pr.path, upstreamsJSON); err != nil {
			t.Fatalf("seed path rule %s: %v", pr.path, err)
		}
	}

	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generation failed: %s", message)
	}
	return generated
}

// Given: 生产渲染链生成的完整配置（混合态 + 自定义路由，含 lb_upstream_host）
// When: 序列化为 Caddy 可直接 consume 的 JSON 文本
// Then: 产物自洽——lb_upstream_host 节点在、其 hosts 映射与推导一致、且
// 整份配置不含 {http.request.hostport}（H2 在**产物层**再兜一次）
func TestEmitConfigForValidate_emitsMixedOriginConfig(t *testing.T) {
	// ruleID 与 caddygeoip 侧钉子（caddy_decode_generated_config_test.go）的
	// 路由 @id 断言同源：改名须两侧同步。
	generated := buildMixedOriginScenarioDB(t, "lb_emit_check")

	body, err := json.MarshalIndent(generated, "", "  ")
	if err != nil {
		t.Fatalf("marshal generated config: %v", err)
	}

	// 产物层 H2：整份 JSON 文本里不得出现客户端 Host 占位符。
	if len(body) == 0 {
		t.Fatal("marshalled config is empty")
	}
	if containsSubstring(body, "{http.request.hostport}") {
		t.Fatalf("生成配置含客户端 Host 占位符（H2 禁止）")
	}

	// 混合态必须在产物里留下 lb_upstream_host 节点，且 hosts 与三级回退一致：
	// 第一档（C.com/D.com 的 origin_domain）与第二档（规则级 B.com，作用于
	// / 的 192.168.42.2）同池共存——这正是上游 map 方案表达不了、也是本自研
	// 能力的价值点。
	var found []map[string]interface{}
	collectHandlersOfKind(generated, "lb_upstream_host", &found)
	if len(found) == 0 {
		t.Fatalf("生成配置里没有 lb_upstream_host 处理器（混合态必发射）:\n%s", truncateForLog(body))
	}
	merged := map[string]string{}
	for _, node := range found {
		hosts, ok := node["hosts"].(map[string]string)
		if !ok {
			t.Fatalf("lb_upstream_host.hosts type=%T", node["hosts"])
		}
		for dial, host := range hosts {
			merged[dial] = host
		}
	}
	for dial, want := range map[string]string{
		"C.com:443":          "C.com", // 第一档：逐上游 origin_domain
		"D.com:443":          "D.com", // 第一档
		"192.168.42.2:40080": "B.com", // 第二档：规则级 host_header
	} {
		if got, ok := merged[dial]; !ok || got != want {
			t.Fatalf("lb_upstream_host.hosts[%s]=%q（存在=%v）; want %q\n全量映射=%v", dial, got, ok, want, merged)
		}
	}
	if _, leaked := merged["X.com:443"]; leaked {
		t.Fatalf("表外地址 X.com 不应进映射（orphan 只走规则级，由渲染层静态下发）: %v", merged)
	}

	// 对端解码钉子（caddygeoip 包）读取本产物；只有被显式要求时才写文件。
	if out := os.Getenv(caddyDecodeEmitEnv); out != "" {
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			t.Fatalf("mkdir for emit: %v", err)
		}
		if err := os.WriteFile(out, body, 0o600); err != nil {
			t.Fatalf("write emitted config to %s: %v", out, err)
		}
		t.Logf("wrote %d bytes to %s", len(body), out)
	}
}

// containsSubstring 是 bytes.Contains 的薄包装（避免为一行判断引入 bytes 依赖歧义）。
func containsSubstring(haystack []byte, needle string) bool {
	if needle == "" {
		return false
	}
	n := len(needle)
	for i := 0; i+n <= len(haystack); i++ {
		if string(haystack[i:i+n]) == needle {
			return true
		}
	}
	return false
}

// collectHandlersOfKind 递归收集 handler == kind 的节点（产物是 JSON 往返后的
// map[string]interface{} / []interface{} 混合树）。
func collectHandlersOfKind(node interface{}, kind string, out *[]map[string]interface{}) {
	switch value := node.(type) {
	case map[string]interface{}:
		if handler, ok := value["handler"].(string); ok && handler == kind {
			*out = append(*out, value)
		}
		for _, child := range value {
			collectHandlersOfKind(child, kind, out)
		}
	case []interface{}:
		for _, child := range value {
			collectHandlersOfKind(child, kind, out)
		}
	}
}

// truncateForLog 截断大配置文本，失败消息只留可读片段。
func truncateForLog(body []byte) string {
	const limit = 2000
	if len(body) <= limit {
		return string(body)
	}
	return string(body[:limit]) + "\n…（截断，共 " + fmt.Sprintf("%d", len(body)) + " 字节）"
}
