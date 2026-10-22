package handlers

// TCP 死值归一钉测集：SQL 字面量单源已下沉 db 包
// （db.TCPRuleDeadFieldsResetSQL / db.TCPRulePathRulesResetSQL——启动迁移
// migrateTCPRuleDeadFields 与导入归一 normalizeRuleRowsForTransport 共用同一
// 常量，消灭跨包双份镜像）。本文件保留两道防线：
//  1. 保存族 ↔ SQL 列覆盖双向对账（SQL 扩列必须同步保存族结构体/适配器）；
//  2. 保存族字段反向对账（新增字段要么进 SQL 归一，要么进显式豁免清单附裁定）。

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

// tcpSQLColumnFallback：SET 列 → tcpDeadFields 字段名的单源映射（TCP 自愈族
// 三处 parity 的第三处）：SQL 归一扩列时，保存族（rules.go tcpDeadFieldReset
// 的结构体/适配器）必须同步覆盖，否则「编辑/复制自愈」对新增列静默缺失。
var tcpSQLColumnFallback = map[string]string{
	"host_header":                   "HostHeader",
	"health_check_path":             "HealthCheckPath",
	"health_check_host":             "HealthCheckHost",
	"domain":                        "Domain",
	"enable_compress":               "EnableCompress",
	"compress_types":                "CompressTypes",
	"request_body_max_size_mb":      "RequestBodyMaxSizeMB",
	"upstream_keepalive_timeout":    "UpstreamKeepaliveTimeout",
	"server_tokens_hidden":          "ServerTokensHidden",
	"ntlm_compatible":               "NTLMCompatible",
	"upstream_force_http1":          "UpstreamForceHTTP1",
	"proxy_dial_timeout":            "ProxyDialTimeout",
	"proxy_response_header_timeout": "ProxyResponseHeaderTimeout",
	"proxy_read_timeout":            "ProxyReadTimeout",
	"proxy_write_timeout":           "ProxyWriteTimeout",
	"proxy_stream_timeout":          "ProxyStreamTimeout",
	"proxy_flush_interval":          "ProxyFlushInterval",
	"proxy_stream_close_delay":      "ProxyStreamCloseDelay",
	"custom_routes_enabled":         "CustomRoutesEnabled",
	"dynamic_dns":                   "DynamicDNS",
	"strategy":                      "Strategy",
	"enable_tls":                    "EnableTLS",
	"tls_source":                    "TLSSource",
	"tls_http_redirect":             "TLSHTTPRedirect",
	"tls_cert":                      "TLSCert",
	"tls_key":                       "TLSKey",
	"block_page_stage1_id":          "BlockPageStage1ID",
	"block_page_stage1_status":      "BlockPageStage1Status",
	"block_page_stage3_id":          "BlockPageStage3ID",
	"block_page_stage3_status":      "BlockPageStage3Status",
	"log_enabled":                   "LogEnabled",
}

// TestTCPDeadFieldsSaveFamily_coversSQLColumns 钉住保存族与 SQL 归一的列覆盖
// 对账（TCP 自愈族）：tcpDeadFields 结构体与 Duplicate 适配器必须包含
// SQL SET 的每一列；Create 适配器刻意豁免 NTLM/健康检查域名/代理路由族
// （显式携带交保存门 400，见 createRuleTCPDeadFields 注释）。
func TestTCPDeadFieldsSaveFamily_coversSQLColumns(t *testing.T) {
	src, err := os.ReadFile("rules.go")
	if err != nil {
		t.Fatalf("read rules.go: %v", err)
	}
	body := string(src)
	structBody := functionBody(t, body, "type tcpDeadFields struct {")
	storedBody := functionBody(t, body, "func storedRuleTCPDeadFields(")
	updateBody := functionBody(t, body, "func updateRuleTCPDeadFields(")

	cols, _ := splitTCPDeadFieldsSQL(t, tcpRuleDeadFieldsResetSQL)
	if len(cols) == 0 {
		t.Fatal("SQL SET 列解析为空")
	}
	if len(tcpSQLColumnFallback) != len(cols) {
		t.Fatalf("列→字段映射条数=%d, want %d（SQL 扩列未同步映射）", len(tcpSQLColumnFallback), len(cols))
	}
	sqlColumns := make(map[string]bool, len(cols))
	for _, col := range cols {
		sqlColumns[col] = true
	}
	for _, col := range cols {
		field, ok := tcpSQLColumnFallback[col]
		if !ok {
			t.Fatalf("SQL 列 %q 缺少 tcpDeadFields 字段映射", col)
		}
		if !strings.Contains(structBody, field+" ") && !strings.Contains(structBody, field+"\t") {
			t.Fatalf("tcpDeadFields 结构体缺少字段 %s（列 %s）", field, col)
		}
		// 复制/编辑适配器必须接字段（自愈路径实际生效处）。
		for name, adapter := range map[string]string{"storedRuleTCPDeadFields": storedBody, "updateRuleTCPDeadFields": updateBody} {
			if !strings.Contains(adapter, field+":") {
				t.Fatalf("%s 未接线字段 %s（列 %s）——该列在复制/编辑路径不自愈", name, field, col)
			}
		}
	}
	for col := range tcpSQLColumnFallback {
		if !sqlColumns[col] {
			t.Fatalf("保存族列 %q 未纳入 SQL 归一（双向 parity 缺口）", col)
		}
	}
}

// TestTCPDeadFieldsSaveFamily_fieldsCoveredOrExempted 反向对账（字段 ⊆ SQL ∪ 豁免）：
// 保存族 tcpDeadFields 每新增一个字段，要么进 SQL 归一映射
// （tcpSQLColumnFallback），要么进下方显式豁免清单并附裁定理由——防止
// 「保存族清零、启动迁移/导入 SQL 漏列」的静默分叉随新字段重演。
func TestTCPDeadFieldsSaveFamily_fieldsCoveredOrExempted(t *testing.T) {
	// 豁免裁定：acme_config_id/ca_provider_id 有意不入 SQL 归一——全部 ACME
	// 消费方（签发/续签/证书回插）以 enable_tls=1 联合门控，而 enable_tls 对
	// TCP 行恒归 0（SQL 第 23 列），残留引用不可达（惰性无害，已逐消费方
	// 推演）；SQL 扩列会改变集群快照 canonical 哈希基线、触发一轮全量重放，
	// 代价大于收益。残留值由下次规则编辑经保存族（tcpDeadFieldReset）清零
	// 自愈。未来新增不依赖 enable_tls 门控的 ACME 消费方时，本豁免必须重审。
	exempted := map[string]string{
		"ACMEConfigID": "ACME 消费方全部 enable_tls=1 联合门控，TCP 恒归 0 后残留引用不可达",
		"CAProviderID": "同上（ResolveCAProviderID 仅在 acme_dns 签发路径消费）",
	}
	covered := make(map[string]bool, len(tcpSQLColumnFallback))
	for _, field := range tcpSQLColumnFallback {
		covered[field] = true
	}
	typ := reflect.TypeOf(tcpDeadFields{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if covered[name] {
			continue
		}
		if _, ok := exempted[name]; ok {
			continue
		}
		t.Fatalf("tcpDeadFields 字段 %s 既不在 SQL 归一映射也不在豁免清单——新增字段必须二选一并附裁定", name)
	}
	// 豁免清单不得腐化：字段被移除/改名时豁免项必须同步删除。
	for name := range exempted {
		if _, ok := typ.FieldByName(name); !ok {
			t.Fatalf("豁免字段 %s 已不存在于 tcpDeadFields，请同步删除豁免项", name)
		}
	}
}

// functionBody 截取以 anchor 开头的函数/类型声明主体（到下一个顶格 func/type）。
func functionBody(t *testing.T, body, anchor string) string {
	t.Helper()
	start := strings.Index(body, anchor)
	if start < 0 {
		t.Fatalf("未找到声明 %q", anchor)
	}
	rest := body[start+len(anchor):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	if end := strings.Index(rest, "\ntype "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// TestTCPDeadFieldReset_zeroesSaveFamily 行为钉：完整填充的 tcpDeadFields
// 经归一后全部为零（strategy 的 cookie→默认策略特例除外）。
func TestTCPDeadFieldReset_zeroesSaveFamily(t *testing.T) {
	yes := true
	num := 42
	strategy := "cookie"
	fields := tcpDeadFields{
		EnableTLS: &yes, TLSSource: new("acme_dns"), TLSCert: new("cert"), TLSKey: new("key"),
		ACMEConfigID: &num, CAProviderID: &num, Domain: new("d.example"), TLSHTTPRedirect: &yes,
		HostHeader: new("h"), HealthCheckPath: new("/hc"), HealthCheckHost: new("probe"),
		EnableCompress: &yes, CompressTypes: new("gzip"), RequestBodyMaxSizeMB: &num,
		UpstreamKeepaliveTimeout: &num, ServerTokensHidden: &num,
		NTLMCompatible: &num, UpstreamForceHTTP1: &num,
		BlockPageStage1ID: &num, BlockPageStage1Status: &num,
		BlockPageStage3ID: &num, BlockPageStage3Status: &num, LogEnabled: &yes,
		ProxyDialTimeout: &num, ProxyResponseHeaderTimeout: &num,
		ProxyReadTimeout: &num, ProxyWriteTimeout: &num, ProxyStreamTimeout: &num,
		ProxyFlushInterval: &num, ProxyStreamCloseDelay: &num,
		CustomRoutesEnabled: &yes, DynamicDNS: &yes, Strategy: &strategy,
	}
	tcpDeadFieldReset("tcp", fields)
	zeroInts := map[string]int{
		"ACMEConfigID": *fields.ACMEConfigID, "RequestBodyMaxSizeMB": *fields.RequestBodyMaxSizeMB,
		"UpstreamKeepaliveTimeout": *fields.UpstreamKeepaliveTimeout, "ServerTokensHidden": *fields.ServerTokensHidden,
		"NTLMCompatible": *fields.NTLMCompatible, "UpstreamForceHTTP1": *fields.UpstreamForceHTTP1,
		"ProxyDialTimeout": *fields.ProxyDialTimeout, "ProxyResponseHeaderTimeout": *fields.ProxyResponseHeaderTimeout,
		"ProxyReadTimeout": *fields.ProxyReadTimeout, "ProxyWriteTimeout": *fields.ProxyWriteTimeout,
		"ProxyStreamTimeout": *fields.ProxyStreamTimeout, "ProxyFlushInterval": *fields.ProxyFlushInterval,
		"ProxyStreamCloseDelay": *fields.ProxyStreamCloseDelay,
	}
	for name, value := range zeroInts {
		if value != 0 {
			t.Fatalf("%s=%d, want 0 after TCP reset", name, value)
		}
	}
	for name, value := range map[string]bool{
		"CustomRoutesEnabled": *fields.CustomRoutesEnabled, "DynamicDNS": *fields.DynamicDNS,
	} {
		if value {
			t.Fatalf("%s=true, want false after TCP reset", name)
		}
	}
	if *fields.Strategy != "weighted_round_robin" {
		t.Fatalf("cookie strategy=%q, want weighted_round_robin", *fields.Strategy)
	}
	// 非 TCP 协议不动。
	keep := 42
	otherCookie := "cookie"
	other := tcpDeadFields{ProxyDialTimeout: &keep, Strategy: &otherCookie}
	tcpDeadFieldReset("http", other)
	if *other.ProxyDialTimeout != 42 || *other.Strategy != "cookie" {
		t.Fatalf("http protocol must not be reset: %+v", other)
	}
}

// splitTCPDeadFieldsSQL 从 "UPDATE lb_rules SET <cols> WHERE <pred>" 形态解析出
// SET 列名（有序）与 WHERE 谓词（空白归一后的子串）。
func splitTCPDeadFieldsSQL(t *testing.T, sqlText string) (cols []string, where string) {
	t.Helper()
	norm := normalizeSQLWhitespace(sqlText)
	const setPrefix = "UPDATE lb_rules SET "
	setIdx := strings.Index(norm, setPrefix)
	whereIdx := strings.Index(norm, " WHERE ")
	if setIdx != 0 || whereIdx < 0 || whereIdx <= setIdx {
		t.Fatalf("SQL 形状异常（须 UPDATE lb_rules SET ... WHERE ...）: %q", norm)
	}
	for _, clause := range strings.Split(norm[len(setPrefix):whereIdx], ",") {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		cols = append(cols, strings.TrimSpace(strings.SplitN(clause, "=", 2)[0]))
	}
	return cols, norm[whereIdx:]
}

func normalizeSQLWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}
