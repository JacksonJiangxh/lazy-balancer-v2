package handlers

// 历史修复（历史问题）：TCP 死值清零 SQL 双实现 parity 钉——启动迁移
// db.migrateTCPRuleDeadFields（db.go）与导入归一
// handlers.normalizeRuleRowsForTransport（config_backup.go:tcpRuleDeadFieldsResetSQL）
// 持有两份逐字相同的 UPDATE 字面量（11 列 SET + TCP 谓词），跨包无法共享常量，
// 无门禁时一侧改动另一侧静默漂移（启动迁移与导入归一对同一存量行产出不同终态）。
// 本测试读取两侧源码/常量，断言 SET 列集合与 WHERE 谓词逐字一致。

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

var goRawStringLiteral = regexp.MustCompile("`[^`]*`")

func TestTCPRuleDeadFieldsSQL_parityWithStartupMigration(t *testing.T) {
	src, err := os.ReadFile("../db/db.go")
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}
	// 锚定到 migrateTCPRuleDeadFields 函数体后第一个原始字符串字面量（db.go 内
	// 另有多个含 protocol='tcp' 的 UPDATE 字面量，仅按内容过滤会歧义）。
	body := string(src)
	anchor := strings.Index(body, "func migrateTCPRuleDeadFields(")
	if anchor < 0 {
		t.Fatalf("db.go 未找到 migrateTCPRuleDeadFields 函数")
	}
	loc := goRawStringLiteral.FindStringIndex(body[anchor:])
	if loc == nil {
		t.Fatalf("migrateTCPRuleDeadFields 内未找到 SQL 字面量")
	}
	migrationSQL := strings.Trim(body[anchor+loc[0]:anchor+loc[1]], "`")
	if !strings.Contains(migrationSQL, "UPDATE lb_rules SET") || !strings.Contains(migrationSQL, "protocol='tcp'") {
		t.Fatalf("migrateTCPRuleDeadFields 首个字面量非 TCP 死值 SQL: %q", migrationSQL)
	}

	migCols, migWhere := splitTCPDeadFieldsSQL(t, migrationSQL)
	localCols, localWhere := splitTCPDeadFieldsSQL(t, tcpRuleDeadFieldsResetSQL)

	if strings.Join(migCols, ",") != strings.Join(localCols, ",") {
		t.Fatalf("SET 列集合分叉:\n  db.go        = %v\n  config_backup = %v", migCols, localCols)
	}
	// TCP 自愈族：七 HTTP 专属 + NTLM + force_http1 + TLS 三列
	// + 代理超时族七列 + custom_routes_enabled + dynamic_dns + strategy。
	if len(migCols) != 22 {
		t.Fatalf("SET 列数=%d, want 22: %v", len(migCols), migCols)
	}
	if migWhere != localWhere {
		t.Fatalf("WHERE 谓词分叉:\n  db.go        = %q\n  config_backup = %q", migWhere, localWhere)
	}
	// 整体兜底：空白归一后两份字面量须逐字一致（列集合/谓词之外的值部分同样受钉）
	if normalizeSQLWhitespace(migrationSQL) != normalizeSQLWhitespace(tcpRuleDeadFieldsResetSQL) {
		t.Fatalf("TCP 死值 SQL 逐字分叉:\n  db.go        = %q\n  config_backup = %q",
			normalizeSQLWhitespace(migrationSQL), normalizeSQLWhitespace(tcpRuleDeadFieldsResetSQL))
	}

	// TCP 自愈族：TCP 残留路径规则清理 DELETE 同样跨包双份——逐字比对。
	migrationDelete := secondRawLiteralAfter(t, body, anchor+loc[1], "DELETE FROM path_rules")
	if normalizeSQLWhitespace(migrationDelete) != normalizeSQLWhitespace(tcpRulePathRulesResetSQL) {
		t.Fatalf("TCP 路径规则清理 SQL 分叉:\n  db.go        = %q\n  config_backup = %q",
			normalizeSQLWhitespace(migrationDelete), normalizeSQLWhitespace(tcpRulePathRulesResetSQL))
	}
}

// secondRawLiteralAfter 返回 offset 之后首个包含 marker 的原始字符串字面量。
func secondRawLiteralAfter(t *testing.T, body string, offset int, marker string) string {
	t.Helper()
	rest := body[offset:]
	idx := strings.Index(rest, "`"+marker)
	if idx < 0 {
		t.Fatalf("offset 之后未找到含 %q 的原始字符串字面量", marker)
	}
	end := strings.Index(rest[idx+1:], "`")
	if end < 0 {
		t.Fatalf("字面量未闭合: %q", marker)
	}
	return rest[idx+1 : idx+1+end]
}

// tcpSQLColumnFallback：SET 列 → tcpDeadFields 字段名的单源映射（TCP 自愈族
// 三处 parity 的第三处）：SQL 归一扩列时，保存族（rules.go tcpDeadFieldReset
// 的结构体/适配器）必须同步覆盖，否则「编辑/复制自愈」对新增列静默缺失。
var tcpSQLColumnFallback = map[string]string{
	"host_header":                   "HostHeader",
	"health_check_path":             "HealthCheckPath",
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
	"tls_cert":                      "TLSCert",
	"tls_key":                       "TLSKey",
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
