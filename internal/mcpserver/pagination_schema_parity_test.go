package mcpserver

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// MCP 工具的 input_schema 是 Agent 唯一构参契约（运行时 schema 校验刻意关闭），
// 其中 page/page_size 的 upper bound 必须与 REST 侧真实上限一致：schema 写空 →
// Agent 依契约传 page=501 吃 400；schema 写小 → 白白限制能力；schema 写大 →
// Agent 以为能翻更深页/取更多条却拿到钳位结果。上限的单源是 handlers 的实现，
// 本测试机械对表——page 取判定点（比较运算 + 操作数），page_size 取钳位实参，
// 常量声明只是被操作数解析的目标，不再是锚点。

func schemaPropertyMaximum(t *testing.T, tool, schema, property string) int {
	t.Helper()
	var shape struct {
		Properties map[string]struct {
			Maximum *int `json:"maximum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(schema), &shape); err != nil {
		t.Fatalf("%s schema 解析失败: %v", tool, err)
	}
	field, ok := shape.Properties[property]
	if !ok {
		t.Fatalf("%s schema 未声明 %s", tool, property)
	}
	if field.Maximum == nil {
		t.Fatalf("%s schema 的 %s 未声明 maximum（REST 侧存在上限）", tool, property)
	}
	return *field.Maximum
}

func readHandlerSource(t *testing.T, name string) string {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "handlers", name))
	if err != nil {
		t.Fatalf("读 %s: %v", name, err)
	}
	return string(body)
}

// handlerFunctionSource 截取某个 handler 方法体（到下一个顶层 func 声明）。
func handlerFunctionSource(t *testing.T, body, signature string) string {
	t.Helper()
	start := strings.Index(body, signature)
	if start < 0 {
		t.Fatalf("未找到 %q", signature)
	}
	rest := body[start+len(signature):]
	if end := strings.Index(rest, "\nfunc "); end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// resolveHandlerConstant 在 handler 源文件内解析名为 name 的整型常量值。
func resolveHandlerConstant(t *testing.T, source, name string) int {
	t.Helper()
	match := regexp.MustCompile(`const ` + name + ` = ([0-9_]+)`).FindStringSubmatch(source)
	if match == nil {
		t.Fatalf("未找到常量 %s（声明形态变化，扫描器需跟进）", name)
	}
	value, err := strconv.Atoi(strings.ReplaceAll(match[1], "_", ""))
	if err != nil {
		t.Fatalf("常量 %s 值 %q 无法解析: %v", name, match[1], err)
	}
	return value
}

// parsePaginationParamCap 从函数体内读 `parsePaginationParam(c, name, 默认值, N)`
// 的 N（支持十进字面量与命名常量）。
func parsePaginationParamCap(t *testing.T, body, param, constFile string) int {
	t.Helper()
	pattern := regexp.MustCompile(`parsePaginationParam\(c, "` + regexp.QuoteMeta(param) + `", (?:[0-9_]+|max[A-Za-z]+), ([0-9_]+|max[A-Za-z]+)\)`)
	match := pattern.FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("函数体内未找到 %s 分页上限", param)
	}
	raw := match[1]
	if _, err := strconv.Atoi(strings.ReplaceAll(raw, "_", "")); err != nil {
		return resolveHandlerConstant(t, readHandlerSource(t, constFile), raw)
	}
	value, err := strconv.Atoi(strings.ReplaceAll(raw, "_", ""))
	if err != nil {
		t.Fatalf("%s 上限 %q 无法解析: %v", param, match[1], err)
	}
	return value
}

// parseAuditDeepPageLimit 从 GetAuditLogs 的判定点派生深翻页上限：锚点是
// `if page > auditLogDeepPageLimit` 的比较，而不是常量声明。比较符必须是严格
// 大于（schema 的 maximum 表示「该值本身合法」）；改成 `>=` 或换操作数都必须
// 同步 schema。
func parseAuditDeepPageLimit(t *testing.T, source, body string) int {
	t.Helper()
	match := regexp.MustCompile(`if page ([><]=?|==) ([A-Za-z_][A-Za-z0-9_]*)`).FindStringSubmatch(body)
	if match == nil {
		t.Fatal("GetAuditLogs 未找到 page 上限判定点（if page > <limit>）")
	}
	if match[1] != ">" {
		t.Fatalf("GetAuditLogs 的 page 判定符=%q, want \">\"（>= 会让 schema maximum 多算一页）", match[1])
	}
	return resolveHandlerConstant(t, source, match[2])
}

func TestPaginationSchemaMaximumMatchesRESTServerCap(t *testing.T) {
	auditSource := readHandlerSource(t, "auditlog.go")
	auditBody := handlerFunctionSource(t, auditSource, "func (h *Handlers) GetAuditLogs(c *gin.Context) {")
	auditPageCap := parseAuditDeepPageLimit(t, auditSource, auditBody)
	auditPageSizeCap := parsePaginationParamCap(t, auditBody, "page_size", "auditlog.go")

	securitySource := readHandlerSource(t, "security.go")
	eventsBody := handlerFunctionSource(t, securitySource, "func (h *Handlers) ListSecurityEvents(c *gin.Context) {")
	eventsCap := parsePaginationParamCap(t, eventsBody, "page", "security.go")
	eventsPageSizeCap := parsePaginationParamCap(t, eventsBody, "page_size", "security.go")
	crsBody := handlerFunctionSource(t, securitySource, "func (h *Handlers) ListCRSRules(c *gin.Context) {")
	crsCap := parsePaginationParamCap(t, crsBody, "page", "security.go")
	crsPageSizeCap := parsePaginationParamCap(t, crsBody, "page_size", "security.go")
	certJobsBody := handlerFunctionSource(t, readHandlerSource(t, "certjobs.go"), "func (h *Handlers) ListCertJobs(c *gin.Context) {")
	certJobsCap := parsePaginationParamCap(t, certJobsBody, "page", "certjobs.go")
	certJobsPageSizeCap := parsePaginationParamCap(t, certJobsBody, "page_size", "certjobs.go")
	// /certificates（聚合清单）的分页默认值与上限同为 maxCertJobPage：
	// 默认值也是命名常量，解析器需容得下「默认值 + 钳位」都是常量的形态。
	certListBody := handlerFunctionSource(t, readHandlerSource(t, "certificates.go"), "func (h *Handlers) ListCertificates(c *gin.Context) {")
	certListCap := parsePaginationParamCap(t, certListBody, "page", "certjobs.go")
	certListPageSizeCap := parsePaginationParamCap(t, certListBody, "page_size", "certjobs.go")

	for _, tc := range []struct {
		tool     string
		schema   string
		page     int
		pageSize int
	}{
		{"list_audit_logs", auditLogsSchema, auditPageCap, auditPageSizeCap},
		{"list_security_events", securityEventsSchema, eventsCap, eventsPageSizeCap},
		{"list_crs_rules", listCRSRulesSchema, crsCap, crsPageSizeCap},
		{"list_cert_jobs", listCertJobsSchema, certJobsCap, certJobsPageSizeCap},
		{"list_certificates", listCertificatesSchema, certListCap, certListPageSizeCap},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			// 上限必须长在**注册的**工具规格上：只对局部常量断言时，注册行
			// 指回 emptySchema（或另一份副本）也能通过（假绿）。
			registered, ok := toolSpecsByName[tc.tool]
			if !ok {
				t.Fatalf("%s 未在工具注册表中（名称漂移？）", tc.tool)
			}
			if registered.schema != tc.schema {
				t.Fatalf("%s 注册的工具 schema 与分页声明常量不一致", tc.tool)
			}
			if got := schemaPropertyMaximum(t, tc.tool, tc.schema, "page"); got != tc.page {
				t.Fatalf("%s schema page.maximum=%d, REST 上限=%d（两处必须同值）", tc.tool, got, tc.page)
			}
			if got := schemaPropertyMaximum(t, tc.tool, tc.schema, "page_size"); got != tc.pageSize {
				t.Fatalf("%s schema page_size.maximum=%d, REST 钳位=%d（两处必须同值）", tc.tool, got, tc.pageSize)
			}
		})
	}
}
