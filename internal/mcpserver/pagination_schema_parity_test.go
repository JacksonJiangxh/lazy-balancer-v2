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
// 其中 page 的 maximum 必须与 REST 侧真实上限一致：schema 写空 → Agent 依契约
// 传 page=501 吃 400；schema 写小 → 白白限制能力；schema 写大 → Agent 以为能
// 翻更深页却拿到钳位结果。上限的单源是 handlers 的实现，本测试机械对表。

func schemaPageMaximum(t *testing.T, tool, schema string) int {
	t.Helper()
	var shape struct {
		Properties map[string]struct {
			Maximum *int `json:"maximum"`
		} `json:"properties"`
	}
	if err := json.Unmarshal([]byte(schema), &shape); err != nil {
		t.Fatalf("%s schema 解析失败: %v", tool, err)
	}
	page, ok := shape.Properties["page"]
	if !ok {
		t.Fatalf("%s schema 未声明 page", tool)
	}
	if page.Maximum == nil {
		t.Fatalf("%s schema 的 page 未声明 maximum（REST 侧存在上限）", tool)
	}
	return *page.Maximum
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

// parsePaginationCap 从函数体内读 `parsePaginationParam(c, "page", 1, N)` 的 N
// （支持十进字面量与下划线分隔）。
func parsePaginationCap(t *testing.T, body string) int {
	t.Helper()
	match := regexp.MustCompile(`parsePaginationParam\(c, "page", 1, ([0-9_]+|maxCertJobPage|max[A-Za-z]+)\)`).FindStringSubmatch(body)
	if match == nil {
		t.Fatalf("函数体内未找到 page 分页上限")
	}
	raw := match[1]
	if raw == "maxCertJobPage" {
		constBody := ""
		for _, name := range []string{"certjobs.go"} {
			constBody += readHandlerSource(t, name)
		}
		if m := regexp.MustCompile(`const maxCertJobPage = ([0-9_]+)`).FindStringSubmatch(constBody); m != nil {
			raw = m[1]
		}
	}
	raw = strings.ReplaceAll(raw, "_", "")
	capValue, err := strconv.Atoi(raw)
	if err != nil {
		t.Fatalf("page 上限 %q 无法解析: %v", match[1], err)
	}
	return capValue
}

func TestPaginationSchemaMaximumMatchesRESTServerCap(t *testing.T) {
	auditSource := readHandlerSource(t, "auditlog.go")
	auditCapMatch := regexp.MustCompile(`const auditLogDeepPageLimit = ([0-9_]+)`).FindStringSubmatch(auditSource)
	if auditCapMatch == nil {
		t.Fatal("未找到 auditLogDeepPageLimit 常量")
	}
	auditCap, err := strconv.Atoi(strings.ReplaceAll(auditCapMatch[1], "_", ""))
	if err != nil {
		t.Fatal(err)
	}

	securitySource := readHandlerSource(t, "security.go")
	eventsCap := parsePaginationCap(t, handlerFunctionSource(t, securitySource, "func (h *Handlers) ListSecurityEvents(c *gin.Context) {"))
	crsCap := parsePaginationCap(t, handlerFunctionSource(t, securitySource, "func (h *Handlers) ListCRSRules(c *gin.Context) {"))
	certJobsCap := parsePaginationCap(t, handlerFunctionSource(t, readHandlerSource(t, "certjobs.go"), "func (h *Handlers) ListCertJobs(c *gin.Context) {"))

	for _, tc := range []struct {
		tool   string
		schema string
		want   int
	}{
		{"list_audit_logs", auditLogsSchema, auditCap},
		{"list_security_events", securityEventsSchema, eventsCap},
		{"list_crs_rules", listCRSRulesSchema, crsCap},
		{"list_cert_jobs", listCertJobsSchema, certJobsCap},
	} {
		t.Run(tc.tool, func(t *testing.T) {
			if got := schemaPageMaximum(t, tc.tool, tc.schema); got != tc.want {
				t.Fatalf("%s schema page.maximum=%d, REST 上限=%d（两处必须同值）", tc.tool, got, tc.want)
			}
		})
	}
}
