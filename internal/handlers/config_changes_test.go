package handlers

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestPlanConfigChangesUnchanged(t *testing.T) {
	logLevel := "info"
	req := models.UpdateConfigRequest{LogLevel: &logLevel, Source: "basic"}
	old := configSnapshot{LogLevel: "info"}

	plan := planConfigChanges(req, old)
	if plan.Changed {
		t.Fatalf("plan.Changed = true, want false; changes = %#v", plan.SectionChanges)
	}
	if plan.Section != "基础设置" {
		t.Fatalf("plan.Section = %q, want 基础设置", plan.Section)
	}
}

func TestPlanConfigChangesGroupsChangedFields(t *testing.T) {
	logLevel := "debug"
	req := models.UpdateConfigRequest{
		LogLevel: &logLevel,
		Source:   "basic",
	}
	old := configSnapshot{LogLevel: "info"}

	plan := planConfigChanges(req, old)
	if !plan.Changed {
		t.Fatal("plan.Changed = false, want true")
	}
	if got := len(plan.SectionChanges["基础设置"]); got != 1 {
		t.Fatalf("basic changes = %d, want 1", got)
	}
}

// 遗留 global_config.dns_credentials：请求体携带该键不再产生变更清单条目
// （写路径已移除，预览面不得对「不会发生的变化」报变更）。
func TestPlanConfigChanges_ignoresLegacyDNSCredentials(t *testing.T) {
	body := `{"source":"acme","dns_provider":"dnspod","dns_credentials":"legacy-id,legacy-token"}`
	var req models.UpdateConfigRequest
	if err := json.Unmarshal([]byte(body), &req); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	plan := planConfigChanges(req, configSnapshot{DNSProvider: "dnspod"})
	if plan.Changed {
		t.Fatalf("legacy dns_provider 未变化时报了变更: %#v", plan.SectionChanges)
	}
}

func TestPlanConfigChangesIncludesJWTExpire(t *testing.T) {
	minutes := 30
	req := models.UpdateConfigRequest{JWTExpireMinutes: &minutes, Source: "basic"}
	old := configSnapshot{JWTExpireMinutes: 20}
	plan := planConfigChanges(req, old)
	if !plan.Changed || len(plan.SectionChanges["基础设置"]) != 1 {
		t.Fatalf("JWT expiry change not planned: %#v", plan)
	}
}

// 大屏本站坐标 lat/lon 共用 label——同时变更时变更清单只列一项
// （原实现逐字段 add，同一 label 重复出现）。
func TestPlanConfigChangesDedupesSharedLabel(t *testing.T) {
	lat, lon := 31.2, 121.5
	req := models.UpdateConfigRequest{ServerMapLat: &lat, ServerMapLon: &lon, Source: "basic"}
	old := configSnapshot{ServerMapLat: 0, ServerMapLon: 0}

	plan := planConfigChanges(req, old)
	if !plan.Changed {
		t.Fatal("plan.Changed = false, want true（任一坐标变更）")
	}
	if len(plan.Changes) != 1 || plan.Changes[0] != "大屏本站坐标" {
		t.Fatalf("changes=%v, want 单条「大屏本站坐标」", plan.Changes)
	}
	got := plan.SectionChanges["基础设置"]
	if len(got) != 1 || got[0] != "大屏本站坐标" {
		t.Fatalf("section changes=%v, want 单条", got)
	}
}

func TestPlanConfigChanges_tracksEveryUpdateConfigPointerField(t *testing.T) {
	expected := map[string]bool{}
	typ := reflect.TypeOf(models.UpdateConfigRequest{})
	for i := range typ.NumField() {
		field := typ.Field(i)
		if field.Name == "Source" || field.Type.Kind() != reflect.Ptr {
			continue
		}
		jsonName, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		expected[jsonName] = true
	}

	parsed, err := parser.ParseFile(token.NewFileSet(), "config_changes.go", nil, 0)
	if err != nil {
		t.Fatalf("parse config_changes.go: %v", err)
	}
	actual := map[string]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		ident, ok := call.Fun.(*ast.Ident)
		if !ok || ident.Name != "add" {
			return true
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatalf("add first argument must be a field-name string literal, got %T", call.Args[0])
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil {
			t.Fatalf("unquote add field: %v", err)
		}
		actual[name] = true
		return true
	})
	for name := range expected {
		if !actual[name] {
			t.Errorf("UpdateConfigRequest.%s is missing from planConfigChanges add calls", name)
		}
	}
	for name := range actual {
		if !expected[name] {
			t.Errorf("planConfigChanges tracks %q without an UpdateConfigRequest pointer field", name)
		}
	}
}
