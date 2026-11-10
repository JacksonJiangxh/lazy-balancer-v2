package services

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GitHub release tag 的三条获取路径（API 的 tag_name / releases/latest 的
// Location 跳转 / 代理直接返回的 HTML 正文）此前均无字符集与长度校验——
// HTML 两条路径虽被正则 `([^"'/]+)` 间接限制，仍可捕获换行等控制字符；API
// 路径可携带控制字符（写入版本行、日志与审计，并参与 raw.githubusercontent
// URL 拼接）。统一在三条解析漏斗处校验白名单。
func TestReleaseTagValidation_charsetAndLength(t *testing.T) {
	valid := []string{"v4.29.0", "v4.29.0-0-0", "v3.17.0", "v2.3.1", "release-2026_09", "v1.0.0+meta"}
	for _, tag := range valid {
		if err := validateReleaseTag(tag); err != nil {
			t.Fatalf("validateReleaseTag(%q) = %v, want nil（合法形状被拒）", tag, err)
		}
	}
	invalid := []struct {
		name string
		tag  string
	}{
		{"换行（日志/审计行伪造面）", "v4.29.0\ninjected"},
		{"空格", "v4 29 0"},
		{"引号", `v4.29.0"x`},
		{"路径穿越", "../../etc/passwd"},
		{"斜杠", "v4/29"},
		{"超长（>64）", "v" + strings.Repeat("9", 80)},
		{"空", ""},
		{"前导点", ".hidden"},
		{"百分号编码未解码残留", "v4.29.0%0a"},
	}
	for _, tc := range invalid {
		if err := validateReleaseTag(tc.tag); err == nil {
			t.Fatalf("validateReleaseTag(%q)（%s）= nil, want error", tc.tag, tc.name)
		}
	}
}

// 两条解析漏斗均接入校验（API JSON 路径与 HTML 跳转路径）。
func TestGitHubTagParsers_rejectUnsafeTags(t *testing.T) {
	if _, err := parseGitHubLatestTag([]byte(`{"tag_name":"v4.29.0\nevil"}`)); err == nil {
		t.Fatal("parseGitHubLatestTag 未拒含换行的 tag_name")
	}
	if _, err := parseGitHubLatestTag([]byte(`{"tag_name":"v4.29.0"}`)); err != nil {
		t.Fatalf("parseGitHubLatestTag 拒了合法 tag: %v", err)
	}
	if _, err := parseGitHubTagFromLocation("https://github.com/x/y/releases/tag/v4.29.0%0a"); err == nil {
		t.Fatal("parseGitHubTagFromLocation 未拒非法 tag 形状")
	}
	if got, err := parseGitHubTagFromLocation("https://github.com/x/y/releases/tag/v4.29.0"); err != nil || got != "v4.29.0" {
		t.Fatalf("parseGitHubTagFromLocation 合法形状: got=%q err=%v", got, err)
	}
}

// 第三条解析漏斗：代理直接返回 200 页面（无 302 跳转）时的正文正则提取。
// 正则 `([^"'/]+)` 允许换行等控制字符，必须与 API/Location 两条漏斗同口径
// 校验——否则控制字符可进入版本行、任务日志与审计详情。
func TestGitHubTagViaProxyBodyFunnelValidatesTag(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><a href=\"/coreruleset/coreruleset/releases/tag/v4.29.0\nevil\">x</a></html>")
	}))
	defer proxy.Close()
	withGHFastProxy(t, proxy.URL+"/")
	withCRSLatestAPIURL(t, deadServerURL(t))

	if tag, err := defaultFetchCRSLatestTag(context.Background()); err == nil {
		t.Fatalf("正文漏斗必须拒绝含控制字符的 tag, got tag=%q", tag)
	} else if !strings.Contains(err.Error(), "形状非法") {
		t.Fatalf("err=%v, want 点名 tag 形状非法", err)
	}

	// 对照：合法正文仍可解析（漏斗校验不误伤）。
	valid := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><a href=\"/coreruleset/coreruleset/releases/tag/v4.28.0\">v4.28.0</a></html>")
	}))
	defer valid.Close()
	withGHFastProxy(t, valid.URL+"/")
	if tag, err := defaultFetchCRSLatestTag(context.Background()); err != nil || tag != "v4.28.0" {
		t.Fatalf("合法正文: tag=%q err=%v, want v4.28.0", tag, err)
	}
}
