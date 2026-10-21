package caddygeoip

// http.ip_sources.lb_file（2026-10-15 受信代理网段热路径化）的模块单测：
// 加载/热重载/fail-stale/坏行 fail-fast/白名单/引擎级（历史修复：真实 Caddy
// 加载含 lb_file 的配置）。文件缓存与解析语义单源在 wafiplist（@ipListFast
// 同一缓存），本文件只测模块装配与 IPRangeSource 契约形态。

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"lazy-balancer-v2/wafiplist"
)

// useTPAllowedDir 把 wafiplist 路径白名单指到临时目录（生产=/app/waf/）。
func useTPAllowedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := wafiplist.AllowedPathPrefix
	wafiplist.AllowedPathPrefix = dir + string(filepath.Separator)
	t.Cleanup(func() { wafiplist.AllowedPathPrefix = old })
	return dir
}

// forceFreshStat 关闭节流（逐次 stat），热重载/fail-stale 测试即时感知。
func forceFreshStat(t *testing.T) {
	t.Helper()
	old := wafiplist.StatCheckInterval
	wafiplist.StatCheckInterval = 0
	t.Cleanup(func() { wafiplist.StatCheckInterval = old })
}

// bumpMtime 推进文件 mtime 到未来（同秒粒度兜底，wafiplist 测试同款）。
func bumpMtime(t *testing.T, path string) {
	t.Helper()
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
}

func TestFileIPRangeSource_module_registers_as_http_ip_sources_lb_file(t *testing.T) {
	info := (FileIPRangeSource{}).CaddyModule()
	if string(info.ID) != "http.ip_sources.lb_file" {
		t.Fatalf("module ID = %q, want %q", info.ID, "http.ip_sources.lb_file")
	}
	mod := info.New()
	if _, ok := mod.(caddy.Provisioner); !ok {
		t.Fatal("module must implement caddy.Provisioner")
	}
	if _, ok := mod.(caddyhttp.IPRangeSource); !ok {
		t.Fatal("module must implement caddyhttp.IPRangeSource")
	}
}

func TestFileIPRangeSource_provision_missing_file_fails_fast(t *testing.T) {
	dir := useTPAllowedDir(t)
	s := &FileIPRangeSource{Path: filepath.Join(dir, "missing.txt")}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err == nil {
		t.Fatal("缺失文件必须 Provision 失败（fail-fast → Caddy 校验拒绝、保存回滚）")
	}
}

func TestFileIPRangeSource_provision_bad_line_fails_fast(t *testing.T) {
	dir := useTPAllowedDir(t)
	path := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(path, []byte("203.0.113.0/24\ngarbage-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &FileIPRangeSource{Path: path}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err == nil {
		t.Fatal("坏行必须 Provision 失败（严格解析，防网段被静默削弱）")
	}
}

func TestFileIPRangeSource_provision_rejects_path_outside_whitelist(t *testing.T) {
	_ = useTPAllowedDir(t)
	s := &FileIPRangeSource{Path: "/etc/passwd"}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err == nil {
		t.Fatal("白名单外路径必须 Provision 失败（防目录穿越）")
	}
}

func TestFileIPRangeSource_getIPRanges_parses_and_normalizes(t *testing.T) {
	dir := useTPAllowedDir(t)
	path := filepath.Join(dir, "tp.txt")
	if err := os.WriteFile(path, []byte(
		"# 注释\n;\n203.0.113.0/24\n\n198.51.100.7\n2001:db8::/48\n203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &FileIPRangeSource{Path: path}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	ranges := s.GetIPRanges(new(http.Request))
	if len(ranges) != 3 {
		t.Fatalf("GetIPRanges=%v, want 3 条（去重后）", ranges)
	}
	got := map[string]bool{}
	for _, p := range ranges {
		got[p.String()] = true
	}
	for _, want := range []string{"203.0.113.0/24", "198.51.100.7/32", "2001:db8::/48"} {
		if !got[want] {
			t.Fatalf("GetIPRanges 缺 %q: %v", want, ranges)
		}
	}
}

func TestFileIPRangeSource_provision_empty_file_yields_empty_set(t *testing.T) {
	dir := useTPAllowedDir(t)
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	s := &FileIPRangeSource{Path: path}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("空文件必须合法（空集=信任无来源）: %v", err)
	}
	if ranges := s.GetIPRanges(new(http.Request)); ranges == nil || len(ranges) != 0 {
		t.Fatalf("GetIPRanges=%v, want 非nil空集", ranges)
	}
}

func TestFileIPRangeSource_hot_reload_detects_content_change(t *testing.T) {
	forceFreshStat(t)
	dir := useTPAllowedDir(t)
	path := filepath.Join(dir, "hot.txt")
	if err := os.WriteFile(path, []byte("203.0.113.5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &FileIPRangeSource{Path: path}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// When：原子换内容（渲染侧 tmp+rename 的等价形态）
	if err := os.WriteFile(path, []byte("198.51.100.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path)

	// Then：≤1s stat 热感知（测试 StatCheckInterval=0 逐次 stat）
	ranges := s.GetIPRanges(new(http.Request))
	if len(ranges) != 1 || ranges[0].String() != "198.51.100.0/24" {
		t.Fatalf("内容变化后 GetIPRanges=%v, want 198.51.100.0/24（旧集必须被替换）", ranges)
	}
}

func TestFileIPRangeSource_fail_stale_keeps_previous_set(t *testing.T) {
	forceFreshStat(t)
	dir := useTPAllowedDir(t)
	path := filepath.Join(dir, "stale.txt")
	if err := os.WriteFile(path, []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &FileIPRangeSource{Path: path}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// When：文件被写坏（带外形态；渲染侧是原子换名，本不会读到半截）
	if err := os.WriteFile(path, []byte("not-a-prefix!!!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bumpMtime(t, path)

	// Then：fail-stale——返回旧集，运行期绝不 fail（取消中的请求不可承受）
	ranges := s.GetIPRanges(new(http.Request))
	if len(ranges) != 1 || ranges[0].String() != "203.0.113.0/24" {
		t.Fatalf("重建失败必须返回旧集（fail-stale）: %v", ranges)
	}
}

func TestFileIPRangeSource_evicted_and_deleted_file_fails_closed_empty(t *testing.T) {
	forceFreshStat(t)
	dir := useTPAllowedDir(t)
	path := filepath.Join(dir, "evicted.txt")
	if err := os.WriteFile(path, []byte("203.0.113.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := &FileIPRangeSource{Path: path}
	if err := s.Provision(caddy.Context{Context: context.Background()}); err != nil {
		t.Fatalf("provision: %v", err)
	}

	// When：GC 删文件并淘汰缓存（受信代理停用 24h 后的形态）
	wafiplist.EvictIPListCache(path)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	// Then：空集=信任无来源（fail-closed——宁可退回 socket IP）
	if ranges := s.GetIPRanges(new(http.Request)); ranges != nil {
		t.Fatalf("缓存淘汰且文件消失必须返回 nil 空集: %v", ranges)
	}
}

func TestFileIPRangeSource_instances_resolve_independently(t *testing.T) {
	dir := useTPAllowedDir(t)
	pathA := filepath.Join(dir, "tp-a.txt")
	pathB := filepath.Join(dir, "tp-b.txt")
	if err := os.WriteFile(pathA, []byte("203.0.113.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pathB, []byte("198.51.100.0/24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := &FileIPRangeSource{Path: pathA}
	b := &FileIPRangeSource{Path: pathB}
	for name, s := range map[string]*FileIPRangeSource{"a": a, "b": b} {
		if err := s.Provision(caddy.Context{Context: context.Background()}); err != nil {
			t.Fatalf("instance %s provision: %v", name, err)
		}
	}
	if got := a.GetIPRanges(new(http.Request)); len(got) != 1 || got[0].String() != "203.0.113.0/24" {
		t.Fatalf("实例 a = %v", got)
	}
	if got := b.GetIPRanges(new(http.Request)); len(got) != 1 || got[0].String() != "198.51.100.0/24" {
		t.Fatalf("实例 b = %v", got)
	}
}

// TestFileIPRangeSource_engine_gate_real_caddy_load（历史修复）：真实 Caddy 引擎
// 加载含 trusted_proxies lb_file 的配置——模块装配/命名空间/JSON 形态的
// 验证终点是引擎接受，字符串断言不构成行为验证。
func TestFileIPRangeSource_engine_gate_real_caddy_load(t *testing.T) {
	dir := useTPAllowedDir(t)
	path := filepath.Join(dir, "tp-engine.txt")
	if err := os.WriteFile(path, []byte("203.0.113.0/24\n198.51.100.7\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cfgJSON, err := json.Marshal(map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":                 []string{":0"},
						"trusted_proxies":        map[string]any{"source": "lb_file", "path": path},
						"trusted_proxies_strict": 1,
						"client_ip_headers":      []string{"X-Forwarded-For"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var cfg caddy.Config
	if err := caddy.StrictUnmarshalJSON(cfgJSON, &cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := caddy.Validate(&cfg); err != nil {
		t.Fatalf("真实 Caddy 引擎必须接受 lb_file 受信代理配置: %v", err)
	}

	// 引擎反门：文件缺失 → Provision fail-fast → 校验拒绝。
	var bad caddy.Config
	badJSON, err := json.Marshal(map[string]any{
		"apps": map[string]any{
			"http": map[string]any{
				"servers": map[string]any{
					"srv0": map[string]any{
						"listen":          []string{":0"},
						"trusted_proxies": map[string]any{"source": "lb_file", "path": filepath.Join(dir, "gone.txt")},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := caddy.StrictUnmarshalJSON(badJSON, &bad); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := caddy.Validate(&bad); err == nil {
		t.Fatal("文件缺失的 lb_file 配置必须被引擎校验拒绝（fail-fast）")
	}
}
