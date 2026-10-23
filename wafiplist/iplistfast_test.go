package wafiplist

import (
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/experimental/plugins/plugintypes"
)

// 测试用白名单前缀（生产=/app/waf/，测试指向临时目录）。
func useAllowedDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old := AllowedPathPrefix
	AllowedPathPrefix = dir + string(filepath.Separator)
	t.Cleanup(func() { AllowedPathPrefix = old })
	return dir
}

func writeListFile(t *testing.T, dir, name string, lines []string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func newOp(t *testing.T, path string) plugintypes.Operator {
	t.Helper()
	op, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path})
	if err != nil {
		t.Fatalf("newIPListFast: %v", err)
	}
	return op
}

func TestIPListFast_hitMissCIDRv4v6(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "basic.txt", []string{
		"# 注释行", "", "; 分号注释",
		"203.0.113.7", "10.8.0.0/16", "2001:db8::/48",
	})
	op := newOp(t, path)

	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"203.0.113.7", true},  // 裸 IP
		{"10.8.3.4", true},     // CIDR 内
		{"10.9.0.1", false},    // CIDR 外
		{"2001:db8::1", true},  // v6 CIDR 内
		{"2001:db9::1", false}, // v6 CIDR 外
		{"203.0.113.8", false}, // 裸 IP 相邻未命中
		{"not-an-ip", false},   // 不可解析输入
	} {
		if got := op.Evaluate(nil, tc.value); got != tc.want {
			t.Fatalf("Evaluate(%q)=%v, want %v", tc.value, got, tc.want)
		}
	}
}

func TestIPListFast_strictParseError(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "bad.txt", []string{"10.0.0.0/8", "garbage-line"})
	if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path}); err == nil {
		t.Fatal("不可解析行必须报错（严格解析，不静默跳过）")
	}
}

func TestIPListFast_rejectsNonWhitelistedPath(t *testing.T) {
	_ = useAllowedDir(t)
	for _, path := range []string{
		"/etc/passwd", "relative/path.txt", "/tmp/evil.txt",
	} {
		if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: path}); err == nil {
			t.Fatalf("路径 %q 必须被白名单拒绝", path)
		}
	}
}

func TestIPListFast_missingFileFailsClosed(t *testing.T) {
	dir := useAllowedDir(t)
	if _, err := newIPListFast(plugintypes.OperatorOptions{Arguments: filepath.Join(dir, "missing.txt")}); err == nil {
		t.Fatal("缺失文件必须报错（构建期 fail-closed → Caddy 校验拒绝）")
	}
}

func TestIPListFast_reloadsOnMtimeChange(t *testing.T) {
	old := StatCheckInterval
	StatCheckInterval = 0 // 逐次复查（否则默认 1s 节流窗口内按缓存判定）
	t.Cleanup(func() { StatCheckInterval = old })
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "reload.txt", []string{"203.0.113.1"})
	op := newOp(t, path)
	if !op.Evaluate(nil, "203.0.113.1") || op.Evaluate(nil, "203.0.113.2") {
		t.Fatal("初始名单判定错误")
	}
	// 重写内容并推进 mtime（同秒粒度兜底：显式 Chtimes 到未来）
	if err := os.WriteFile(path, []byte("203.0.113.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if op.Evaluate(nil, "203.0.113.1") || !op.Evaluate(nil, "203.0.113.2") {
		t.Fatal("mtime 变更后必须重建检索结构")
	}
}

// 等价探针：同一 200 条名单分别用 @ipMatch 与 @ipListFast 构建两个真实
// coraza WAF，随机 50 个 IP 各跑事务，判定（是否中断）逐点一致。
func TestIPMatchVsIPListFast_equivalenceProbe(t *testing.T) {
	dir := useAllowedDir(t)
	rng := rand.New(rand.NewPCG(7, 0))
	entries := make([]string, 0, 200)
	for range 200 {
		switch rng.IntN(4) {
		case 0:
			entries = append(entries, fmt.Sprintf("10.%d.%d.0/24", rng.IntN(10), rng.IntN(10)))
		case 1:
			entries = append(entries, fmt.Sprintf("203.0.%d.%d", rng.IntN(5), rng.IntN(256)))
		case 2:
			entries = append(entries, fmt.Sprintf("2001:db8:%x::/64", rng.IntN(4)))
		case 3:
			entries = append(entries, fmt.Sprintf("198.51.%d.0/25", rng.IntN(4)))
		}
	}
	path := writeListFile(t, dir, "probe.txt", entries)

	buildWAF := func(t *testing.T, directives string) coraza.WAF {
		t.Helper()
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatalf("NewWAF: %v", err)
		}
		return waf
	}
	matchWAF := buildWAF(t, fmt.Sprintf("SecRuleEngine On\nSecRule REMOTE_ADDR \"@ipMatch %s\" \"id:1,phase:1,deny\"\n", strings.Join(entries, ",")))
	fastWAF := buildWAF(t, fmt.Sprintf("SecRuleEngine On\nSecRule REMOTE_ADDR \"@ipListFast %s\" \"id:2,phase:1,deny\"\n", path))

	blocked := func(waf coraza.WAF, ip string) bool {
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection(ip, 12345, "127.0.0.1", 443)
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		it := tx.ProcessRequestHeaders()
		return it != nil
	}
	for range 50 {
		var ip string
		if rng.IntN(2) == 0 {
			ip = fmt.Sprintf("%d.%d.%d.%d", []int{10, 203, 198}[rng.IntN(3)], rng.IntN(256), rng.IntN(256), rng.IntN(256))
		} else {
			ip = fmt.Sprintf("2001:db8:%x::%x", rng.IntN(8), rng.IntN(65536))
		}
		if blocked(matchWAF, ip) != blocked(fastWAF, ip) {
			t.Fatalf("探针 %s: @ipMatch=%v @ipListFast=%v — 判定不一致", ip, blocked(matchWAF, ip), blocked(fastWAF, ip))
		}
	}
}

// 写锁代际守卫——并发重建时，基于更早 stat 的解析
// 结果（旧代际）不得覆盖已落地的新代际缓存，否则旧内容会回流服役。
func TestLoadIPListFile_staleGenerationDoesNotOverwriteNewer(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "gen.txt", []string{"192.0.2.1"})
	old := time.Now().Add(-2 * time.Hour).Truncate(time.Second)

	// 新代际先落地：内容 B + 更晚 mtime
	if err := os.WriteFile(path, []byte("198.51.100.77\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	newer := time.Now().Truncate(time.Second)
	if err := os.Chtimes(path, newer, newer); err != nil {
		t.Fatal(err)
	}
	newerState, err := loadIPListFileFresh(path)
	if err != nil {
		t.Fatal(err)
	}

	// 旧代际解析随后完成：基于更早 stat 的内容 A + 更老 mtime
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	state, err := loadIPListFileFresh(path)
	if err != nil {
		t.Fatal(err)
	}

	// Then：缓存仍是新代际（旧解析不得覆盖）
	if state != newerState {
		t.Fatal("旧代际解析覆盖了新代际缓存（写锁缺代际守卫）")
	}
}

// 空文件合法（2026-10-15 始终发射收敛）：空名单投影空文件后 @ipListFast 构建
// 期加载必须无错误（空集=匹配器永不命中，与无规则语义等价）——否则空名单
// 策略的恒发射规则会在 Caddy validate 阶段被 fail-closed 拒绝。含坏行仍报错
// （严格解析不变）；空→有内容的 mtime+size stat 变化照常热感知。
func TestIPListFast_emptyFileLoadsNoErrorAndNeverMatches(t *testing.T) {
	dir := useAllowedDir(t)
	path := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	state, err := loadIPListFileFresh(path)
	if err != nil {
		t.Fatalf("空文件构建期加载必须无错误: %v", err)
	}
	if len(state.v4) != 0 || len(state.v6) != 0 {
		t.Fatalf("空文件集合 v4=%d v6=%d, want 0/0", len(state.v4), len(state.v6))
	}
	// 注释/空行文件同形（解析后 0 条目）
	path2 := writeListFile(t, dir, "blank.txt", []string{"# 注释", "", "; 注释"})
	if _, err := loadIPListFileFresh(path2); err != nil {
		t.Fatalf("注释/空行文件加载必须无错误: %v", err)
	}

	op := newOp(t, path)
	for _, v := range []string{"203.0.113.7", "10.0.0.1", "2001:db8::1", "not-an-ip"} {
		if op.Evaluate(nil, v) {
			t.Fatalf("空文件算子对 %q 不得命中", v)
		}
	}
}

// ResolvePrefixesNormalized 是 Provision 已归一路径的热路径入口：复用同一
// 缓存快照与网段语义，不再重复 Clean/白名单校验。
func TestResolvePrefixesNormalized_contract(t *testing.T) {
	// Given: Provision 已完成白名单归一和首次新鲜加载。
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "tp-normalized.txt", []string{"203.0.113.7", "10.8.0.0/16"})
	cleaned, err := NormalizeAllowedPath(path)
	if err != nil {
		t.Fatalf("NormalizeAllowedPath: %v", err)
	}
	if _, err := LoadPrefixesFresh(cleaned); err != nil {
		t.Fatalf("LoadPrefixesFresh: %v", err)
	}

	// When: 热路径使用已归一入口。
	prefixes, err := ResolvePrefixesNormalized(cleaned)

	// Then: 复用同一缓存快照与网段语义，不重复路径归一。
	if err != nil {
		t.Fatalf("ResolvePrefixesNormalized: %v", err)
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes=%v, want 2 entries", prefixes)
	}
}

// LoadPrefixesFresh 与 NormalizeAllowedPath+ResolvePrefixesNormalized 组合是
// 白名单校验导出入口：fresh=构建期 fail-closed，组合=运行期节流+fail-stale；
// 返回缓存共享只读快照。
func TestLoadAndResolvePrefixes_contract(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "tp-accessor.txt", []string{"203.0.113.7", "10.8.0.0/16"})

	fresh, err := LoadPrefixesFresh(path)
	if err != nil {
		t.Fatalf("LoadPrefixesFresh: %v", err)
	}
	if len(fresh) != 2 {
		t.Fatalf("fresh=%v, want 2 条", fresh)
	}

	// 运行期形态 = 归一（白名单）+ 热路径入口（原 ResolvePrefixes
	// 包装无生产调用方已删除，测试直用生产同款两步组合）。
	cleaned, err := NormalizeAllowedPath(path)
	if err != nil {
		t.Fatalf("NormalizeAllowedPath: %v", err)
	}
	resolve, err := ResolvePrefixesNormalized(cleaned)
	if err != nil {
		t.Fatalf("ResolvePrefixesNormalized: %v", err)
	}
	if len(resolve) != 2 {
		t.Fatalf("resolve=%v, want 2 条", resolve)
	}

	// 白名单外路径拒绝（与算子同规，防目录穿越）。
	for _, p := range []string{"/etc/passwd", "relative.txt"} {
		if _, err := LoadPrefixesFresh(p); err == nil {
			t.Fatalf("LoadPrefixesFresh(%q) 必须被白名单拒绝", p)
		}
		if _, err := NormalizeAllowedPath(p); err == nil {
			t.Fatalf("NormalizeAllowedPath(%q) 必须被白名单拒绝", p)
		}
	}

	// fail-stale：重建失败（坏行）且有旧集 → 返回旧集；从未加载 → error。
	if err := os.WriteFile(path, []byte("garbage!!!\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(path, future, future)
	old := StatCheckInterval
	StatCheckInterval = 0
	t.Cleanup(func() { StatCheckInterval = old })
	stale, err := ResolvePrefixesNormalized(cleaned)
	if err != nil || len(stale) != 2 {
		t.Fatalf("fail-stale 必须返回旧集: got=%v err=%v", stale, err)
	}
	if _, err := LoadPrefixesFresh(path); err == nil {
		t.Fatal("fresh 路径坏行必须报错（构建期 fail-closed）")
	}
}

// fakeFileStat 实现 os.FileInfo（读后复核谓词的单测替身）。
type fakeFileStat struct {
	size int64
	mod  time.Time
}

func (f fakeFileStat) Name() string       { return "iplist" }
func (f fakeFileStat) Size() int64        { return f.size }
func (f fakeFileStat) Mode() os.FileMode  { return 0o644 }
func (f fakeFileStat) ModTime() time.Time { return f.mod }
func (f fakeFileStat) IsDir() bool        { return false }
func (f fakeFileStat) Sys() any           { return nil }

// 读后复核必须覆盖同尺寸原位改写：size 不变而 mtime 变化同样是「读取期间
// 被改写」——只比 size 会把混合字节当完整代际缓存（半新半旧的拒绝面）。
func TestIPListGenerationChanged_detectsSameSizeRewrite(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)
	before := fakeFileStat{size: 100, mod: base}
	if ipListGenerationChanged(before, fakeFileStat{size: 100, mod: base}, nil) {
		t.Fatal("同形态不得判为改写")
	}
	if !ipListGenerationChanged(before, fakeFileStat{size: 100, mod: base.Add(time.Millisecond)}, nil) {
		t.Fatal("同尺寸 mtime 变化必须判为改写")
	}
	if !ipListGenerationChanged(before, fakeFileStat{size: 101, mod: base}, nil) {
		t.Fatal("size 变化必须判为改写")
	}
	if !ipListGenerationChanged(before, nil, os.ErrNotExist) {
		t.Fatal("读后 stat 失败必须判为改写")
	}
}

// 锁表不得随历史路径永驻：最后一个使用者释放后条目退役——否则 u-*/p<id>-*
// 投影按规则身份命名，删除规则后锁表随历史规则数量单调增长。
func TestIPListLoadLocks_retiredAfterRelease(t *testing.T) {
	const path = "/app/waf/locks-retire-probe.iplist"
	unlock := lockIPListLoad(path)
	if _, ok := ipListLoadLocks.Load(path); !ok {
		unlock()
		t.Fatal("持锁期间锁表必须有条目")
	}
	unlock()
	if _, ok := ipListLoadLocks.Load(path); ok {
		t.Fatal("最后一个使用者释放后锁表条目必须退役")
	}
	// 退役后复取用仍正常工作并再次回收（串行化契约不变）。
	unlock = lockIPListLoad(path)
	unlock()
	if _, ok := ipListLoadLocks.Load(path); ok {
		t.Fatal("退役后复取用仍须回收")
	}
}

// 取用/退役并发不得产生双锁（两把锁并发解析同一文件）——互斥区内同时在
// 场者必须恒为 1。
func TestIPListLoadLocks_concurrentAcquireRelease(t *testing.T) {
	const path = "/app/waf/locks-concurrent-probe.iplist"
	var inside atomic.Int64
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 200 {
				unlock := lockIPListLoad(path)
				if n := inside.Add(1); n != 1 {
					t.Errorf("互斥区内同时 %d 个持有者（双锁并发解析）", n)
				}
				inside.Add(-1)
				unlock()
			}
		}()
	}
	wg.Wait()
	if _, ok := ipListLoadLocks.Load(path); ok {
		t.Fatal("并发取用/释放后锁表必须清空")
	}
}
