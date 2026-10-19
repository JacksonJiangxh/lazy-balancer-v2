package wafiplist

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 写侧是最该 fail-visible 的边界：主机位未掩码的单条 1.2.3.200/24 能通过
// 读侧全部校验（无前驱条目可做嵌套比较），但二分查询用未掩码地址比较 →
// 查 1.2.3.200 假阴性；族错配则在 As4（v6 入参 panic）/As16（v4 → 4in6 +
// v4 bits，可加载但永不命中）处腐化。写侧必须掩码 + 显式校验族并返回
// error（不得 panic、不得留下半成品）。
func TestWriteFastFile_masksHostBitsAndRejectsWrongFamily(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mask.fast")
	if err := WriteFastFile(path, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.200/24"),
		netip.MustParsePrefix("10.20.30.40/32"),
	}, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	state, err := ReadFastFile(path)
	if err != nil {
		t.Fatalf("ReadFastFile: %v", err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.0/24"),
		netip.MustParsePrefix("10.20.30.40/32"),
	}
	if len(state.V4) != len(want) {
		t.Fatalf("V4=%v, want %v", state.V4, want)
	}
	for i, p := range want {
		if state.V4[i] != p {
			t.Errorf("V4[%d]=%v, want %v（写侧须掩码主机位）", i, state.V4[i], p)
		}
	}

	for _, tc := range []struct {
		name string
		v4   []netip.Prefix
		v6   []netip.Prefix
	}{
		{"v4 槽含 v6 前缀", []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")}, nil},
		{"v6 槽含 v4 前缀", nil, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}},
		{"v6 槽含 4in6 前缀", nil, []netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.0/104")}},
		{"invalid 前缀", []netip.Prefix{{}}, nil},
	} {
		p := filepath.Join(dir, tc.name+".fast")
		if err := WriteFastFile(p, tc.v4, tc.v6); err == nil {
			t.Fatalf("%s: 必须返回 error（写侧 fail-visible）", tc.name)
		}
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Fatalf("%s: 校验失败不得留下产物文件", tc.name)
		}
	}
}

// 固定 path+".tmp" 在并发/多调用方（绕过 wafFileMu 的未来调用方）下会互相
// 覆盖：rename ENOENT 或旧代际覆盖新代际。CreateTemp 使每次写入独占临时
// 文件；成功后不得残留临时文件。
func TestWriteFastFile_uniqueTempFileAndNoResidue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.fast")
	decoy := path + ".tmp"
	if err := os.WriteFile(decoy, []byte("decoy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteFastFile(path, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if b, err := os.ReadFile(decoy); err != nil || string(b) != "decoy" {
		t.Fatalf("固定名 %q 不得被写侧复用/覆写: content=%q err=%v", decoy, b, err)
	}
	residue, err := filepath.Glob(filepath.Join(dir, "x.fast.*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(residue) != 0 {
		t.Fatalf("成功写入后残留临时文件: %v", residue)
	}
}

// 尾部多余字节（截断+追加/旧版本写长）与未知 flags 位此前被静默容忍——
// 按当前计数解析会把「格式误读」藏到运行期。须响亮拒绝。
func TestReadFastFile_rejectsTrailingGarbageAndUnknownFlags(t *testing.T) {
	dir := t.TempDir()

	valid := filepath.Join(dir, "valid.fast")
	badPath := filepath.Join(dir, "bad.fast")
	if err := WriteFastFile(valid, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(valid)
	if err != nil {
		t.Fatal(err)
	}

	// 尾部垃圾
	if err := os.WriteFile(badPath, append(append([]byte{}, raw...), 'j', 'u', 'n', 'k'), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(badPath); err == nil {
		t.Fatal("尾部多余字节必须拒绝（长度不精确=格式误读）")
	}

	// 未知 flags 位（header[12:16]）
	mutated := append([]byte{}, raw...)
	mutated[15] = 1
	if err := os.WriteFile(badPath, mutated, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(badPath); err == nil {
		t.Fatal("非零 flags 必须拒绝（未知特性位不得静默忽略）")
	}
}

// netip.ParseAddr 接受 zone 形态（fe80::1%eth0，甚至 %eth0/64），
// 分裂。加载/威胁库解析只看 ParseIPEntry 是否报错，须同口径拒绝。
func TestParseIPEntry_rejectsZone(t *testing.T) {
	for _, entry := range []string{"fe80::1%eth0", "fe80::1%1", "fe80::1%eth0/64"} {
		if p, err := ParseIPEntry(entry); err == nil {
			t.Fatalf("ParseIPEntry(%q)=%v, want error（带 zone 的地址不视为有效条目）", entry, p)
		}
	}
	// 回归：无 zone 形态不漂移
	for _, entry := range []string{"fe80::1", "10.0.0.1", "2001:db8::/48"} {
		if _, err := ParseIPEntry(entry); err != nil {
			t.Fatalf("ParseIPEntry(%q) 必须成功: %v", entry, err)
		}
	}
}

// 此前对**原始串**做 strings.Contains(path, "..")：文件名合法的
// /app/waf/a..b.txt 被误拒；filepath.Clean + 绝对路径 + 前缀已足以防穿越。
func TestNormalizeAllowedPath_allowsDotDotInFilename(t *testing.T) {
	dir := useAllowedDir(t)
	for _, name := range []string{"a..b.txt", "u-deny-1.txt", "p1-acl.txt"} {
		p := filepath.Join(dir, name)
		got, err := NormalizeAllowedPath(p)
		if err != nil {
			t.Fatalf("NormalizeAllowedPath(%q) 误拒: %v", p, err)
		}
		if got != p {
			t.Fatalf("NormalizeAllowedPath(%q)=%q, want 原路径", p, got)
		}
	}
	// 穿越仍拒绝（Clean 后越出白名单）
	for _, p := range []string{
		filepath.Join(dir, "..", "evil.txt"),
		dir + string(filepath.Separator) + "sub" + string(filepath.Separator) + ".." + string(filepath.Separator) + ".." + string(filepath.Separator) + "evil.txt",
		"/etc/passwd",
		"relative/path.txt",
	} {
		if _, err := NormalizeAllowedPath(p); err == nil {
			t.Fatalf("NormalizeAllowedPath(%q) 必须拒绝（目录穿越）", p)
		}
	}
}

// parseIPListFile 此前「逐行 ParseIPEntry 校验 → AggregatePrefixes 再解析
// 一遍」= 每条目 2 次解析。新增 AggregateParsedPrefixes 单源原语后，逐条目
// 只解析一次。
func TestParseIPListFile_parsesEachEntryOnce(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "once.txt", []string{"10.0.0.0/8", "203.0.113.7", "2001:db8::/48"})
	before := parseEntryCallsForTest.Load()
	if _, err := loadIPListFileFresh(path); err != nil {
		t.Fatal(err)
	}
	if got := parseEntryCallsForTest.Load() - before; got != 3 {
		t.Fatalf("条目解析次数=%d, want 3（逐条目单次解析；双重解析形态=6）", got)
	}
}

// U09-07 回归：解析原语与字符串入口语义逐点等价（含主机位掩码形态）。
func TestAggregateParsedPrefixes_equivalentToAggregatePrefixes(t *testing.T) {
	entries := []string{
		"10.0.0.0/25", "10.0.0.128/25", // 兄弟归并
		"203.0.113.0/24", "203.0.113.7", // 覆盖剔除
		"1.2.3.200/24",                 // 主机位未掩码（ParseIPEntry 掩码）
		"2001:db8::/64", "2001:db8::1", // v6 覆盖
		"::ffff:198.51.100.0/120", // 4in6 归一
	}
	want := AggregatePrefixes(entries)
	parsed := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		p, err := ParseIPEntry(e)
		if err != nil {
			t.Fatalf("ParseIPEntry(%q): %v", e, err)
		}
		parsed = append(parsed, p)
	}
	got := AggregateParsedPrefixes(parsed)
	if len(got) != len(want) {
		t.Fatalf("AggregateParsedPrefixes=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AggregateParsedPrefixes[%d]=%v, want %v", i, got[i], want[i])
		}
	}
}

// U09-07 同族：AggregateIPEntries 也不得双重解析（非法条目原样透传）。
func TestAggregateIPEntries_parsesEachEntryOnce(t *testing.T) {
	entries := []string{"10.0.0.1", "10.0.0.7", "garbage"}
	before := parseEntryCallsForTest.Load()
	got := AggregateIPEntries(entries)
	if n := parseEntryCallsForTest.Load() - before; n != int64(len(entries)) {
		t.Fatalf("条目解析次数=%d, want %d（校验后聚合再解析=2×）", n, len(entries))
	}
	want := []string{"10.0.0.1/32", "10.0.0.7/32", "garbage"}
	if len(got) != len(want) {
		t.Fatalf("AggregateIPEntries=%v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("AggregateIPEntries[%d]=%q, want %q", i, got[i], want[i])
		}
	}
}

// 旧实现存挂钟 UnixNano，time.Since(time.Unix(...)) 无单调读数——NTP/手动
// 回拨会让节流窗口无限延长（回拨多大，名单变更感知延迟就多长）。读数须为
// 「包基线以来的单调纳秒」（量级 ≪ UnixNano 的 1.7e18）。
func TestIPListFileState_statThrottleTickIsMonotonic(t *testing.T) {
	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "mono.txt", []string{"203.0.113.7"})
	state, err := loadIPListFileFresh(path)
	if err != nil {
		t.Fatal(err)
	}
	tick := state.lastCheckTick.Load()
	if tick <= 0 {
		t.Fatalf("lastCheckTick=%d, want >0", tick)
	}
	if tick > int64(100_000*time.Hour) { // 100_000h≈11.4 年；UnixNano 形态远超此界
		t.Fatalf("lastCheckTick=%d 形如挂钟 UnixNano，必须存单调读数（基线以来纳秒）", tick)
	}
	// 时间推进后读数单调增长
	time.Sleep(2 * time.Millisecond)
	if _, err := loadIPListFileFresh(path); err != nil {
		t.Fatal(err)
	}
	if next := state.lastCheckTick.Load(); next <= tick {
		t.Fatalf("lastCheckTick 未推进: %d → %d", tick, next)
	}
}

// 钩子此前零消费方（注释声称「渲染日志已覆盖」不成立）——运行期名单被删/
// 写坏时按旧集合无限期判定且无任何日志。默认实现须写 stderr 日志；同路径
// 上报按 StaleServeLogInterval 节流；恢复成功后清除节流记录（再故障即时上报）。
func TestStaleServe_reportThrottledPerPathAndResetOnRecovery(t *testing.T) {
	oldInterval := StaleServeLogInterval
	oldHook := OnStaleServe
	StaleServeLogInterval = time.Hour
	var calls []string
	OnStaleServe = func(path string, err error) {
		if err == nil {
			t.Errorf("stale 上报必须携带 error")
		}
		calls = append(calls, path)
	}
	oldStat := StatCheckInterval
	StatCheckInterval = 0
	t.Cleanup(func() {
		StaleServeLogInterval = oldInterval
		OnStaleServe = oldHook
		StatCheckInterval = oldStat
	})

	dir := useAllowedDir(t)
	path := writeListFile(t, dir, "stale-hook.txt", []string{"203.0.113.7"})
	if _, err := LoadPrefixesFresh(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if _, err := ResolvePrefixesNormalized(path); err != nil {
			t.Fatalf("fail-stale 必须返回旧集: %v", err)
		}
	}
	if len(calls) != 1 {
		t.Fatalf("同一路径节流窗口内应只上报 1 次, got %d", len(calls))
	}
	if calls[0] != path {
		t.Fatalf("上报路径=%q, want %q", calls[0], path)
	}

	// 恢复（成功加载清除节流记录）→ 再次故障即时上报
	writeListFile(t, dir, "stale-hook.txt", []string{"203.0.113.7"})
	if _, err := LoadPrefixesFresh(path); err != nil {
		t.Fatalf("恢复加载: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolvePrefixesNormalized(path); err != nil {
		t.Fatalf("fail-stale(第二次): %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("恢复后再次故障必须即时上报, got %d 次: %v", len(calls), calls)
	}
}
