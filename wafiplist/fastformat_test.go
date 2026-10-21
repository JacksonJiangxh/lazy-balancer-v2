package wafiplist

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Step 1 TDD: .fast 二进制格式读写往返
func TestFastFile_WriteReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fast")

	// 乱序输入：本函数原地排序（历史问题 契约声明）。期望值用**独立**的已序
	// 切片——旧测试复用被原地排序的同一入参比较，删除排序仍绿（假绿）。
	v4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("1.2.3.4/32"),
	}
	v6 := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::1/128"),
	}
	wantV4 := []netip.Prefix{
		netip.MustParsePrefix("1.2.3.4/32"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
	}
	wantV6 := []netip.Prefix{
		netip.MustParsePrefix("::1/128"),
		netip.MustParsePrefix("2001:db8::/32"),
	}

	if err := WriteFastFile(path, v4, v6); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}

	state, err := ReadFastFile(path)
	if err != nil {
		t.Fatalf("ReadFastFile: %v", err)
	}

	if len(state.V4) != len(v4) {
		t.Fatalf("V4 count=%d, want %d", len(state.V4), len(v4))
	}
	if len(state.V6) != len(v6) {
		t.Fatalf("V6 count=%d, want %d", len(state.V6), len(v6))
	}
	for i, p := range wantV4 {
		if state.V4[i] != p {
			t.Errorf("V4[%d]=%v, want %v", i, state.V4[i], p)
		}
	}
	for i, p := range wantV6 {
		if state.V6[i] != p {
			t.Errorf("V6[%d]=%v, want %v", i, state.V6[i], p)
		}
	}
}

// 空集往返
func TestFastFile_EmptySets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.fast")
	if err := WriteFastFile(path, nil, nil); err != nil {
		t.Fatalf("WriteFastFile empty: %v", err)
	}
	state, err := ReadFastFile(path)
	if err != nil {
		t.Fatalf("ReadFastFile empty: %v", err)
	}
	if len(state.V4) != 0 || len(state.V6) != 0 {
		t.Fatalf("expected empty, got V4=%d V6=%d", len(state.V4), len(state.V6))
	}
}

// 损坏 magic
func TestFastFile_BadMagic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.fast")
	os.WriteFile(path, []byte("XXXX\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"), 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("expected error for bad magic")
	}
}

// 截断文件
func TestFastFile_Truncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "trunc.fast")
	// header 声称 100 条 v4 但数据只有 10 字节
	header := make([]byte, 16)
	copy(header[0:4], fastFileMagic)
	header[4] = 0
	header[5] = 0
	header[6] = 0
	header[7] = 100 // v4_count=100
	os.WriteFile(path, append(header, make([]byte, 10)...), 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("expected error for truncated file")
	}
}

// 历史修复（历史问题）：腐化 bits/乱序条目静默破坏二分判定——ReadFastFile
// 必须校验 bits 范围（v4≤32/v6≤128）与地址非降序不变量，响亮拒绝腐化文件。
func TestFastFile_CorruptedBitsRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "corrupt.fast")
	// 一条 v4 条目：addr=10.0.0.0, bits=33（越界）
	data := make([]byte, 0, 16+5)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 1) // v4_count=1
	data = append(data, 0, 0, 0, 0) // v6_count=0
	data = append(data, 0, 0, 0, 0) // 保留 4 字节（header 共 16B）
	data = append(data, 10, 0, 0, 0, 33)
	os.WriteFile(path, data, 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("bits>32 must be rejected（invalid prefix 静默破坏二分）")
	}
}

// 同族：乱序条目（地址降序）拒绝。
func TestFastFile_UnorderedRejected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unordered.fast")
	data := make([]byte, 0, 16+10)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 2)      // v4_count=2
	data = append(data, 0, 0, 0, 0)      // v6_count=0
	data = append(data, 0, 0, 0, 0)      // 保留 4 字节（header 共 16B）
	data = append(data, 10, 0, 0, 2, 24) // 10.0.0.2/24
	data = append(data, 10, 0, 0, 1, 24) // 10.0.0.1/24（降序违例）
	os.WriteFile(path, data, 0644)
	if _, err := ReadFastFile(path); err == nil {
		t.Fatal("descending address order must be rejected")
	}
}

// 历史修复（历史问题）：升序校验不验「嵌套/同址不同 bits」形态——
// 10.0.0.0/16 与其子段 10.0.1.0/24 地址升序却互相包含，二分可被窄段遮蔽
// 返回假阴性（「可加载但查询错误」正是 WriteFastFile 注释定义的最坏静默
// 腐化形态）。须响亮拒绝。
func TestFastFile_NestedPrefixesRejected(t *testing.T) {
	dir := t.TempDir()
	// 宽段 10.0.0.0/16 + 其中段 10.0.1.0/24（升序合法、嵌套违例）
	v4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}
	nestedPath := filepath.Join(dir, "nested-v4.fast")
	if err := WriteFastFile(nestedPath, v4, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(nestedPath); err == nil {
		t.Fatal("nested v4 prefixes (wide + contained sub) must be rejected（二分假阴性）")
	}

	// 同址不同 bits：10.0.0.0/16 + 10.0.0.0/24（Compare==0 非降序、包含）
	sameAddr := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/16"),
		netip.MustParsePrefix("10.0.0.0/24"),
	}
	sameAddrPath := filepath.Join(dir, "same-addr-v4.fast")
	if err := WriteFastFile(sameAddrPath, sameAddr, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(sameAddrPath); err == nil {
		t.Fatal("same-address different-bits v4 prefixes must be rejected（二分假阴性）")
	}

	// v6 同口径：2001:db8::/32 + 2001:db8:1::/48
	v6 := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2001:db8:1::/48"),
	}
	v6Path := filepath.Join(dir, "nested-v6.fast")
	if err := WriteFastFile(v6Path, nil, v6); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(v6Path); err == nil {
		t.Fatal("nested v6 prefixes must be rejected（二分假阴性）")
	}

	// 反例：相邻（不嵌套）合法文件不受影响——10.0.0.0/24 + 10.0.1.0/24
	adjacent := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
		netip.MustParsePrefix("10.0.1.0/24"),
	}
	adjacentPath := filepath.Join(dir, "adjacent.fast")
	if err := WriteFastFile(adjacentPath, adjacent, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(adjacentPath); err != nil {
		t.Fatalf("adjacent disjoint prefixes must load, got: %v", err)
	}
}

// 历史问题：读侧必须校验主机位已掩码——.fast 是跨进程输入（节点回传），
// 单条未掩码条目可通过 bits/升序/嵌套全部校验，却让二分查询用未掩码地址
// 比较而假阴性（威胁名单静默漏拦）。
func TestFastFile_UnmaskedEntriesRejected(t *testing.T) {
	dir := t.TempDir()

	// 单条未掩码 v4：1.2.3.200/24（无前驱可比较嵌套；修复前可加载）。
	v4Path := filepath.Join(dir, "unmasked-v4.fast")
	data := make([]byte, 0, 16+5)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 1) // v4_count=1
	data = append(data, 0, 0, 0, 0) // v6_count=0
	data = append(data, 0, 0, 0, 0) // 保留 4 字节
	data = append(data, 1, 2, 3, 200, 24)
	if err := os.WriteFile(v4Path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(v4Path); err == nil {
		t.Fatal("unmasked v4 host bits must be rejected（二分假阴性）")
	}

	// 单条未掩码 v6：2001:db8::1/32。
	v6Addr := netip.MustParseAddr("2001:db8::1").As16()
	v6Path := filepath.Join(dir, "unmasked-v6.fast")
	data = make([]byte, 0, 16+17)
	data = append(data, []byte(fastFileMagic)...)
	data = append(data, 0, 0, 0, 0) // v4_count=0
	data = append(data, 0, 0, 0, 1) // v6_count=1
	data = append(data, 0, 0, 0, 0) // 保留 4 字节
	data = append(data, v6Addr[:]...)
	data = append(data, 32)
	if err := os.WriteFile(v6Path, data, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(v6Path); err == nil {
		t.Fatal("unmasked v6 host bits must be rejected（二分假阴性）")
	}

	// 反例：写侧产物（掩码后）照常加载。
	okPath := filepath.Join(dir, "masked.fast")
	if err := WriteFastFile(okPath, []netip.Prefix{
		netip.MustParsePrefix("1.2.3.200/24"),
	}, []netip.Prefix{netip.MustParsePrefix("2001:db8::1/32")}); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(okPath); err != nil {
		t.Fatalf("masked entries from WriteFastFile must load, got: %v", err)
	}
}

// 历史问题（历史）：ReadFastFile 对跨进程 .fast 输入必须先过 Stat
// 体积门再读字节——异常/恶意超大文件不得在读取阶段就拖垮内存（文本名单
// 路径已有 MaxFileBytes 同型硬上限，iplistfast.go:249-250）。
func TestFastFile_ReadSizeCap(t *testing.T) {
	dir := t.TempDir()
	old := MaxFastFileBytes
	MaxFastFileBytes = 4096
	t.Cleanup(func() { MaxFastFileBytes = old })

	// 超限文件：内容本身合法（写侧产物拼接填充无所谓——体积门先于内容解析）。
	bigPath := filepath.Join(dir, "big.fast")
	if err := os.WriteFile(bigPath, make([]byte, 4097), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(bigPath); err == nil {
		t.Fatal("oversize .fast must be rejected before reading body")
	}

	// 回归形状：上限内的合法文件照常加载。
	okPath := filepath.Join(dir, "ok.fast")
	if err := WriteFastFile(okPath, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil); err != nil {
		t.Fatalf("WriteFastFile: %v", err)
	}
	if _, err := ReadFastFile(okPath); err != nil {
		t.Fatalf("in-cap .fast must load: %v", err)
	}

	// 边界形状：恰好等于上限的文件不被体积门误杀（由后续内容校验裁决）。
	exactPath := filepath.Join(dir, "exact.fast")
	if err := os.WriteFile(exactPath, make([]byte, 4096), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFastFile(exactPath); err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("exact-cap file must pass the size gate and fail on content (magic), got: %v", err)
	}
}
