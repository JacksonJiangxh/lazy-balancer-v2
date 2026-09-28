package wafiplist

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// Step 1 TDD: .fast 二进制格式读写往返
func TestFastFile_WriteReadRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.fast")

	v4 := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("1.2.3.4/32"),
	}
	v6 := []netip.Prefix{
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("::1/128"),
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
	for i, p := range v4 {
		if state.V4[i] != p {
			t.Errorf("V4[%d]=%v, want %v", i, state.V4[i], p)
		}
	}
	for i, p := range v6 {
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

// EnsureFastFile: .fast 比 .iplist 新 → 跳过编译
func TestEnsureFastFile_UpToDate(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "test.iplist")
	fast := filepath.Join(dir, "test.iplist.fast")

	os.WriteFile(src, []byte("1.2.3.4\n"), 0644)
	// 先写 .fast（会更新 mtime）
	WriteFastFile(fast, []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")}, nil)

	compileCalled := false
	fn := func(p string) ([]netip.Prefix, []netip.Prefix, error) {
		compileCalled = true
		return nil, nil, nil
	}

	result, err := EnsureFastFile(src, fn)
	if err != nil {
		t.Fatalf("EnsureFastFile: %v", err)
	}
	if result != fast {
		t.Fatalf("result=%s, want %s", result, fast)
	}
	if compileCalled {
		t.Fatal("compile should be skipped when .fast is up to date")
	}
}
