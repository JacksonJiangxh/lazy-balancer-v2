package caddygeoip

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// F62-30(第 62 轮审计):写侧三文件此前零测试——补并发追加/空 ID 短路/目录
// 惰性创建的行为钉。

// Given: 并发 50 goroutine 各追加一行
// When: AppendSecurityTiming
// Then: 互斥锁保证 50 行完整落盘(无交错/丢行)
func TestAppendSecurityTiming_concurrentAppend(t *testing.T) {
	dir := t.TempDir()
	orig := securityTimingLogPath
	securityTimingLogPath = filepath.Join(dir, "timing.log")
	defer func() {
		securityTimingLogPath = orig
		securityTimingFd = nil
	}()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			AppendSecurityTiming(strings.Repeat("a", 8), int64(n))
		}(i)
	}
	wg.Wait()
	if securityTimingFd != nil {
		_ = securityTimingFd.Sync()
	}
	data, err := os.ReadFile(securityTimingLogPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 50 {
		t.Errorf("lines=%d; want 50 (mutex must serialize appends)", len(lines))
	}
	for _, l := range lines {
		if !strings.HasPrefix(l, "aaaaaaaa ") {
			t.Errorf("malformed line: %q", l)
		}
	}
}

// Given: 空 ID
// When: AppendSecurityTiming
// Then: 短路(不建文件)
func TestAppendSecurityTiming_emptyIdShortCircuit(t *testing.T) {
	dir := t.TempDir()
	orig := securityTimingLogPath
	securityTimingLogPath = filepath.Join(dir, "timing.log")
	defer func() { securityTimingLogPath = orig; securityTimingFd = nil }()

	AppendSecurityTiming("", 100)

	if _, err := os.Stat(securityTimingLogPath); !os.IsNotExist(err) {
		t.Error("empty ID must short-circuit without creating file")
	}
}

// Given: 目录不存在
// When: AppendSecurityTiming
// Then: MkdirAll 兜底后正常写入
func TestAppendSecurityTiming_mkdirFallback(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b", "timing.log")
	orig := securityTimingLogPath
	securityTimingLogPath = nested
	defer func() { securityTimingLogPath = orig; securityTimingFd = nil }()

	AppendSecurityTiming("testid01", 42)

	data, err := os.ReadFile(nested)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != "testid01 42" {
		t.Errorf("content=%q; want %q", data, "testid01 42")
	}
}

// Given: 正常调用
// When: securityTimingID
// Then: 16 字符 hex(8 字节;F62-29 扩容后)
func TestSecurityTimingID_length(t *testing.T) {
	id := securityTimingID()
	if len(id) != 16 {
		t.Errorf("len=%d; want 16 (8 bytes hex)", len(id))
	}
	for _, c := range id {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			t.Errorf("non-hex char %q in %q", c, id)
		}
	}
}
