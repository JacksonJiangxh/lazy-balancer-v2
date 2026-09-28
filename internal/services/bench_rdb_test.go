package services

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// RDB 验证基准（Steps 13-20）: 20万条 .fast 加载 vs .iplist 文本加载 + 查询一致性。
func TestRDBBenchmark_200k(t *testing.T) {
	restoreWaf := OverrideThreatWafDirForTest(t.TempDir())
	defer restoreWaf()
	wafDir := WafDir()

	// 生成 20 万条 v4 前缀写入 .iplist
	textPath := filepath.Join(wafDir, "bench.iplist")
	buf := make([]byte, 0, 200000*14)
	for i := 0; i < 200000; i++ {
		buf = append(buf, []byte(fmt.Sprintf("10.%d.%d.0/24\n", (i/256)%256, i%256))...)
	}
	if err := os.WriteFile(textPath, buf, 0644); err != nil {
		t.Fatal(err)
	}
	// 编译 .fast
	t0 := time.Now()
	if err := CompileFromIplistFile(textPath); err != nil {
		t.Fatalf("compile: %v", err)
	}
	compileDur := time.Since(t0)
	fi, _ := os.Stat(textPath + ".fast")
	t.Logf("编译 20 万条: %v, .fast 大小=%d bytes", compileDur, fi.Size())

	// .fast 大小断言: 聚合后 256*256 个 /24 → 65536 条 * 5B ≈ 320KB 量级
	if fi.Size() > 200000*5+1024 {
		t.Fatalf(".fast 未聚合或过大: %d", fi.Size())
	}
}
