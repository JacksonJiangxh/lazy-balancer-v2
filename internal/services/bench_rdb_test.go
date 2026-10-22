package services

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/wafiplist"
)

// RDB 编译规模回归：20 万条 /24 文本编译为聚合 .fast，并约束产物大小。
// 加载与查询一致性由 wafiplist 的 Parse/Evaluate 契约测试覆盖，本测试不宣称基准对比。
func TestRDBCompile_200kAggregates(t *testing.T) {
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
	fastPath := wafiplist.FastPath(textPath)
	fi, statErr := os.Stat(fastPath)
	if statErr != nil {
		t.Fatalf("stat 编译产物 %s: %v", fastPath, statErr)
	}
	state, readErr := wafiplist.ReadFastFile(fastPath)
	if readErr != nil {
		t.Fatalf("read 编译产物: %v", readErr)
	}
	t.Logf("编译 20 万条: %v, 聚合后 v4=%d v6=%d, .fast 大小=%d bytes",
		compileDur, len(state.V4), len(state.V6), fi.Size())

	// 断言口径按**聚合后**条数：输入的 65536 个不同 /24 覆盖 10.0.0.0/8
	// 全部 24 位主机空间，聚合结果必须恰为单条 10.0.0.0/8（留一条未聚合的
	// /24 都会让条数 >1）；.fast 大小由该条数精确推导（16B 头 + 5B/v4）。
	if len(state.V4) != 1 || state.V4[0].String() != "10.0.0.0/8" || len(state.V6) != 0 {
		t.Fatalf("聚合结果 v4=%v v6=%v, want [10.0.0.0/8] 且无 v6", state.V4, state.V6)
	}
	// .fast 尾部带 4 字节 crc32c 校验和（wafiplist fastformat 的 checksum
	// flag 形态，覆盖 header+条目区），大小公式必须含该尾部。
	wantSize := int64(16 + len(state.V4)*5 + len(state.V6)*17 + 4)
	if fi.Size() != wantSize {
		t.Fatalf(".fast 大小=%d, want %d（16B 头 + 5B/v4 + 17B/v6 + 4B crc32c）", fi.Size(), wantSize)
	}
}
