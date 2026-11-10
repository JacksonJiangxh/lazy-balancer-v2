package caddygeoip

// 侧车计数只在计数变化时写盘：本代进程无失败即无写盘，上一代留下的失败标记
// 永远不会被成功路径删除。新进程的计数从 0 起，旧标记描述的故障不再适用——
// 创建管线时必须清除，否则面板跨重启持续显示「写侧计数不可用」（误报为持续态）。

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAcquireAuditPipeline_clearsPreviousGenerationFailureMarker(t *testing.T) {
	closeTestAuditPipelines(t)
	target := filepath.Join(t.TempDir(), "audit.log")
	marker := auditWriterStatsFailurePath(target)
	if err := os.WriteFile(marker, []byte("writer-stats sidecar write failed at 2026-01-01T00:00:00Z: disk full\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := acquireAuditPipeline(target, 0o644); err != nil {
		t.Fatalf("acquire pipeline: %v", err)
	}

	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("创建管线时必须清除上一代失败标记, stat err=%v", err)
	}
}
