package caddygeoip

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 审计写侧失败/丢弃当前仅 Caddy 日志可见：面板健康位需要跨进程可读的计数。
// 契约：管线把累计 fail/drop 计数原子维护，并由 drain 低频写入目标路径旁的
// 侧车文件（不进入请求路径）；根服务摄取 tick 读该文件。
func TestAuditPipeline_writesWriterStatsSidecar(t *testing.T) {
	closeTestAuditPipelines(t)
	oldInterval := auditWriterStatsInterval
	auditWriterStatsInterval = 30 * time.Millisecond
	t.Cleanup(func() { auditWriterStatsInterval = oldInterval })

	target := filepath.Join(t.TempDir(), "audit.log")
	p, err := acquireAuditPipeline(target, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	p.reportDropped()
	p.reportIOError("write", errors.New("injected disk failure"))

	statsPath := auditWriterStatsPath(target)
	deadline := time.Now().Add(3 * time.Second)
	var raw []byte
	for {
		raw, err = os.ReadFile(statsPath)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("writer stats sidecar %s not written: %v", filepath.Base(statsPath), err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	var got struct {
		Dropped  uint64 `json:"dropped"`
		IOErrors uint64 `json:"io_errors"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("stats sidecar malformed: %v (%s)", err, raw)
	}
	if got.Dropped != 1 || got.IOErrors != 1 {
		t.Fatalf("stats=%+v, want dropped=1 io_errors=1", got)
	}
	if p.dropped.Load() != 1 {
		t.Fatalf("pipeline dropped counter=%d, want 1", p.dropped.Load())
	}
}
