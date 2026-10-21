package taskengine

// RunSyncQuiet：执行同一 Run 体但不落 task_runs 行（高频自愈重试降噪），
// RunSync 仍按既有语义落行。

import (
	"sync/atomic"
	"testing"
)

func TestEngine_RunSyncQuietExecutesWithoutRunRow(t *testing.T) {
	e := newTestEngine(t)
	var runs atomic.Int32
	const id = "t-quiet"
	if err := e.Register(Descriptor{
		ID: id, Family: "t", Name: "静默重试", Kind: KindOneshot,
		Run: func(RunContext) error {
			runs.Add(1)
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := e.RunSyncQuiet(id, "caddy-restart", ""); err != nil {
		t.Fatalf("quiet run: %v", err)
	}
	if got := runs.Load(); got != 1 {
		t.Fatalf("执行次数=%d, want 1", got)
	}
	if got := countRuns(t, id); got != 0 {
		t.Fatalf("quiet 轮 task_runs=%d, want 0（重试降噪：不落行）", got)
	}

	if _, err := e.RunSync(id, "caddy-restart", ""); err != nil {
		t.Fatalf("recorded run: %v", err)
	}
	if got := runs.Load(); got != 2 {
		t.Fatalf("执行次数=%d, want 2", got)
	}
	if got := countRuns(t, id); got != 1 {
		t.Fatalf("RunSync 轮 task_runs=%d, want 1", got)
	}
}
