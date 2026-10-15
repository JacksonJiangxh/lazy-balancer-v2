package handlers

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 启动竞态修复（历史）测试夹具：临时监督器 pid 标记 + 临时回放标记路径
// + 短超时——与 caddy_test.go 监督器委托测试同注入缝模式（包级 var）。
// supervisorAlive=true 形态以本测试进程 pid 冒充监督器（存活、状态非 Z，
// caddyProcRoot 保持真 /proc）。
func setupStartupReplayFixture(t *testing.T, supervisorUp bool) string {
	t.Helper()
	oldPid, oldMarker, oldTimeout, oldProc := caddySupervisorPidFile, caddyStartupReplayMarkerFile, startupReplayWaitTimeout, caddyProcRoot
	dir := t.TempDir()
	pidFile := filepath.Join(dir, "supervisor.pid")
	markerFile := filepath.Join(dir, "startup-replayed")
	procRoot := t.TempDir() // 伪 /proc（macOS 无 /proc——caddy_test.go seedProcStat 同模式）
	if supervisorUp {
		// 伪 /proc 种活 pid（存活、状态非 Z）——supervisorAlive 真
		if err := os.WriteFile(pidFile, []byte("12345"), 0o600); err != nil {
			t.Fatal(err)
		}
		seedProcStat(t, procRoot, "12345", "caddy-superv", 'S')
	} // else：pid 文件不落盘 = supervisorAlive false
	caddySupervisorPidFile = pidFile
	caddyStartupReplayMarkerFile = markerFile
	startupReplayWaitTimeout = 2 * time.Second
	caddyProcRoot = procRoot
	t.Cleanup(func() {
		caddySupervisorPidFile, caddyStartupReplayMarkerFile, startupReplayWaitTimeout, caddyProcRoot = oldPid, oldMarker, oldTimeout, oldProc
	})
	return markerFile
}

// Given 监督器不在场（测试/裸跑环境）。When waitStartupReplayDone。
// Then 立即返回——协议关闭，不得等满超时拖慢启动。
func TestWaitStartupReplayDone_noSupervisorReturnsImmediately(t *testing.T) {
	setupStartupReplayFixture(t, false)

	start := time.Now()
	waitStartupReplayDone()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("监督器不在场应立即返回，实际耗时 %s", elapsed)
	}
}

// Given 监督器在位且回放标记已写（启动回放阶段已完成）。When wait。
// Then 立即返回——手动重载 / caddy-restart 重应用的常态路径。
func TestWaitStartupReplayDone_markerPresentReturnsImmediately(t *testing.T) {
	marker := setupStartupReplayFixture(t, true)
	if err := os.WriteFile(marker, []byte("done"), 0o600); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	waitStartupReplayDone()
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("标记在场应立即返回，实际耗时 %s", elapsed)
	}
}

// Given 监督器在位、标记延迟 300ms 才落盘（监督器等 admin 就绪+回放中）。
// When wait。Then 阻塞至标记落盘后返回——等待真实发生且被释放（时序定死：
// 回放→标记→app 应用）。
func TestWaitStartupReplayDone_waitsForMarkerThenReturns(t *testing.T) {
	marker := setupStartupReplayFixture(t, true)
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(marker, []byte("done"), 0o600)
	}()

	start := time.Now()
	waitStartupReplayDone()
	elapsed := time.Since(start)
	if elapsed < 250*time.Millisecond {
		t.Fatalf("标记未落盘时应等待，实际仅 %s 即返回", elapsed)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("标记落盘后应及时返回，实际耗时 %s", elapsed)
	}
}

// Given 监督器在位、标记永不出现（监督器夭折病理态）。When wait。
// Then 有界超时后放行——退化语义=修复前（app 直接应用），不得挂死启动。
func TestWaitStartupReplayDone_timesOutAndProceeds(t *testing.T) {
	setupStartupReplayFixture(t, true) // 超时注入为 2s

	start := time.Now()
	waitStartupReplayDone()
	if elapsed := time.Since(start); elapsed < 1500*time.Millisecond {
		t.Fatalf("应等满超时（%s）再放行，实际 %s 即返回", startupReplayWaitTimeout, elapsed)
	}
}
