package services

// F-L4-68-01（第 68 轮，P4）：cert-waiting-ca Run 体「!certJobsActive() →
// StopLoop」存在 T0 读后 T1 入队竞态窗口——续期扫描入队侧 StartLoop 先落地、
// Run 侧 StopLoop 后落地时，最终态=任务活跃但调度已停（无人再唤醒，滞留到
// 下次入队/重启）。修复：StopLoop 后复检 certJobsActiveFn——活跃则重新
// StartLoop 拉回（复检之后的新入队由入队侧 StartLoop 承担，窗口闭合）。

import (
	"sync"
	"testing"

	"lazy-balancer-v2/internal/taskengine"
)

// stubCertJobsActiveSequence 按序返回脚本化判定结果（用尽后保持最后一个值）。
func stubCertJobsActiveFn(t *testing.T, seq ...bool) {
	t.Helper()
	old := certJobsActiveFn
	var mu sync.Mutex
	certJobsActiveFn = func() bool {
		mu.Lock()
		defer mu.Unlock()
		if len(seq) > 1 {
			v := seq[0]
			seq = seq[1:]
			return v
		}
		return seq[0]
	}
	t.Cleanup(func() { certJobsActiveFn = old })
}

func waitingCALoopOn(t *testing.T, te *taskengine.Engine) bool {
	t.Helper()
	m, ok := te.Lookup("cert-waiting-ca")
	if !ok {
		t.Fatal("cert-waiting-ca 未注册")
	}
	return m.LoopOn
}

// Given 竞态序列：Run 首查「无活」（false）→ 判定停止前新任务入队（复检 true）。
// When 手动触发 cert-waiting-ca 执行一轮。
// Then 调度不得关闭（复检捕获入队并拉回——现实现单查直接 StopLoop：RED）。
func TestTaskEngineWire_CertWaitingCAStopRechecksActiveJobs(t *testing.T) {
	te := newWireTestEngine(t)
	te.StartLoop("cert-waiting-ca")
	stubCertJobsActiveFn(t, false, true)

	if err := te.Trigger("cert-waiting-ca", "manual", ""); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if !waitingCALoopOn(t, te) {
		t.Fatal("T1 入队窗口竞态下调度被关闭——任务活跃但补扫循环已停（滞留）")
	}
}

// 回归形状：真实全终态（首查 false、复检仍 false）→ 照常自动停（默认关闭态）。
func TestTaskEngineWire_CertWaitingCAStopsWhenIdleAfterRecheck(t *testing.T) {
	te := newWireTestEngine(t)
	te.StartLoop("cert-waiting-ca")
	stubCertJobsActiveFn(t, false)

	if err := te.Trigger("cert-waiting-ca", "manual", ""); err != nil {
		t.Fatalf("Trigger: %v", err)
	}
	if waitingCALoopOn(t, te) {
		t.Fatal("全部终态后调度应自动停止（回归默认关闭态）")
	}
}
