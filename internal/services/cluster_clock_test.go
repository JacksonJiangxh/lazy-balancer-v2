package services

// JJC-20261122-001 时钟偏移测量模块测试。

import (
	"testing"
	"time"
)

// resetMasterClockOffsetForTest 清空包级偏移测量状态（偏移量/测量时刻/告警
// 去重值），并在测试结束时还原——偏移是包级单例，跨测试必须隔离。
func resetMasterClockOffsetForTest(t *testing.T) {
	t.Helper()
	oldOffset := masterClockOffsetNanos.Load()
	oldAt := masterClockOffsetAtUnix.Load()
	oldWarn := masterClockOffsetLastWarnSec.Load()
	masterClockOffsetNanos.Store(0)
	masterClockOffsetAtUnix.Store(0)
	masterClockOffsetLastWarnSec.Store(0)
	t.Cleanup(func() {
		masterClockOffsetNanos.Store(oldOffset)
		masterClockOffsetAtUnix.Store(oldAt)
		masterClockOffsetLastWarnSec.Store(oldWarn)
	})
}

func TestMasterAdjustedNow_zeroOffsetWithoutMeasurement(t *testing.T) {
	resetMasterClockOffsetForTest(t)
	local := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	if got := masterAdjustedNow(local); !got.Equal(local) {
		t.Fatalf("no measurement should return local unchanged, got %v", got)
	}
}

func TestMasterAdjustedNow_appliesFreshOffset(t *testing.T) {
	resetMasterClockOffsetForTest(t)
	local := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	// 主节点时钟落后本机 120s：master = local - 120s
	RecordMasterClockOffset(local.Add(-120*time.Second).Unix(), local)
	got := masterAdjustedNow(local)
	if want := local.Add(-120 * time.Second); !got.Equal(want) {
		t.Fatalf("adjusted now=%v, want %v", got, want)
	}
}

func TestMasterAdjustedNow_staleMeasurementFallsBackToZero(t *testing.T) {
	resetMasterClockOffsetForTest(t)
	// 测量时刻落在 10 分钟新鲜度窗口之外：回退零偏移
	stale := time.Date(2026, 11, 22, 0, 0, 0, 0, time.UTC)
	local := stale.Add(masterClockOffsetFreshFor + time.Minute)
	RecordMasterClockOffset(stale.Add(-120*time.Second).Unix(), stale)
	if got := masterAdjustedNow(local); !got.Equal(local) {
		t.Fatalf("stale measurement should fall back to local, got %v", got)
	}
}

func TestRecordMasterClockOffset_clampsAbsurdValues(t *testing.T) {
	resetMasterClockOffsetForTest(t)
	local := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	// 偏移超 ±24h 钳制：拒绝记录，保持零偏移
	RecordMasterClockOffset(local.Add(48*time.Hour).Unix(), local)
	if got := masterAdjustedNow(local); !got.Equal(local) {
		t.Fatalf("absurd offset should be rejected, adjusted=%v", got)
	}
	// 非法头值（<=0）：忽略
	RecordMasterClockOffset(0, local)
	RecordMasterClockOffset(-1, local)
	if masterClockOffsetAtUnix.Load() != 0 {
		t.Fatalf("invalid header values should be ignored")
	}
}

func TestRecordMasterClockOffset_measurementWithinClampAccepted(t *testing.T) {
	resetMasterClockOffsetForTest(t)
	local := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	offset := 5 * time.Hour
	RecordMasterClockOffset(local.Add(offset).Unix(), local)
	if got := masterAdjustedNow(local); !got.Equal(local.Add(offset)) {
		t.Fatalf("offset within clamp should be applied, adjusted=%v", got)
	}
}
