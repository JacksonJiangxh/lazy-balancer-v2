package services

import (
	"errors"
	"strings"
	"testing"
)

func resetBackgroundApplyFailures(t *testing.T) {
	t.Helper()
	clearAll := func() {
		backgroundApplyStore.mu.Lock()
		backgroundApplyStore.failures = map[string]BackgroundApplyFailure{}
		backgroundApplyStore.mu.Unlock()
	}
	clearAll()
	t.Cleanup(clearAll)
}

func setBackgroundApplyFailure(source string, failure BackgroundApplyFailure) {
	backgroundApplyStore.mu.Lock()
	defer backgroundApplyStore.mu.Unlock()
	backgroundApplyStore.failures[source] = failure
}

// TrackBackgroundReload：失败登记并按原样返回错误；成功只清该来源（一个来源
// 成功不得掩盖另一来源仍在失败）；nil 回调保持 nil。
func TestTrackBackgroundReload_recordsAndClearsPerSource(t *testing.T) {
	resetBackgroundApplyFailures(t)
	if wrapped := TrackBackgroundReload(BackgroundApplyCRS, nil); wrapped != nil {
		t.Fatal("nil 回调必须返回 nil")
	}

	boom := errors.New("crs update failed")
	wrapped := TrackBackgroundReload(BackgroundApplyCRS, func() error { return boom })
	if err := wrapped(); !errors.Is(err, boom) {
		t.Fatalf("包装回调改变了错误语义: %v", err)
	}
	failure := BackgroundApplyFailureSnapshot()
	if failure == nil || failure.Source != string(BackgroundApplyCRS) || failure.Message != "crs update failed" || failure.At == "" {
		t.Fatalf("失败未登记: %+v", failure)
	}

	TrackBackgroundReload(BackgroundApplyIP2Region, func() error { return errors.New("ip2region update failed") })()
	// CRS 成功只清 CRS：IP2Region 的失败必须保留。
	TrackBackgroundReload(BackgroundApplyCRS, func() error { return nil })()
	failure = BackgroundApplyFailureSnapshot()
	if failure == nil || failure.Source != string(BackgroundApplyIP2Region) {
		t.Fatalf("互相掩盖：CRS 成功清掉了其他来源的失败: %+v", failure)
	}

	ClearBackgroundApplyFailure(BackgroundApplyIP2Region)
	if failure := BackgroundApplyFailureSnapshot(); failure != nil {
		t.Fatalf("ClearBackgroundApplyFailure 未清空: %+v", failure)
	}
	if banner := BackgroundApplyFailureBanner(); banner != "" {
		t.Fatalf("无失败时横幅必须为空串, got %q", banner)
	}
}

// 横幅选源稳定：多来源并存取最近时间；同秒按来源名字典序取最小（map 遍历
// 顺序随机，缺 tie-break 每次调用换源 → 前端轮询抖动）。
func TestBackgroundApplyFailureSnapshot_stableSelection(t *testing.T) {
	resetBackgroundApplyFailures(t)
	setBackgroundApplyFailure(string(BackgroundApplyThreat), BackgroundApplyFailure{
		Source: string(BackgroundApplyThreat), Message: "threat 旧", At: "2026-01-01 00:00:10",
	})
	setBackgroundApplyFailure(string(BackgroundApplyCRS), BackgroundApplyFailure{
		Source: string(BackgroundApplyCRS), Message: "crs 新", At: "2026-01-01 00:00:20",
	})
	if failure := BackgroundApplyFailureSnapshot(); failure == nil || failure.Source != string(BackgroundApplyCRS) {
		t.Fatalf("时间较新的失败未被选中: %+v", failure)
	}

	// 同秒两来源：字典序最小的来源必须恒被选中。
	resetBackgroundApplyFailures(t)
	setBackgroundApplyFailure("ZZZ", BackgroundApplyFailure{Source: "ZZZ", Message: "zzz", At: "2026-01-01 00:00:30"})
	setBackgroundApplyFailure("AAA", BackgroundApplyFailure{Source: "AAA", Message: "aaa", At: "2026-01-01 00:00:30"})
	for attempt := range 50 {
		failure := BackgroundApplyFailureSnapshot()
		if failure == nil || failure.Source != "AAA" {
			t.Fatalf("第 %d 次快照选源=%+v, want AAA（同秒字典序最小）", attempt+1, failure)
		}
	}

	banner := BackgroundApplyFailureBanner()
	if !strings.Contains(banner, "AAA") || !strings.Contains(banner, "2026-01-01 00:00:30") || !strings.Contains(banner, "aaa") {
		t.Fatalf("横幅文案缺来源/时间/消息: %q", banner)
	}
}
