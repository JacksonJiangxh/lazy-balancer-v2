package services

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 审计日志目录必须在首次 ApplyConfigOnStartup 前
// 保证存在——coraza v3.7.0 NewWAF→serialWriter.Init OpenFile 不建父目录,目录
// 缺失=Provision 致命=/load 拒收。导出 helper 供 main.go 启动早期调用。
func TestEnsureWafAuditDir_createsDirectory(t *testing.T) {
	// Given: 不存在的嵌套目录
	dir := filepath.Join(t.TempDir(), "logs", "waf-audit")
	oldPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldPath })

	// When
	if err := EnsureWafAuditDir(); err != nil {
		t.Fatalf("EnsureWafAuditDir: %v", err)
	}

	// Then: 目录已创建
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		t.Fatalf("dir %s not created: %v", dir, err)
	}
	// 幂等:重复调用不报错
	if err := EnsureWafAuditDir(); err != nil {
		t.Fatalf("EnsureWafAuditDir second call: %v", err)
	}
}

// 待补采标记损坏必须与「标记读错误」同口径中止本轮。
// 旧实现清除损坏标记后返回 (nil,nil)——恰好等于「无标记」，调用方继续
// .1→.2 移位，该轮转窗口的事件再无补采依据（上轮补采失败 + 标记损坏的双故障
// 下安全事件永久丢失），与同函数注释「避免被静默当作无标记后继续轮转」相反。
func TestRotateAuditLog_corruptPendingMarkerDefersRotation(t *testing.T) {
	// Given：活文件已过阈值、存在 .1 归档、待补采标记损坏（半写 JSON）
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldSizeBytes := auditLogPath, auditLogSizeBytes
	auditLogPath = logPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() { auditLogPath, auditLogSizeBytes = oldLogPath, oldSizeBytes })
	if err := os.WriteFile(logPath, []byte("live-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("pending-archive"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := securityEventsPendingDeltaPath()
	if err := os.WriteFile(marker, []byte(`{"path": "broken`), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	_, err := rotateAuditLogIfNeeded()

	// Then：本轮中止并返回错误（下轮重试），不得当作无标记继续轮转
	if err == nil {
		t.Fatal("标记损坏必须让轮转中止并返回错误（旧实现清除后返回 nil,nil）")
	}
	for path, want := range map[string]string{
		logPath:        "live-content",
		logPath + ".1": "pending-archive",
	} {
		got, rerr := os.ReadFile(path)
		if rerr != nil {
			t.Fatalf("read preserved file %s: %v", path, rerr)
		}
		if string(got) != want {
			t.Fatalf("%s=%q, want %q（补采责任未知时不得移位/覆盖归档）", path, got, want)
		}
	}
	if _, serr := os.Stat(logPath + ".2"); !os.IsNotExist(serr) {
		t.Fatalf(".1 不得移入 .2，stat err=%v", serr)
	}
	// 标记保留在盘上：人工可诊断/恢复，下一轮仍按失败中止（不静默丢补采责任）
	if _, serr := os.Stat(marker); serr != nil {
		t.Fatalf("损坏标记必须保留（不得静默清除）: %v", serr)
	}
}

// 轮转必须先复制到暂存名 .1.new、成功后才移位归档：持续复制失败（磁盘满/
// 只读挂载/IO 错误）不得改变归档代际。旧序先 .4→.5 … .1→.2 再复制，每 2s
// tick 蚕食一代——.1..5 全存在时约 4 个 tick 即丢掉 4 代审计证据。
func TestRotateAuditLog_copyFailureKeepsArchiveGenerations(t *testing.T) {
	// Given：活文件超阈 + 5 代归档全部存在
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldSizeBytes, oldCopy := auditLogPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath = logPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() { auditLogPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldSizeBytes, oldCopy })
	if err := os.WriteFile(logPath, []byte("live-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 5; i++ {
		if err := os.WriteFile(fmt.Sprintf("%s.%d", logPath, i), []byte(fmt.Sprintf("gen-%d", i)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	auditLogCopyFile = func(string, string) error { return errors.New("injected copy failure") }

	// When：连续 5 个 tick 都复制失败
	for tick := 1; tick <= 5; tick++ {
		if _, err := rotateAuditLogIfNeeded(); err == nil {
			t.Fatalf("第 %d 个 tick：copy 失败必须返回错误", tick)
		}
	}

	// Then：归档代际与内容原样保留，活文件未截断，暂存不留残
	for i := 1; i <= 5; i++ {
		got, err := os.ReadFile(fmt.Sprintf("%s.%d", logPath, i))
		if err != nil {
			t.Fatalf("复制失败后归档 .%d 丢失: %v", i, err)
		}
		if want := fmt.Sprintf("gen-%d", i); string(got) != want {
			t.Fatalf(".%d=%q, want %q（复制失败不得移位/覆盖归档）", i, got, want)
		}
	}
	if _, err := os.Stat(logPath + ".6"); !os.IsNotExist(err) {
		t.Fatalf(".5 不得移位为 .6, stat err=%v", err)
	}
	if _, err := os.Stat(logPath + ".1.new"); !os.IsNotExist(err) {
		t.Fatalf("暂存文件必须清理, stat err=%v", err)
	}
	if got, err := os.ReadFile(logPath); err != nil || string(got) != "live-content" {
		t.Fatalf("活文件被改动: %q err=%v", got, err)
	}
}

// 成功路径：当前日志先落暂存，随后归档移位、暂存提升为 .1——新 .1 是新归档，
// 旧 .1 让位到 .2，暂存不留残。
func TestRotateAuditLog_promotesStagedArchiveAfterShift(t *testing.T) {
	// Given：活文件超阈、既有 .1 一代
	oldDB, oldMetrics, oldAudit := db.DB, db.MetricsDB, db.AuditDB
	db.DB, db.MetricsDB, db.AuditDB = nil, nil, nil
	t.Cleanup(func() { db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetrics, oldAudit })
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, filepath.Join(dir, "security_events.offset")
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopy
	})
	if err := os.WriteFile(logPath, []byte("new-archive-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("gen-1"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When
	if _, err := rotateAuditLogIfNeeded(); err != nil {
		t.Fatalf("正常轮转不应报错: %v", err)
	}

	// Then
	if got, err := os.ReadFile(logPath + ".1"); err != nil || string(got) != "new-archive-content" {
		t.Fatalf(".1 必须是本轮新归档: %q err=%v", got, err)
	}
	if got, err := os.ReadFile(logPath + ".2"); err != nil || string(got) != "gen-1" {
		t.Fatalf("旧 .1 必须让位到 .2: %q err=%v", got, err)
	}
	if _, err := os.Stat(logPath + ".1.new"); !os.IsNotExist(err) {
		t.Fatalf("暂存文件必须已被提升（不得留残）, stat err=%v", err)
	}
	if info, err := os.Stat(logPath); err != nil || info.Size() != 0 {
		t.Fatalf("活文件必须已截断: size=%v err=%v", info, err)
	}
}

// 归档代检查的 stat 只允许把 NotExist 视为「该代不存在」：权限/IO 错误下
// 归档可能仍存在，继续 shift/promote 会覆盖仍有效的 .1（丢一代审计证据）。
// 用自指符号链接注入 ELOOP（stat 失败但不是缺失）。
func TestRotateAuditLog_statErrorAbortsBeforeOverwritingArchives(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldSizeBytes := auditLogPath, auditLogSizeBytes
	auditLogPath = logPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() { auditLogPath, auditLogSizeBytes = oldLogPath, oldSizeBytes })
	resetPendingDeltaCorruptStreakForTest()
	if err := os.WriteFile(logPath, []byte("live-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("archive-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	// 自指符号链接：os.Stat 返回 ELOOP（非 NotExist）。
	if err := os.Symlink(logPath+".3", logPath+".3"); err != nil {
		t.Fatal(err)
	}

	_, err := rotateAuditLogIfNeeded()
	if err == nil {
		t.Fatal("stat 非 NotExist 错误必须中止本轮并返回错误")
	}
	got, rerr := os.ReadFile(logPath + ".1")
	if rerr != nil || string(got) != "archive-one" {
		t.Fatalf(".1=%q err=%v，stat 异常时不得覆盖仍在的归档", got, rerr)
	}
	if _, serr := os.Stat(logPath + ".1.new"); !os.IsNotExist(serr) {
		t.Fatalf("中止必须清理暂存归档 .1.new，stat err=%v", serr)
	}
}

// .1 未能让位时中止：.2 为非空目录使 .1→.2 的 rename 失败（上级链 .2/.3/.4/.5
// 同样被占住，逐级 shift 全部失败），本轮必须中止且保留 .1 与 .2 现场。
func TestRotateAuditLog_shiftFailureForFirstGenerationAbortsAndKeepsArchives(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldSizeBytes := auditLogPath, auditLogSizeBytes
	auditLogPath = logPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() { auditLogPath, auditLogSizeBytes = oldLogPath, oldSizeBytes })
	resetPendingDeltaCorruptStreakForTest()
	if err := os.WriteFile(logPath, []byte("live-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath+".1", []byte("archive-one"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, gen := range []string{".2", ".3", ".4", ".5"} {
		p := logPath + gen
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, "keep"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	_, err := rotateAuditLogIfNeeded()
	if err == nil {
		t.Fatal(".1 未能让位必须中止本轮并返回错误")
	}
	got, rerr := os.ReadFile(logPath + ".1")
	if rerr != nil || string(got) != "archive-one" {
		t.Fatalf(".1=%q err=%v，中止后必须保留上一代归档", got, rerr)
	}
	if st, serr := os.Stat(logPath + ".2"); serr != nil || !st.IsDir() {
		t.Fatalf(".2 现场必须保留, stat=%v err=%v", st, serr)
	}
	if _, serr := os.Stat(logPath + ".1.new"); !os.IsNotExist(serr) {
		t.Fatalf("中止必须清理暂存归档 .1.new，stat err=%v", serr)
	}
}

// 损坏的待补采标记在连续 N 轮不可解析后隔离为 .corrupt-<ts> 并继续轮转——
// 单轮仍 fail-closed 保留现场，否则 audit.log 永久不轮转（无界增长）。
func TestRotateAuditLog_corruptPendingMarkerQuarantinedAfterThreshold(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	oldLogPath, oldSizeBytes := auditLogPath, auditLogSizeBytes
	auditLogPath = logPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() { auditLogPath, auditLogSizeBytes = oldLogPath, oldSizeBytes })
	resetPendingDeltaCorruptStreakForTest()
	t.Cleanup(resetPendingDeltaCorruptStreakForTest)

	if err := os.WriteFile(logPath, []byte("live-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	marker := securityEventsPendingDeltaPath()
	if err := os.WriteFile(marker, []byte(`{"path": "broken`), 0o644); err != nil {
		t.Fatal(err)
	}

	for round := 1; round < pendingDeltaCorruptQuarantineRounds; round++ {
		if _, err := rotateAuditLogIfNeeded(); err == nil {
			t.Fatalf("第 %d 轮损坏标记必须 fail-closed 中止", round)
		}
		if _, err := os.Stat(marker); err != nil {
			t.Fatalf("第 %d 轮不得提前隔离标记: %v", round, err)
		}
	}
	// 第 N 轮：标记被隔离，轮转继续推进（后续偏移写入可能因测试环境目录
	// 只读失败——隔离动作本身必须已发生，归档必须已生成）。
	_, err := rotateAuditLogIfNeeded()
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatalf("连续 %d 轮损坏后标记必须已隔离, stat err=%v (rotate err=%v)", pendingDeltaCorruptQuarantineRounds, serr, err)
	}
	quarantined, _ := filepath.Glob(marker + ".corrupt-*")
	if len(quarantined) != 1 {
		t.Fatalf("隔离文件=%v, want 恰一个 .corrupt-<ts>", quarantined)
	}
	if _, serr := os.Stat(logPath + ".1"); serr != nil {
		t.Fatalf("隔离后轮转必须继续（.1 归档应存在）: %v (rotate err=%v)", serr, err)
	}
}
