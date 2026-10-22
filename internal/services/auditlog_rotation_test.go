package services

import (
	"os"
	"path/filepath"
	"testing"
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
