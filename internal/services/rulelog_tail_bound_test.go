package services

// U8-P3-1（Round 62 审计）：ReadRuleLogTail 反向扫描必须受 maxBackwardScan
// 约束。maxBackwardScan 常量曾声明但扫描循环从不引用（F63-B5e2-2 修复未接线），
// 无换行的损坏/二进制日志会一路回扫到文件头（每轮 64KiB 前置拷贝，
// 100MB 无换行 ≈ 数十 GB 级复制）。本文件钉两形状：
//   - 无换行大文件：返回非空部分 tail、长度受扫描上限约束、offset 不变量保持
//   - 正常多行文件：tail 语义（最后 N 行 + 起始 offset）不变

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeRuleLogFile(t *testing.T, ruleID string, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	origDir := ruleLogDir
	ruleLogDir = dir
	t.Cleanup(func() { ruleLogDir = origDir })
	path := filepath.Join(dir, sanitizeRuleLogName(ruleID)+".log")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("write rule log %s: %v", path, err)
	}
	return path
}

func TestReadRuleLogTail_noNewlineFileBounded(t *testing.T) {
	// 8MB 无换行：旧实现全量回扫（buf 达 8MB），新实现须停在 maxBackwardScan。
	size := 8 << 20
	writeRuleLogFile(t, "probe", bytes.Repeat([]byte{0x41}, size))

	content, offset := ReadRuleLogTail("probe", 100)

	if content == "" {
		t.Fatal("tail of newline-free log returned empty content, want bounded partial tail")
	}
	if int64(len(content)) > maxBackwardScan+64*1024 {
		t.Fatalf("tail length %d exceeds maxBackwardScan bound %d", len(content), maxBackwardScan+64*1024)
	}
	if offset+int64(len(content)) != int64(size) {
		t.Fatalf("offset invariant broken: offset=%d len=%d size=%d, want offset+len==size", offset, len(content), size)
	}
}

func TestReadRuleLogTail_multilineTailSemanticsUnchanged(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 3000; i++ {
		b.WriteString(fmt.Sprintf("line-%d\n", i))
	}
	writeRuleLogFile(t, "multi", []byte(b.String()))

	content, offset := ReadRuleLogTail("multi", 100)

	lines := strings.Split(strings.TrimSuffix(content, "\n"), "\n")
	if len(lines) != 100 {
		t.Fatalf("got %d lines, want last maxLines=100", len(lines))
	}
	if lines[0] != "line-2901" || lines[99] != "line-3000" {
		t.Fatalf("tail window wrong: first=%s last=%s, want line-2901..line-3000", lines[0], lines[99])
	}
	if offset+int64(len(content)) != int64(b.Len()) {
		t.Fatalf("offset invariant broken: offset=%d len=%d total=%d", offset, len(content), b.Len())
	}
}

// F-68-U7b2-01（第 68 轮审计）：removeTimberjackRotations 数字边界守卫——
// 兄弟规则（caddy_id 以本 stem 为前缀，lb_abc 与 lb_abc-extra）的轮转副本
// 此前被本规则的清扫按前缀+后缀整体误删（logstats.go B-2 同族先例：
// stem 后 '-<ts>' 段首字符必须为数字）。
func TestRemoveRuleLogFiles_siblingRuleRotationsUntouched(t *testing.T) {
	dir := t.TempDir()
	origDir := ruleLogDir
	ruleLogDir = dir
	t.Cleanup(func() { ruleLogDir = origDir })

	for _, name := range []string{
		"lb_abc.log", "lb_abc-extra.log",
		"lb_abc-20260910T15-04-05.123-size.log",
		"lb_abc-extra-20260910T15-04-05.123-size.log",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	RemoveRuleLogFiles("lb_abc")

	if _, err := os.Stat(filepath.Join(dir, "lb_abc.log")); !os.IsNotExist(err) {
		t.Fatal("lb_abc.log 应已删除")
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-20260910T15-04-05.123-size.log")); !os.IsNotExist(err) {
		t.Fatal("lb_abc 自身轮转副本应已清扫")
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-extra-20260910T15-04-05.123-size.log")); err != nil {
		t.Fatalf("兄弟规则轮转副本被误删: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "lb_abc-extra.log")); err != nil {
		t.Fatalf("兄弟规则活文件被误删: %v", err)
	}
}
