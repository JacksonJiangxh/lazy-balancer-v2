package services

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/wafiplist"
)

// 代际判据的真实原因（读侧注释修正的行为钉）：写相位先 replace .fast、后
// replace 文本；rename 不改 mtime，故稳态 .fast 的 mtime 不早于文本，
// readThreatIplistPath 走 .fast 分支。禁止把 rename 顺序改回「先文本后
// fast」——陈旧文本会遮蔽新 fast（新威胁漏拦/已移除误拦）。
func TestWriteThreatIplistCompiled_fastGenerationIsNotOlderThanText(t *testing.T) {
	path := filepath.Join(t.TempDir(), "threat-ustc.iplist")
	if err := writeThreatIplistCompiled(path, []string{"203.0.113.1", "198.51.100.0/24"}); err != nil {
		t.Fatal(err)
	}
	textInfo, err := os.Stat(path)
	if err != nil {
		t.Fatalf("读取文本代际: %v", err)
	}
	fastInfo, err := os.Stat(wafiplist.FastPath(path))
	if err != nil {
		t.Fatalf("读取 .fast 代际: %v", err)
	}
	if fastInfo.ModTime().Before(textInfo.ModTime()) {
		t.Fatalf("稳态 .fast mtime 早于文本（写相位 rename 顺序被改？）: fast=%v text=%v",
			fastInfo.ModTime(), textInfo.ModTime())
	}
	vals, err := readThreatIplistPath(path)
	if err != nil {
		t.Fatalf("按代际读取失败: %v", err)
	}
	if len(vals) != 2 {
		t.Fatalf("按代际应读到 2 条: %v", vals)
	}
}
