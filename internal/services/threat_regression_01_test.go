package services

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/wafiplist"
)

// 损坏 .fast 必须①在「未装载」判定中计为未装载（强制重编译/修复），②在文本
// 在场时从文本自愈重建，③读取侧回退文本而不是让引用策略静默缺席。

// writeCorruptFastFixture 写一份 magic 合法但计数与尺寸不自洽的 .fast
// （损坏形状：truncation/写中断）。
func writeCorruptFastFixture(t *testing.T, path string) {
	t.Helper()
	data := make([]byte, 16)
	copy(data[0:4], "LBF1")
	data[7] = 100 // v4_count=100，但无条目数据 → expectedSize 不自洽
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

// 目标/回归形状：损坏 .fast 计为未装载；WriteFastFile 产物计为已装载。
func TestThreatListEmpty_corruptFastCountsAsUnloaded(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)

	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := os.WriteFile(iplistPath, []byte("192.0.2.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// 损坏形状：文件存在（stat 通过）但内容不自洽。
	writeCorruptFastFixture(t, iplistPath+".fast")
	if !threatListEmpty("ustc") {
		t.Fatal(".fast 存在但损坏时必须视为未装载（否则哈希快路径永久跳过修复）")
	}

	// 回归形状：合法 .fast 视为已装载。
	if err := wafiplist.WriteFastFile(iplistPath+".fast", mustParsePrefixes(t, "192.0.2.0/24"), nil); err != nil {
		t.Fatal(err)
	}
	if threatListEmpty("ustc") {
		t.Fatal("合法 .fast 不得误判为未装载")
	}
}

// 行为形状：文本在场 + .fast 损坏 + 下载失败——必须从文本自愈重建 .fast 并
// 标记成功（旧实现 heal 只认「缺失」，损坏形态走下载，下载失败即整源失败，
// 引用策略持续被渲染层跳过）。
func TestThreatUpdate_healsCorruptFastFromText(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, map[string]bool{"ustc": true}, nil) // ustc 下载恒失败

	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	if err := os.WriteFile(iplistPath, []byte("203.0.113.1\n10.9.0.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	writeCorruptFastFixture(t, iplistPath+".fast")

	if err := GetThreatUpdateManager().RunUpdate("manual", nil); err != nil {
		t.Fatalf("文本在场时 .fast 损坏必须自愈（不依赖下载）: %v", err)
	}
	status, _, _, _, _ := readThreatRow(t, "ustc")
	if status != "success" {
		t.Fatalf("ustc 行状态=%s, want success（文本自愈路径）", status)
	}
	state, err := wafiplist.ReadFastFile(iplistPath + ".fast")
	if err != nil {
		t.Fatalf("自愈后 .fast 必须可读: %v", err)
	}
	if len(state.V4) != 2 {
		t.Fatalf("自愈后 .fast 条目数=%d, want 2", len(state.V4))
	}
}

// 写侧形状：内容哈希命中但 .fast 损坏时不得跳过写盘（旧实现 stat 存在即跳过，
// 损坏文件永久驻留）。
func TestWriteThreatSystemList_corruptFastForcesRewrite(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	// 首轮正常写入（建立 content_hash 与完好文件）。
	if _, err := writeThreatSystemList("ustc", []string{"203.0.113.1/32", "10.9.0.0/24"}); err != nil {
		t.Fatalf("首轮写入: %v", err)
	}
	// 带外损坏 .fast（文本完好、内容哈希不变）。
	writeCorruptFastFixture(t, iplistPath+".fast")

	if _, err := writeThreatSystemList("ustc", []string{"203.0.113.1/32", "10.9.0.0/24"}); err != nil {
		t.Fatalf("二次写入: %v", err)
	}
	if _, err := wafiplist.ReadFastFile(iplistPath + ".fast"); err != nil {
		t.Fatalf("哈希命中但 .fast 损坏时必须重写（当前残留损坏文件）: %v", err)
	}
}

// 读取侧形状：.fast 较新但损坏时回退文本并告警；无文本才报错。
func TestReadThreatIplistPath_corruptFastFallsBackToText(t *testing.T) {
	dir := t.TempDir()
	iplistPath := filepath.Join(dir, "threat-x.iplist")
	fastPath := iplistPath + ".fast"

	// 文本与 .fast 内容故意不同，区分回退来源。
	if err := os.WriteFile(iplistPath, []byte("198.51.100.0/24\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := wafiplist.WriteFastFile(fastPath, mustParsePrefixes(t, "203.0.113.0/24"), nil); err != nil {
		t.Fatal(err)
	}
	// 回归形状：合法且较新的 .fast 以 fast 为准。
	newer := time.Now()
	if err := os.Chtimes(fastPath, newer, newer); err != nil {
		t.Fatal(err)
	}
	vals, err := readThreatIplistPath(iplistPath)
	if err != nil || len(vals) != 1 || vals[0] != "203.0.113.0/24" {
		t.Fatalf("合法较新 .fast 必须以 fast 为准, got %v, err=%v", vals, err)
	}

	// 目标形状：损坏的较新 .fast → 回退文本。
	writeCorruptFastFixture(t, fastPath)
	if err := os.Chtimes(fastPath, newer, newer); err != nil {
		t.Fatal(err)
	}
	vals, err = readThreatIplistPath(iplistPath)
	if err != nil || len(vals) != 1 || vals[0] != "198.51.100.0/24" {
		t.Fatalf("损坏 .fast 必须回退文本, got %v, err=%v", vals, err)
	}

	// 畸形形状：损坏 .fast 且无文本 → 显式错误（调用方按装载失败处理）。
	if err := os.Remove(iplistPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readThreatIplistPath(iplistPath); err == nil {
		t.Fatal("损坏 .fast 且文本缺失时必须报错")
	}
}

func mustParsePrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}
