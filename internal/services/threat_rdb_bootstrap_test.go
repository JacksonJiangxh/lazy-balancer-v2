package services

// RDB 文件化升级引导窗口（v2.3.4）：v2.3.3 → v2.3.4 升级后，DB 侧名单非空
// 且 content_hash 命中（源内容未变）——但 .iplist 文件不存在。若不处理：
// 哈希跳过写文件 + 排程门控不到期 → 文件永不落地 → 严格渲染模式持续跳过
// 引用威胁库的策略（静默保护缺口）。
// 修复语义（沿 v2.3.2「名单为空视为到期」先例）：
// ①到期判定：.iplist 文件缺失的源视为到期（仅限从未失败形态）；
// ②哈希跳过：文件缺失时哈希命中不再跳过——照常写 .iplist + 编译 .fast。

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given：源行 content_hash 命中（内容未变）+ next_update 在未来 + .iplist 文件缺失。
// When：threatDueSources(auto)。
// Then：该源仍被纳入（升级窗口不被排程门控饿死）。
func TestThreatRDBBootstrap_fileMissingSourceIsDue(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)

	// 模拟 v2.3.3 形态：名单行有内容 + content_hash 已登记 + next_update 在未来
	name := db.ThreatListNameBySource("ustc")
	if name == "" {
		t.Fatal("ustc 名单名缺失")
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries='[{"value":"192.0.2.1"}]' WHERE name=?`, name); err != nil {
		t.Fatal(err)
	}
	future := time.Now().UTC().Add(6 * time.Hour).Format(crsTimeLayout)
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET content_hash='stale-hash', next_update=? WHERE name='ustc'`, future); err != nil {
		t.Fatal(err)
	}

	due, err := threatDueSources("auto")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range due {
		if s.name == "ustc" {
			found = true
		}
	}
	if !found {
		t.Fatal("升级窗口：.iplist 缺失的源必须视为到期（否则文件永不落地、策略持续被跳过）")
	}
}

// Given：文件缺失但 DB 哈希命中（内容未变）。
// When：真跑一轮更新（manual 全量）。
// Then：.iplist + .fast 照常落盘（哈希跳过被文件缺失旁路）。
func TestThreatRDBBootstrap_hashHitStillWritesFiles(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	bodies := map[string][]string{"ustc": {"192.0.2.0/24", "198.51.100.7"}}
	setupThreatTest(t, bodies, nil, nil)

	// 第一轮：正常写文件
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatal(err)
	}
	var storedHash string
	if err := db.DB.QueryRow(`SELECT COALESCE(content_hash,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&storedHash); err != nil || storedHash == "" {
		t.Fatalf("hash=%q err=%v", storedHash, err)
	}

	// 模拟升级形态：删除文件，哈希保持命中
	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	os.Remove(iplistPath)
	os.Remove(iplistPath + ".fast")

	// 第二轮：内容未变（哈希命中）但文件缺失 → 必须重写文件
	if err := GetThreatUpdateManager().RunUpdate("manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(iplistPath); err != nil {
		t.Fatalf("哈希命中但文件缺失时必须重写 .iplist: %v", err)
	}
	if _, err := os.Stat(iplistPath + ".fast"); err != nil {
		t.Fatalf("哈希命中但文件缺失时必须重编译 .fast: %v", err)
	}
}
