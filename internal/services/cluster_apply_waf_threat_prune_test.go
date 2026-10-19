package services

// 历史修复 收口（SecurityEngine 域移交）：从端安全数据同步必须删除主端已移除的
// 威胁源本地残留文件——否则 wafFilesRefDiffers/wafFilesDrifted 恒判漂移，
// 每轮全量重拉却永不删除（历史问题 同条目的半项）。

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

// Given 主节点 ref 只声明 ustc 威胁源；从端残留 firehol_l1 的 .fast+.iplist。
// When applySnapshot 拉取并应用安全数据（漂移→全量重拉路径）。
// Then 残留对必须被删除、主节点的 ustc .fast 落盘——下轮漂移判定收敛。
func TestSyncService_applySnapshot_prunesStaleThreatFastFiles(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec("UPDATE global_config SET is_master=0 WHERE id=1"); err != nil {
		t.Fatalf("set slave mode: %v", err)
	}

	// 主节点文件树：CRS + 单个威胁源 ustc。
	masterTree := t.TempDir()
	masterWaf := filepath.Join(masterTree, "waf")
	if err := os.MkdirAll(filepath.Join(masterTree, "crs", "rules"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(masterWaf, 0755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(masterTree, "crs", "rules", "a.conf"), []byte("SecRule X 1"), 0644)
	os.WriteFile(filepath.Join(masterTree, "crs", "VERSION"), []byte("v4.28.0"), 0644)
	os.WriteFile(filepath.Join(masterWaf, "threat-ustc.iplist.fast"), []byte("MASTER-FAST"), 0644)

	restorePaths := OverrideWafLivePathsForTest(filepath.Join(masterTree, "crs"), filepath.Join(masterTree, "ip2region.xdb"))
	restoreMasterWaf := OverrideThreatWafDirForTest(masterWaf)
	bundle := BuildWafFileBundle()
	ref := BuildWafFileRef()
	restoreMasterWaf()
	restorePaths()
	if bundle == nil || ref == nil || ref.CRSSha256 == "" || len(ref.ThreatSha256s) != 1 {
		t.Fatalf("master bundle/ref build failed: bundle=%+v ref=%+v", bundle, ref)
	}

	// 从节点：空 CRS + 残留威胁源文件（主端已删除的源）。
	slaveTree := t.TempDir()
	slaveWaf := filepath.Join(slaveTree, "waf")
	if err := os.MkdirAll(slaveWaf, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slaveWaf, "threat-firehol_l1.iplist.fast"), []byte("STALE-FAST"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(slaveWaf, "threat-firehol_l1.iplist"), []byte("STALE-TEXT"), 0644); err != nil {
		t.Fatal(err)
	}
	restoreSlavePaths := OverrideWafLivePathsForTest(filepath.Join(slaveTree, "crs"), filepath.Join(slaveTree, "ip2region.xdb"))
	defer restoreSlavePaths()
	restoreSlaveWaf := OverrideThreatWafDirForTest(slaveWaf)
	defer restoreSlaveWaf()

	masterServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/cluster/sync/waf-files" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"data": bundle})
	}))
	defer masterServer.Close()
	if _, err := database.Exec("UPDATE global_config SET master_url=?, cluster_token=? WHERE id=1", masterServer.URL, "probe-token"); err != nil {
		t.Fatalf("seed master endpoint: %v", err)
	}
	caddyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version:       11,
		Users:         []models.ClusterUser{{ID: 7, Username: "waf-prune-admin", PasswordHash: "hash", Role: "admin", IsEnabled: true}},
		BasicSettings: models.ClusterBasicSettings{LogLevel: new("info"), Timezone: new("Asia/Shanghai")},
		WafFiles:      ref,
	})

	// When
	done := make(chan error, 1)
	go func() { done <- syncService.applySnapshot(context.Background(), snapshot) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("applySnapshot: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("applySnapshot 超时")
	}

	// Then：主端已删除源的本地残留对必须删除
	for _, name := range []string{"threat-firehol_l1.iplist.fast", "threat-firehol_l1.iplist"} {
		if _, err := os.Stat(filepath.Join(slaveWaf, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s 仍残留（err=%v）——主端已删除的威胁源未收敛，漂移判定永不收敛", name, err)
		}
	}
	// And：主端声明源照常落盘
	content, err := os.ReadFile(filepath.Join(slaveWaf, "threat-ustc.iplist.fast"))
	if err != nil || string(content) != "MASTER-FAST" {
		t.Fatalf("ustc .fast 落盘=%q err=%v, want MASTER-FAST", string(content), err)
	}
}

// Given 本地存在威胁库文件。
// When ApplyWafFileBundle 收到不含威胁条目的 bundle（lbbak 导入路径形态——
// 威胁 .iplist 由调用方自行编译落盘，不经 bundle.ThreatFiles）。
// Then 本地威胁文件不得被删除（收敛职责只在集群同步的 prune 步骤）。
func TestApplyWafFileBundle_doesNotPruneThreatFiles(t *testing.T) {
	waf := t.TempDir()
	defer OverrideThreatWafDirForTest(waf)()
	local := filepath.Join(waf, "threat-ustc.iplist.fast")
	if err := os.WriteFile(local, []byte("LOCAL-FAST"), 0644); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := ApplyWafFileBundle(&WafFileBundle{}); err != nil {
		t.Fatalf("apply empty bundle: %v", err)
	}
	if content, err := os.ReadFile(local); err != nil || string(content) != "LOCAL-FAST" {
		t.Fatalf("本地威胁文件被删除/改写: %q err=%v（lbbak 路径依赖保留）", string(content), err)
	}
}

// Given 白名单内外的本地威胁文件与主端引用集合。
// When pruneSyncedThreatFiles。
// Then 只删「白名单内且不在引用集合」的 .fast/.iplist 对；白名单外文件、
// 被引用源、nil ref 均不动。
func TestPruneSyncedThreatFiles_whitelistAndKeepSet(t *testing.T) {
	waf := t.TempDir()
	defer OverrideThreatWafDirForTest(waf)()
	files := []string{
		"threat-ustc.iplist.fast",         // 被引用 → 保留
		"threat-firehol_l1.iplist.fast",   // 未引用 → 删除
		"threat-firehol_l1.iplist",        // 伴生文本 → 删除
		"threat-not_a_source.iplist.fast", // 白名单外 → 不动（同步不管辖）
		"other.txt",                       // 无关文件 → 不动
	}
	for _, name := range files {
		if err := os.WriteFile(filepath.Join(waf, name), []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	ref := &models.ClusterWafFilesRef{ThreatSha256s: map[string]string{"ustc": "abc"}}

	// When
	pruned, err := pruneSyncedThreatFiles(ref)

	// Then
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if len(pruned) != 1 || pruned[0] != "firehol_l1" {
		t.Fatalf("pruned=%v, want [firehol_l1]", pruned)
	}
	for _, name := range []string{"threat-firehol_l1.iplist.fast", "threat-firehol_l1.iplist"} {
		if _, statErr := os.Stat(filepath.Join(waf, name)); !errors.Is(statErr, os.ErrNotExist) {
			t.Fatalf("%s 未删除", name)
		}
	}
	for _, name := range []string{"threat-ustc.iplist.fast", "threat-not_a_source.iplist.fast", "other.txt"} {
		if _, statErr := os.Stat(filepath.Join(waf, name)); statErr != nil {
			t.Fatalf("%s 被误删: %v", name, statErr)
		}
	}

	// nil ref（主端无 WAF 组件）：不动任何文件
	if pruned, err := pruneSyncedThreatFiles(nil); err != nil || len(pruned) != 0 {
		t.Fatalf("nil ref prune=(%v,%v), want (nil,nil)", pruned, err)
	}
	// 非 nil ref 但威胁集合为空（主端只有 CRS）：白名单内文件全部收敛删除
	if err := os.WriteFile(filepath.Join(waf, "threat-et_compromised.iplist.fast"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	pruned, err = pruneSyncedThreatFiles(&models.ClusterWafFilesRef{CRSSha256: "crs"})
	if err != nil {
		t.Fatalf("empty threat ref prune: %v", err)
	}
	if len(pruned) != 2 || pruned[0] != "et_compromised" || pruned[1] != "ustc" {
		t.Fatalf("pruned=%v, want [et_compromised ustc]", pruned)
	}
	if _, statErr := os.Stat(filepath.Join(waf, "threat-not_a_source.iplist.fast")); statErr != nil {
		t.Fatalf("白名单外文件被误删: %v", statErr)
	}
}
