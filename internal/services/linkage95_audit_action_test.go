package services

// 零到期源成功轮的审计动作单源：威胁/爬虫两族同记动作「更新」+ detail
// 「无到期源」；「跳过」动作专留给降级中止（此前爬虫零到期轮借 skipped 充当
// 审计词，而威胁族同轮记「更新」）。

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func TestEmptySourceRoundAuditActionUnified(t *testing.T) {
	t.Run("threat", func(t *testing.T) {
		_, database := newClusterTestService(t)
		ResetThreatUpdateManagerForTest()
		t.Cleanup(ResetThreatUpdateManagerForTest)
		if _, err := database.Exec(`UPDATE security_threat_sources SET update_enabled=0`); err != nil {
			t.Fatalf("disable sources: %v", err)
		}

		if err := GetThreatUpdateManager().RunUpdate("auto", nil); err != nil {
			t.Fatalf("zero-due round must succeed: %v", err)
		}

		action, detail := lastAuditRow(t, "威胁情报库")
		if action != "更新" {
			t.Fatalf("零到期源轮审计动作=%q，want 更新（「跳过」专留降级中止）", action)
		}
		if !strings.Contains(detail, "无到期源") {
			t.Fatalf("零到期源轮 detail=%q，want 显式声明无到期源", detail)
		}
	})

	t.Run("crawler", func(t *testing.T) {
		_, database := newClusterTestService(t)
		oldFile := crawlerIPListFile
		crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
		t.Cleanup(func() { crawlerIPListFile = oldFile })
		// 先补齐内置源（ensureCrawlerSources 会按默认启用播种缺失源），
		// 再统一停用——否则零到期前提不成立。
		if err := ensureCrawlerSources(); err != nil {
			t.Fatalf("ensure crawler sources: %v", err)
		}
		if _, err := database.Exec(`UPDATE security_crawler_sources SET update_enabled=0`); err != nil {
			t.Fatalf("disable cores: %v", err)
		}

		if err := GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "auto"}); err != nil {
			t.Fatalf("zero-due round must succeed: %v", err)
		}

		action, detail := lastAuditRow(t, "爬虫地址库")
		if action != "更新" {
			t.Fatalf("零到期源轮审计动作=%q，want 更新（此前记「跳过」）", action)
		}
		if !strings.Contains(detail, "无到期源") {
			t.Fatalf("零到期源轮 detail=%q，want 显式声明无到期源", detail)
		}
	})
}

// 降级中止仍记「跳过」：该动作的安全语义不得被正常空轮稀释。
func TestDemotedRoundKeepsSkippedAuditAction(t *testing.T) {
	t.Run("threat", func(t *testing.T) {
		_, database := newClusterTestService(t)
		ResetThreatUpdateManagerForTest()
		t.Cleanup(ResetThreatUpdateManagerForTest)
		if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Fatalf("demote node: %v", err)
		}

		if err := GetThreatUpdateManager().RunUpdate("auto", nil); err != nil {
			t.Fatalf("demoted round: %v", err)
		}
		if action, _ := lastAuditRow(t, "威胁情报库"); action != "跳过" {
			t.Fatalf("降级中止审计动作=%q，want 跳过", action)
		}
	})

	t.Run("crawler", func(t *testing.T) {
		_, database := newClusterTestService(t)
		if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
			t.Fatalf("demote node: %v", err)
		}

		_ = GetCrawlerUpdateManager().RunUpdate(context.Background(), taskengine.RunContext{Ctx: context.Background(), Trigger: "auto"})
		if action, _ := lastAuditRow(t, "爬虫地址库"); action != "跳过" {
			t.Fatalf("降级中止审计动作=%q，want 跳过", action)
		}
	})
}

// lastAuditRow 返回指定 resource 的最新一条审计 (action, detail)。
func lastAuditRow(t *testing.T, resource string) (string, string) {
	t.Helper()
	var action, detail string
	if err := db.AuditDB.QueryRow(`SELECT action, detail FROM audit_log WHERE resource=? ORDER BY id DESC LIMIT 1`, resource).
		Scan(&action, &detail); err != nil {
		t.Fatalf("read audit row (%s): %v", resource, err)
	}
	return action, detail
}
