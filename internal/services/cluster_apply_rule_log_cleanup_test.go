package services

// 从节点规则删除必须清理规则访问日志：lb_rules 行与证书文件都随快照替换
// 删除，但 /app/logs/rules/<id>.log(+轮转) 是每节点本地文件（Caddy 按
// log_enabled 在各节点独立写）——集群 apply 不清理即永久残留（UI/看门狗/
// 日志统计均按存活规则过滤，无人可见；单规则最坏 6×100MB）。清理失败仅
// warn+审计，不得阻断同步（与证书轴的派生数据口径一致）。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestApplySnapshot_removesRuleLogsForDisappearedRules(t *testing.T) {
	_, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	logDir := t.TempDir()
	restoreLogDir := SetRuleLogDirForTest(logDir)
	t.Cleanup(restoreLogDir)

	for _, id := range []string{"lb_keep", "lb_gone"} {
		if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
			VALUES (?,?, 'http', ?, 8080, 1)`, id, id, id+".example.test"); err != nil {
			t.Fatalf("seed rule %s: %v", id, err)
		}
		if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES (?, '127.0.0.1', 9000, 1)`, id); err != nil {
			t.Fatalf("seed upstream %s: %v", id, err)
		}
		if err := os.WriteFile(filepath.Join(logDir, id+".log"), []byte("line\n"), 0o644); err != nil {
			t.Fatalf("write log %s: %v", id, err)
		}
	}

	// 主节点快照：仅保留 lb_keep（lb_gone 已被删除）。
	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{
		Version: 7,
		Rules: []models.LbRule{{
			CaddyID: "lb_keep", Name: "lb_keep", Protocol: "http",
			Domain: "lb_keep.example.test", ListenPort: 8080, Enabled: true,
		}},
	})
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply snapshot: %v", err)
	}

	if _, err := os.Stat(filepath.Join(logDir, "lb_gone.log")); !os.IsNotExist(err) {
		t.Fatalf("消失规则的访问日志仍残留（stat err=%v）", err)
	}
	if _, err := os.Stat(filepath.Join(logDir, "lb_keep.log")); err != nil {
		t.Fatalf("存活规则的访问日志被误删: %v", err)
	}
}

// 回归形状：清理失败（只读目录）不得让同步失败——快照已提交，日志是派生
// 数据；失败只留 warn/审计。
func TestApplySnapshot_ruleLogCleanupFailureDoesNotFailSync(t *testing.T) {
	_, database := newClusterTestService(t)
	originalCertDir := certDir
	certDir = t.TempDir()
	t.Cleanup(func() { certDir = originalCertDir })
	logDir := t.TempDir()
	restoreLogDir := SetRuleLogDirForTest(logDir)
	t.Cleanup(restoreLogDir)

	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled)
		VALUES ('lb_gone2','lb_gone2','http','gone2.example.test',8080,1)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO upstreams (rule_id,host,port,enabled) VALUES ('lb_gone2','127.0.0.1',9000,1)`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "lb_gone2.log"), []byte("line\n"), 0o644); err != nil {
		t.Fatalf("write log: %v", err)
	}
	// 清理失败注入：把日志本体占位为非空目录——os.Remove 对非空目录返回
	// ENOTEMPTY，删除面（removeRuleLogRotationsInEntries 的 os.Remove）不得
	// 吞掉该错误。不依赖目录权限位：chmod 0500 对 root 无效（CAP_DAC_OVERRIDE
	// 直接无视读位，曾实测 root 下删除成功），非空目录的 ENOTEMPTY 与运行
	// 用户无关，断言稳定；且最终断言（日志残留）经 stat 仍成立。
	if err := os.Remove(filepath.Join(logDir, "lb_gone2.log")); err != nil {
		t.Fatalf("remove log file: %v", err)
	}
	if err := os.Mkdir(filepath.Join(logDir, "lb_gone2.log"), 0o755); err != nil {
		t.Fatalf("occupy log path with dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(logDir, "lb_gone2.log", "inner"), []byte("x"), 0o644); err != nil {
		t.Fatalf("make occupied dir non-empty: %v", err)
	}

	snapshot := v3SnapshotWithACMESection(models.ClusterSnapshot{Version: 8})
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("规则日志清理失败不得阻断同步: %v", err)
	}
	if _, err := os.Stat(filepath.Join(logDir, "lb_gone2.log")); err != nil {
		t.Fatalf("只读目录下日志应残留（本用例验证失败不阻断）: %v", err)
	}
}
