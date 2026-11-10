package services

import (
	"context"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// 升主可见告警（不自动动作）：Promote 清空 last_sync_error 前必须先读现值——
// 若旧集群同步残留未完成补偿标记（重载失败/品牌落盘失败/安全数据未收敛），
// 清标记的同时必须留「升主完成：检测到上次同步存在未完成补偿（X），建议执行
// 一次系统配置载入」的审计与告警，只报告不自动动作（与看门狗口径一致）。
func TestClusterService_Promote_auditsPendingCompensationMarkers(t *testing.T) {
	tests := []struct {
		name        string
		storedError string
		wantDetail  []string // 审计 detail 必须包含的片段；空=不得出现补偿告警
	}{
		{
			name:        "reload failure marker",
			storedError: encodeSyncError("apply_ok_reload_failed: caddy down", models.SyncErrorCodeApplyFailed),
			wantDetail:  []string{"未完成补偿", "重载失败补偿", "系统配置载入"},
		},
		{
			name:        "commit uncertainty marker",
			storedError: encodeSyncError(syncCommitUncertainMarkerPrefix+": 提交结果不确定", models.SyncErrorCodeApplyFailed),
			wantDetail:  []string{"未完成补偿", "提交不确定补偿", "系统配置载入"},
		},
		{
			name:        "branding failure marker",
			storedError: encodeSyncError(syncBrandingFailureMarkerPrefix+": 品牌配置落盘失败", models.SyncErrorCodeApplyFailed),
			wantDetail:  []string{"未完成补偿", "品牌落盘补偿", "系统配置载入"},
		},
		{
			name:        "waf convergence failure message",
			storedError: encodeSyncError("安全数据持续同步失败（已连续 5 轮未收敛）", models.SyncErrorCodeTransportError),
			wantDetail:  []string{"未完成补偿", "安全数据未收敛", "系统配置载入"},
		},
		{
			name:        "plain transport error is not a compensation marker",
			storedError: encodeSyncError("同步拉取失败", models.SyncErrorCodeTransportError),
			wantDetail:  nil,
		},
		{
			name:        "empty sync error",
			storedError: "",
			wantDetail:  nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given：从节点态 + 指定 last_sync_error 残留
			_, database := newClusterTestService(t)
			service := NewClusterService(database, "")
			if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url='', cluster_token='secret', last_sync_error=? WHERE id=1`, test.storedError); err != nil {
				t.Fatalf("seed slave state: %v", err)
			}

			// When
			if err := service.Promote(context.Background()); err != nil {
				t.Fatalf("promote: %v", err)
			}

			// Then：标记照常清空（升主语义不变）
			var stored string
			if err := database.QueryRow(`SELECT COALESCE(last_sync_error,'') FROM global_config WHERE id=1`).Scan(&stored); err != nil {
				t.Fatalf("read sync error: %v", err)
			}
			if stored != "" {
				t.Fatalf("last_sync_error=%q, want cleared after promote", stored)
			}
			// And：补偿标记在清除前被告警留痕（只报告，不自动动作）
			var n int
			if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='提升完成' AND resource='集群节点' AND detail LIKE '%未完成补偿%'`).Scan(&n); err != nil {
				t.Fatalf("count compensation audit: %v", err)
			}
			if len(test.wantDetail) == 0 {
				if n != 0 {
					t.Fatalf("compensation audit rows=%d, want 0（非补偿标记不得误报）", n)
				}
				return
			}
			if n != 1 {
				t.Fatalf("compensation audit rows=%d, want 1", n)
			}
			var detail string
			if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log WHERE action='提升完成' AND detail LIKE '%未完成补偿%'`).Scan(&detail); err != nil {
				t.Fatalf("read compensation audit: %v", err)
			}
			for _, fragment := range test.wantDetail {
				if !strings.Contains(detail, fragment) {
					t.Fatalf("audit detail=%q, want fragment %q", detail, fragment)
				}
			}
		})
	}
}

// Promote 后补重装首槽：升主节点接管规则库更新生产职责时，与装配同源的
// RearmSecurityLibrarySlots 必须武装 auto_update 开但 next_update 为空的行——
// 否则空槽靠重启才能恢复，升主节点静默停更。
func TestClusterService_Promote_rearmsEmptySecurityLibrarySlots(t *testing.T) {
	// Given：从节点态 + CRS 版本行「auto_update 开、next_update 空」
	_, database := newClusterTestService(t)
	service := NewClusterService(database, "")
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url='', cluster_token='secret' WHERE id=1`); err != nil {
		t.Fatalf("seed slave state: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_crs_version (id, version, auto_update, next_update) VALUES (1, 'test-version', 1, '')
		ON CONFLICT(id) DO UPDATE SET auto_update=1, next_update=''`); err != nil {
		t.Fatalf("seed empty crs slot: %v", err)
	}

	// When
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}

	// Then：升主后空槽被武装（与引擎装配同源口径）
	var nextUpdate string
	if err := database.QueryRow(`SELECT COALESCE(next_update,'') FROM security_crs_version WHERE id=1`).Scan(&nextUpdate); err != nil {
		t.Fatalf("read crs next_update: %v", err)
	}
	if nextUpdate == "" {
		t.Fatal("升主后 CRS next_update 仍为空——首槽未被武装")
	}
}
