package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// 导出侧归一 nodes.mode：该列唯一写点（注册路径）恒写 'slave'，巡检按
// mode='slave' 过滤。旧版本遗留/带外直改的 'master' 行若原样入包，会被当前
// 版本的导入行级门拒绝——实例无法还原自己的备份（备份自毒）。
func TestExportConfigBackup_normalizesLegacyNodeMode(t *testing.T) {
	h := newBackupTestHandlers(t)
	seedLiveAdminShared(t)
	// 带外遗留形态：直改库得到的 mode='master' 行。
	if _, err := db.DB.Exec(`INSERT INTO nodes (name,mode,ip_address,port,is_approved) VALUES ('legacy-master','master','10.0.0.21',8000,1)`); err != nil {
		t.Fatalf("seed legacy node: %v", err)
	}

	router := gin.New()
	router.GET("/config/export", h.ExportConfigBackup)
	exportResponse := httptest.NewRecorder()
	router.ServeHTTP(exportResponse, httptest.NewRequest(http.MethodGet, "/config/export?sections=cluster", nil))
	if exportResponse.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exportResponse.Code, exportResponse.Body.String())
	}
	unpacked, err := parseLbbak(exportResponse.Body.Bytes())
	if err != nil {
		t.Fatalf("unpack export: %v", err)
	}
	var exported struct {
		Tables map[string][]map[string]any `json:"tables"`
	}
	if err := json.Unmarshal(unpacked.ConfigJSON, &exported); err != nil {
		t.Fatalf("decode export config: %v", err)
	}
	rows := exported.Tables["nodes"]
	if len(rows) != 1 {
		t.Fatalf("exported nodes rows=%d, want 1", len(rows))
	}
	if mode, _ := rows[0]["mode"].(string); mode != "slave" {
		t.Fatalf("exported nodes.mode=%q, want slave（导出归一，避免自备份不可还原）", mode)
	}

	// 自备份可还原：同一实例导入自己的导出必须通过行级门。
	importResponse := postImportBytes(t, h, unpacked.ConfigJSON)
	if importResponse.Code != http.StatusOK {
		t.Fatalf("self-backup restore status=%d body=%s, want 200", importResponse.Code, importResponse.Body.String())
	}
	var mode string
	if err := db.DB.QueryRow(`SELECT mode FROM nodes WHERE name='legacy-master'`).Scan(&mode); err != nil {
		t.Fatalf("read restored node: %v", err)
	}
	if mode != "slave" {
		t.Fatalf("restored nodes.mode=%q, want slave", mode)
	}
}
