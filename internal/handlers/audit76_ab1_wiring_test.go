package handlers

// 第 76 轮 F2/AB-1 接线钉：预置名单两条解封路径（remove-ip 端点、差集全量
// 保存）必须调用 services.AutobanForgetIPs（单一入口）——机制侧行为
//（封禁→删除→无新事件→越 2 tick→不重封）由 services 层
// TestAutobanForgetIPs_deleteThenNoNewEventsNoReban 钉死，本钉测锁定两调用
// 点不旁路（源扫描：符号出现恰 2 次）。另附预置名单 remove-ip HTTP 行为
// 冒烟（200+条目更新——走新清桶接线,空桶下为 no-op）。

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestAutobanUnban_bucketClearWiringPinned(t *testing.T) {
	src, err := os.ReadFile("securityiplists.go")
	if err != nil {
		t.Fatalf("read securityiplists.go: %v", err)
	}
	if got := strings.Count(string(src), "services.AutobanForgetIPs("); got != 2 {
		t.Fatalf("services.AutobanForgetIPs 调用点=%d, want 恰 2（remove-ip 端点+差集全量保存；新增解封面必须走同一入口并更新本钉测）", got)
	}
}

func TestRemoveIPFromList_autobanPresetUnbanSmoke(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := ipRemoveRouter(t)
	var presetID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, services.AutobanPresetListName).Scan(&presetID); err != nil {
		t.Fatalf("preset list missing: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`, `[{"value":"203.0.113.77","remark":"自动封禁"}]`, presetID); err != nil {
		t.Fatalf("seed preset entry: %v", err)
	}

	rec := postRemove(t, router, fmt.Sprintf("/security/ip-lists/%d/remove-ip", presetID), map[string]any{"value": "203.0.113.77"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if got := decodeRemove(t, rec).Data.Removed; !got {
		t.Fatal("预置名单条目应可移除（F73-A 例外：删除即解封）")
	}
	var entriesJSON string
	if err := db.DB.QueryRow(`SELECT COALESCE(entries,'[]') FROM security_ip_lists WHERE id=?`, presetID).Scan(&entriesJSON); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(entriesJSON, "203.0.113.77") {
		t.Fatalf("entries=%s, want 已移除 203.0.113.77", entriesJSON)
	}
}
