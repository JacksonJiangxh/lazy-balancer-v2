package services

import (
	"encoding/json"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 内置 system 名单的「行缺失自愈」统一走 db.EnsureSystemIPList：三条播种路径
// （启动/autoban 运行期/threat 运行期）的 category、描述来源与幂等性必须一致。
// 手写 INSERT 曾在三处漂移（category 字面量、描述来源、缺 OR IGNORE）。
func TestSystemListSelfHealPaths_convergeOnEnsure(t *testing.T) {
	newClusterTestService(t)
	overrideWafDirForTest(t)
	setupThreatTest(t, nil, nil, nil)

	// ---- 自动封禁：删除 system=1 行后自愈 ----
	if _, err := db.DB.Exec(`DELETE FROM security_ip_lists WHERE name=? AND system=1`, AutobanPresetListName); err != nil {
		t.Fatal(err)
	}
	id, err := ensureAutobanPresetListID()
	if err != nil {
		t.Fatalf("ensureAutobanPresetListID: %v", err)
	}
	var desc, category, entries string
	var system int
	if err := db.DB.QueryRow(`SELECT COALESCE(description,''), COALESCE(category,''), COALESCE(system,0) FROM security_ip_lists WHERE id=?`, id).
		Scan(&desc, &category, &system); err != nil {
		t.Fatal(err)
	}
	if desc != autobanPresetListDescription || category != "自动封禁" || system != 1 {
		t.Fatalf("自愈行 desc=%q category=%q system=%d, want %q/自动封禁/1", desc, category, system, autobanPresetListDescription)
	}
	again, err := ensureAutobanPresetListID()
	if err != nil || again != id {
		t.Fatalf("幂等自愈: id=%d err=%v, want %d（重复调用不得新建行）", again, err, id)
	}

	// 同名用户列表必须与内置行并存（不合并、不删除）。
	if _, err := db.DB.Exec(`DELETE FROM security_ip_lists WHERE name=? AND system=1`, AutobanPresetListName); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, description, category, entries, system) VALUES (?, '用户自建', '自定义', '[]', 0)`, AutobanPresetListName); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureAutobanPresetListID(); err != nil {
		t.Fatalf("同名用户列表在场时自愈: %v", err)
	}
	var systemRows, userRows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&systemRows); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=0`, AutobanPresetListName).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if systemRows != 1 || userRows != 1 {
		t.Fatalf("同名共存 system=%d user=%d, want 1/1", systemRows, userRows)
	}

	// ---- 威胁情报库：删除 system=1 行后写盘路径自愈 ----
	name := db.ThreatListNameBySource("ustc")
	if name == "" {
		t.Fatal("夹具失效：ustc 未登记内置名单")
	}
	if _, err := db.DB.Exec(`DELETE FROM security_ip_lists WHERE name=? AND system=1`, name); err != nil {
		t.Fatal(err)
	}
	if _, err := writeThreatSystemList("ustc", []string{"203.0.113.77"}); err != nil {
		t.Fatalf("writeThreatSystemList: %v", err)
	}
	if err := db.DB.QueryRow(`SELECT COALESCE(description,''), COALESCE(category,''), COALESCE(system,0), COALESCE(entries,'') FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, name).
		Scan(&desc, &category, &system, &entries); err != nil {
		t.Fatalf("威胁库自愈行缺失: %v", err)
	}
	if desc != threatListDescription("ustc") || category != "恶意 IP" || system != 1 {
		t.Fatalf("威胁库自愈行 desc=%q category=%q system=%d, want %q/恶意 IP/1", desc, category, system, threatListDescription("ustc"))
	}
	// 自愈行必须是合法 JSON 空集（'[]'）：手写 INSERT 曾写空串（非法 JSON），
	// 与播种/渲染的空集口径（null/[] 等价）分叉。
	var seedEntries []struct{}
	if err := json.Unmarshal([]byte(entries), &seedEntries); err != nil || len(seedEntries) != 0 {
		t.Fatalf("自愈行 entries=%q, want 合法空集 []（json err=%v）", entries, err)
	}
}
