package services

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 威胁名单文本分支必须按下载/自愈同口径剔除不可解析行：坏行原样透传会让
// @ipListFast 严格解析整份失败（无缓存时 deny 方向=不命中，allow 否定算子
// =全拒），与下载解析「只收合法行」分叉。
func TestReadThreatIplistPath_filtersUnparsableTextLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "threat-ustc.iplist")
	content := "203.0.113.1\nnot-an-ip\n203.0.113.2\n# comment\n198.51.100.0/24\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	vals, err := readThreatIplistPath(path)
	if err != nil {
		t.Fatalf("readThreatIplistPath: %v", err)
	}
	if len(vals) != 3 {
		t.Fatalf("val 条数=%d, want 3（坏行必须剔除，注释不计数）: %v", len(vals), vals)
	}
	for _, v := range vals {
		if v == "not-an-ip" {
			t.Fatal("不可解析行进入了渲染集（会让引擎整份加载失败）")
		}
	}
}

// entries='null' 与 '[]' 同为合法空集：渲染按空集合生效，摘要不得判成
// 「装载失败」——同一名单在列表显示「缺失」而实际按空集生效会让方向相反的
// 排障结论并存（deny 不拦 / trust 不信任）。
func TestParseIPListEntriesStrict_nullIsEmptySet(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"null", "null", true},
		{"empty array", "[]", true},
		{"object array", `[{"value":"1.2.3.4"}]`, true},
		{"malformed", `[{bad`, false},
		{"empty string", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			list, err := parseIPListEntriesStrict(c.raw)
			if ok := err == nil; ok != c.want {
				t.Fatalf("parseIPListEntriesStrict(%q) ok=%v (err=%v), want %v", c.raw, ok, err, c.want)
			}
			if c.want && c.raw == "null" && list != nil {
				t.Fatalf("null 必须解析为空集（nil），got=%v", list)
			}
		})
	}

	// 摘要路径与渲染同判：null 行 = 未装载失败（failed 不置位），presence=false。
	newClusterTestService(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES ('null-entries', 'null')`)
	if err != nil {
		t.Fatal(err)
	}
	listID, _ := res.LastInsertId()
	presence, failed := loadIPListRefPresenceVia(db.DB, []int64{listID})
	if failed[listID] {
		t.Fatal("entries=null 不得被判为装载失败（与渲染口径分叉）")
	}
	if presence[listID] {
		t.Fatal("entries=null 是空集，presence 必须为 false")
	}
}
