package services

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/wafiplist"
)

// 威胁名册文本损坏（低可解析率/空文本）而 .fast 完好时，渲染侧
// 旧实现无条件信任文本代际 → 损坏行被整段渲染、.fast 正确条目被遮蔽，拦截
// 面静默缩水且无留痕。文本解析率低于下载侧同源阈值（50%）时必须改用 .fast。
func TestReadThreatIplistPath_corruptTextFallsBackToFast(t *testing.T) {
	t.Run("garbage text", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "threat-x.iplist")
		// 3 行乱码 vs .fast 2 条：旧实现会原样返回 3 行（长度即差异）。
		if err := os.WriteFile(path, []byte("garbage-line\nnot-an-ip\nstill-bad\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := wafiplist.WriteFastFile(path+".fast", mustParsePrefixes(t,
			"203.0.113.0/24", "198.51.100.0/24"), nil); err != nil {
			t.Fatal(err)
		}
		// 文本较新（主节点同代写入形态）：旧实现无条件采用文本。
		newer := time.Now().Add(time.Minute)
		if err := os.Chtimes(path, newer, newer); err != nil {
			t.Fatal(err)
		}
		vals, err := readThreatIplistPath(path)
		if err != nil {
			t.Fatalf("读取失败: %v", err)
		}
		// 必须比对条目值集合——只比条数时返回任意两条（含乱码行）都会通过。
		gotSet := map[string]bool{}
		for _, v := range vals {
			gotSet[v] = true
		}
		if len(vals) != 2 || !gotSet["203.0.113.0/24"] || !gotSet["198.51.100.0/24"] {
			t.Fatalf("损坏文本必须回退 .fast 的条目集合（不混入坏行），got %v", vals)
		}
	})

	t.Run("empty text", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "threat-y.iplist")
		if err := os.WriteFile(path, []byte("# only comments\n\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := wafiplist.WriteFastFile(path+".fast", mustParsePrefixes(t,
			"192.0.2.0/24"), nil); err != nil {
			t.Fatal(err)
		}
		newer := time.Now().Add(time.Minute)
		if err := os.Chtimes(path, newer, newer); err != nil {
			t.Fatal(err)
		}
		vals, err := readThreatIplistPath(path)
		if err != nil || len(vals) != 1 || vals[0] != "192.0.2.0/24" {
			t.Fatalf("空文本必须回退 .fast，got %v err=%v", vals, err)
		}
	})

	t.Run("partially valid text stays authoritative", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "threat-z.iplist")
		// 2/3 可解析 ≥ 50%：正常名单的偶发坏行不得触发回退。
		if err := os.WriteFile(path, []byte("203.0.113.0/24\n198.51.100.0/24\nbad-line\n"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := wafiplist.WriteFastFile(path+".fast", mustParsePrefixes(t,
			"192.0.2.0/24"), nil); err != nil {
			t.Fatal(err)
		}
		newer := time.Now().Add(time.Minute)
		if err := os.Chtimes(path, newer, newer); err != nil {
			t.Fatal(err)
		}
		vals, err := readThreatIplistPath(path)
		if err != nil {
			t.Fatalf("读取失败: %v", err)
		}
		if len(vals) != 3 || vals[0] != "203.0.113.0/24" {
			t.Fatalf("可解析率达标时必须沿用文本，got %v", vals)
		}
	})
}
