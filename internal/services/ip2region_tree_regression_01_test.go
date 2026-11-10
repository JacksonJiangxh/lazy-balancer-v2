package services

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// 带外 ≥4GB 假 xdb（管理面导入/手工替换可达）header EndIndexPtr 近 2^32 时
// ptr += 14 回绕，扫描永不终止。修复：int64 运算 + 文件大小上界钳制。
func TestRegionTreeFromXDB_ptrOverflowTerminates(t *testing.T) {
	// Given：稀疏假 xdb——header 声明段区 [0xFFFFFFF0, 0xFFFFFFFF]，文件
	// 恰好覆盖该区间（4GB+16 稀疏占位，不写真实段数据）
	dir := t.TempDir()
	path := filepath.Join(dir, "fake.xdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 256)
	binary.LittleEndian.PutUint32(header[8:], 0xFFFFFFF0)
	binary.LittleEndian.PutUint32(header[12:], 0xFFFFFFFF)
	if _, err := f.WriteAt(header, 0); err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(0x100000010); err != nil {
		t.Fatal(err)
	}
	// 稀疏支持探测：不支持稀疏分配的文件系统会把 Truncate 落成真实 4GiB
	// 占用（慢机/CI 卷可能被吃满）。已分配块超过阈值即跳过而非硬跑。
	if fi, statErr := f.Stat(); statErr == nil {
		if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks*512 > 64<<20 {
			_ = f.Close()
			t.Skipf("文件系统未对 Truncate 稀疏分配（已占用 %d bytes），跳过 4GiB 假 xdb 用例", st.Blocks*512)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// When：扫描（旧 uint32 实现在 ptr += 14 回绕后永不返回）
	type result struct{ tree *IP2RegionRegionTree }
	done := make(chan result, 1)
	go func() {
		done <- result{tree: regionTreeFromXDB(path)}
	}()
	select {
	case got := <-done:
		// Then：钳制后段区终点收敛到文件实际末尾，header 声明的 4GB 高位
		// 段区不含可解析段 → 无任何省份（nil），而非把 header/向量零字节
		// 当段解析出幽灵省份。
		if got.tree != nil {
			t.Fatalf("钳制后不应解析出地域树, got %+v", got.tree)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("regionTreeFromXDB 未在 5s 内返回——uint32 ptr 回绕致扫描不终止")
	}
}

// xdb 段索引全量扫描的省→城市树契约（使用仓库内固定
// caddygeoip/testdata/ip2region_v4.xdb，CI 不得因 live 库不存在而恒跳过）。
func TestIP2RegionRegionTree_scan(t *testing.T) {
	// 测试夹具直取仓库源文件，避免开发机 live 库或 /tmp 副本造成版本分叉。
	path := filepath.Join("..", "..", "caddygeoip", "testdata", "ip2region_v4.xdb")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("repository xdb fixture unavailable: %v", err)
	}
	tree := regionTreeFromXDB(path)
	if tree == nil {
		t.Fatal("scan returned nil tree for a valid xdb")
	}
	// 34 个省级行政区 + 海外由 ProvinceList 渠道保证；树只含中国省份。
	if len(tree.Provinces) < 30 {
		t.Fatalf("provinces=%d, want >=30（中国省级行政区）", len(tree.Provinces))
	}
	// 直辖市/大省必有城市。
	foundCity := false
	for _, cities := range tree.Cities {
		if len(cities) > 0 {
			foundCity = true
			break
		}
	}
	if !foundCity {
		t.Fatal("no cities found in tree（xdb 段含城市列，扫描应产出至少一省的城市集）")
	}
	// 排序不变量：前 n-1（省份）严格递增，海外固定末位。
	for i := 1; i < len(tree.Provinces)-1; i++ {
		if tree.Provinces[i-1] >= tree.Provinces[i] {
			t.Fatalf("provinces not sorted: %q >= %q", tree.Provinces[i-1], tree.Provinces[i])
		}
	}
	if tree.Provinces[len(tree.Provinces)-1] != "海外" {
		t.Fatalf("海外 must be last, got %q", tree.Provinces[len(tree.Provinces)-1])
	}
	// 未映射 ASCII 段清零断言——当前 v3.17.0 全部拼音/英文段已
	// 映射；未来 xdb 版本新增未映射段时计数 >0，此断言失败提醒补映射表
	//（丢失可见而非静默过滤）。
	if tree.DroppedASCIIProvinces != 0 || tree.DroppedASCIICities != 0 {
		t.Fatalf("unmapped ASCII segments dropped: prov=%d city=%d — 映射表需为新版 xdb 补条目", tree.DroppedASCIIProvinces, tree.DroppedASCIICities)
	}
	// 少数民族自治州简称必须映射为全称——
	// 云南大理/怒江、四川凉山等 30 个自治州；「大理」这类简称不得残留。
	assertCity := func(prov, want string) {
		for _, c := range tree.Cities[prov] {
			if c == want {
				return
			}
		}
		t.Fatalf("%s 缺 %q", prov, want)
	}
	assertCity("云南省", "大理白族自治州")
	assertCity("云南省", "怒江傈僳族自治州")
	assertCity("四川省", "凉山彝族自治州")
	assertCity("新疆维吾尔自治区", "伊犁哈萨克自治州")
	assertCity("青海省", "海西蒙古族藏族自治州")
	assertCity("甘肃省", "临夏回族自治州")
	for _, bad := range []string{"大理", "怒江", "凉山"} {
		for prov, cities := range tree.Cities {
			for _, c := range cities {
				if c == bad {
					t.Fatalf("%s 残留自治州简称 %q", prov, bad)
				}
			}
		}
	}

	// revision 机制的实际契约：缓存文件的 revision 与当前树版本不一致 → 判过期
	//（旧缓存自动重建）；revision 一致且条目规范 → 不判过期。只比较
	// tree.Revision 与生产常量是恒真的（常量由被测扫描函数自己写入）。
	stalePath := filepath.Join(t.TempDir(), "stale.regions.json")
	oldData, err := json.Marshal(IP2RegionRegionTree{Revision: "v0-legacy", Provinces: []string{"广东省"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stalePath, oldData, 0o644); err != nil {
		t.Fatal(err)
	}
	if !staleRegionTreeCache(stalePath) {
		t.Fatal("旧 revision 缓存必须判过期（触发重建）")
	}
	freshPath := filepath.Join(t.TempDir(), "fresh.regions.json")
	freshData, err := json.Marshal(IP2RegionRegionTree{
		Revision:  treeCacheRevision,
		Provinces: []string{"广东省", "海外"},
		Cities:    map[string][]string{"广东省": {"深圳市"}},
		Countries: []string{"日本"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(freshPath, freshData, 0o644); err != nil {
		t.Fatal(err)
	}
	if staleRegionTreeCache(freshPath) {
		t.Fatal("当前 revision 且条目规范时不得判过期")
	}
	foundUrumqi := false
	for _, c := range tree.Cities["新疆维吾尔自治区"] {
		if c == "乌鲁木齐市" {
			foundUrumqi = true
			break
		}
	}
	if !foundUrumqi {
		t.Fatal("新疆维吾尔自治区 缺 乌鲁木齐市（UEruemqi 段未回收）")
	}
}
