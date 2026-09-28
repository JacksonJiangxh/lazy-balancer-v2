package wafiplist

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// RDB 验证（Steps 13-20）：20 万条不可聚合 /32 集——.fast 冷加载 vs 文本冷加载
// 的耗时对照 + 同 IP 查询语义一致。
func TestFastLoad_vs_TextLoad_200k(t *testing.T) {
	dir := t.TempDir()
	textPath := filepath.Join(dir, "bench.iplist")
	buf := make([]byte, 0, 200000*13)
	for i := 0; i < 200000; i++ {
		// 分散 /32，跨多段，避免聚合
		buf = append(buf, []byte(fmt.Sprintf("203.%d.%d.%d\n", i%256, (i/256)%256, (i/65536)%256))...)
	}
	if err := os.WriteFile(textPath, buf, 0644); err != nil {
		t.Fatal(err)
	}

	// 经 EnsureFastFile 编译（与生产路径同构）
	_, err := EnsureFastFile(textPath, func(p string) ([]netip.Prefix, []netip.Prefix, error) {
		raw, _ := os.ReadFile(p)
		var v4 []netip.Prefix
		for _, line := range strings.Split(string(raw), "\n") {
			if line == "" {
				continue
			}
			pr, err := ParseIPEntry(line)
			if err != nil {
				continue
			}
			if pr.Addr().Is4() {
				v4 = append(v4, pr)
			}
		}
		return v4, nil, nil
	})
	if err != nil {
		t.Fatalf("EnsureFastFile: %v", err)
	}
	fi, _ := os.Stat(textPath + ".fast")
	t.Logf(".fast=%d bytes(text=%d)", fi.Size(), len(buf))

	// 冷加载 .fast（fresh=true 绕过缓存）
	t0 := time.Now()
	st1, err1 := loadIPListFile(textPath+".fast", true)
	d1 := time.Since(t0)
	if err1 != nil || st1 == nil {
		t.Fatalf("fast: %v", err1)
	}

	// 冷加载文本
	t0 = time.Now()
	st2, err2 := loadIPListFile(textPath, true)
	d2 := time.Since(t0)
	if err2 != nil || st2 == nil {
		t.Fatalf("text: %v", err2)
	}
	t.Logf("20万条冷加载: .fast=%v text=%v 加速=%.0fx", d1, d2, float64(d2)/float64(d1))
	if d1 > d2 {
		t.Fatalf(".fast 加载必须不慢于文本: fast=%v text=%v", d1, d2)
	}

	// 语义一致: 同 IP 命中判定相同（与 Evaluate 同构的二分查询）
	hit := func(st *ipListFileState, ip string) bool {
		addr := netip.MustParseAddr(ip).Unmap()
		set := st.v4
		if addr.Is6() {
			set = st.v6
		}
		i := sort.Search(len(set), func(i int) bool { return set[i].Addr().Compare(addr) > 0 }) - 1
		return i >= 0 && set[i].Contains(addr)
	}
	for _, probe := range []string{"203.0.0.0", "203.1.2.3", "203.255.255.255", "10.0.0.1"} {
		if hit(st1, probe) != hit(st2, probe) {
			t.Fatalf("语义分叉 %s: fast=%v text=%v", probe, hit(st1, probe), hit(st2, probe))
		}
	}
	if !hit(st1, "203.1.2.3") {
		t.Fatal("203.1.2.3 必须命中(fast)")
	}
	if hit(st1, "10.0.0.1") {
		t.Fatal("10.0.0.1 必须不命中")
	}
}
