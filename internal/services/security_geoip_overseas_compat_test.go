package services

import (
	"strings"
	"testing"
)

// 兼容补丁：「海外」条目的语义展开——存量「禁止海外」规则在发射端改造
// （已解析海外行发国名）后，「海外」条目必须展开为「哨兵 ∪ 树 Countries 全集」，
// 否则已解析海外流量漏放（deny）/误拒（allow）。语义=「任何海外值」。
func TestGeoipLocOperator_overseasEntryExpandsToAllCountries(t *testing.T) {
	// Given：deny 名单含「海外」+一个省份；树国家集含 United States/Japan
	exact := map[string]bool{"United States": true, "Japan": true}
	countries := []string{"海外", "广东省"}

	// When
	op := geoipLocOperator(countries, false, exact)

	// Then：「海外」分支必须同时覆盖哨兵与全部国名（精确 alternative）
	for _, want := range []string{"海外", "United States", "Japan", "广东省"} {
		if !strings.Contains(op, want) {
			t.Fatalf("operator 缺少海外语义成员 %q: %s", want, op)
		}
	}
	if !strings.HasPrefix(op, "@rx ^(?:") {
		t.Fatalf("锚定形态被破坏: %s", op)
	}

	// allow 模式同款展开（取反形态）
	opAllow := geoipLocOperator([]string{"海外"}, true, exact)
	for _, want := range []string{"海外", "United States", "Japan"} {
		if !strings.Contains(opAllow, want) {
			t.Fatalf("allow operator 缺少 %q: %s", want, opAllow)
		}
	}
}

// 树缺失（exactSet 空）时：「海外」至少保留哨兵精确匹配（fail-safe 不产生死条目）。
func TestGeoipLocOperator_overseasEntryWithoutTreeKeepsSentinel(t *testing.T) {
	op := geoipLocOperator([]string{"海外"}, false, nil)
	if !strings.Contains(op, "海外") {
		t.Fatalf("无树时哨兵必须保留: %s", op)
	}
}
