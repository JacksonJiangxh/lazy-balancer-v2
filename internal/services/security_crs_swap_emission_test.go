package services

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 树交换探针必须在 CRS 指令发射点二次采样：入口采样之后还要付库探测、索引
// 构建与逐（规则×策略）渲染（百毫秒级），窗口可能在此间开启——此时逐条
// Include 会指向缺失/半拷贝的规则文件，发布一份「可编译但安全链弱化」的配置。
// 两个实际消费点（glob 分支 / 选组分支）都必须命中即拒。
func TestBuildCorazaDirectives_rejectsSwapWindowAtCRSEmission(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"crs-setup.conf",
		"rules/REQUEST-901-INITIALIZATION.conf",
		"rules/REQUEST-949-BLOCKING-EVALUATION.conf",
		"rules/RESPONSE-959-BLOCKING-EVALUATION.conf",
		"rules/REQUEST-913-SCANNER-DETECTION.conf",
	} {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), []byte("# fixture\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	restore := SetSecurityLibsDirsForTest(dir, filepath.Join(dir, "ip2region.xdb"))
	t.Cleanup(restore)
	resetCRSRuleIndexCacheForHardeningTest(t)

	policies := map[string]*models.SecurityPolicy{
		"glob 分支":   {ID: 1, Name: "swap-glob", Mode: "blocking", AnomalyThreshold: 5},
		"选组分支":      {ID: 2, Name: "swap-groups", Mode: "blocking", AnomalyThreshold: 5, CRSRuleGroups: json.RawMessage(`["13"]`)},
		"6 位 ID 分支": {ID: 3, Name: "swap-ids", Mode: "blocking", AnomalyThreshold: 5, CRSRuleGroups: json.RawMessage(`["913100"]`)},
	}
	for name, policy := range policies {
		t.Run(name, func(t *testing.T) {
			leave := enterCRSTreeSwapWindow()
			defer leave()
			if _, err := BuildCorazaDirectives(policy, nil, "", false, 0, "lb_swap"); !errors.Is(err, errCRSTreeSwapInFlight) {
				t.Fatalf("err=%v, want errCRSTreeSwapInFlight（发射点必须在窗口内拒绝整份配置）", err)
			}
		})
	}

	// 直接消费点：选组发射器自身也要防御（不依赖调用方）。
	leave := enterCRSTreeSwapWindow()
	defer leave()
	if err := emitCRSRuleGroupSelection(&strings.Builder{}, &models.SecurityPolicy{Name: "swap-direct"}, []string{"13"}, lazyCRSRuleIndex()); !errors.Is(err, errCRSTreeSwapInFlight) {
		t.Fatalf("emitCRSRuleGroupSelection err=%v, want errCRSTreeSwapInFlight", err)
	}
}

// 窗口关闭后同一策略必须恢复正常生成（探针不得泄漏/误拒）。
func TestBuildCorazaDirectives_resumesAfterSwapWindow(t *testing.T) {
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rules, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "crs-setup.conf"), []byte("# fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rules, "REQUEST-901-INITIALIZATION.conf"), []byte("# fixture\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restore := SetSecurityLibsDirsForTest(dir, filepath.Join(dir, "ip2region.xdb"))
	t.Cleanup(restore)
	resetCRSRuleIndexCacheForHardeningTest(t)

	leave := enterCRSTreeSwapWindow()
	leave()
	if _, err := BuildCorazaDirectives(&models.SecurityPolicy{ID: 9, Name: "after", Mode: "blocking", AnomalyThreshold: 5}, nil, "", false, 0, "lb_after"); err != nil {
		t.Fatalf("窗口关闭后生成必须恢复: %v", err)
	}
}
