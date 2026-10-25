package services

import (
	"os"
	"path/filepath"
	"testing"
)

// 同一棵 CRS 树的「规则全集」有三种口径：rule_count/完整性探针递归全树，
// 索引与缓存键只扫顶层。发行契约=扁平 rules/ 目录（当前等价）；子目录 .conf
// 出现即契约被打破——守卫必须能检出，索引仍只收顶层规则。
func TestCRSSubdirRuleGuard_detectsNestedConf(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, filepath.Join(dir, "REQUEST-900.conf"), "SecRule ARGS \"@rx x\" \"id:910001,phase:2,pass\"\n")
	if warnCRSSubdirRuleFiles(filepath.Join(dir, "missing")) {
		t.Fatal("不存在的子目录不得报告命中")
	}

	sub := filepath.Join(dir, "nested")
	writeTestFile(t, filepath.Join(sub, "REQUEST-901.conf"), "SecRule ARGS \"@rx y\" \"id:910002,phase:2,pass\"\n")
	if !warnCRSSubdirRuleFiles(sub) {
		t.Fatal("子目录含 .conf 时守卫必须检出（契约被打破）")
	}

	oldDir := CRSRuleIndexDir
	CRSRuleIndexDir = dir
	t.Cleanup(func() { CRSRuleIndexDir = oldDir })
	index := buildCRSRuleIndex("v-test")
	if len(index.Rules) != 1 || index.Rules[0].File != "REQUEST-900.conf" {
		t.Fatalf("索引=%+v, want 仅顶层一条（CRS 发行契约=扁平目录）", index.Rules)
	}
	_ = os.RemoveAll(sub)
}
