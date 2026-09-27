package mcpserver

import "testing"

// F62-22(第 62 轮审计):tools 切片与 toolUsage map 是两份按 name 松耦合的
// 平行注册表——漏配时 ListToolSpecs 静默输出空 Usage。本钉测试强制键集相等。
func TestToolUsageParity(t *testing.T) {
	if len(tools) != len(toolUsage) {
		t.Fatalf("tools=%d but toolUsage=%d — registration drift", len(tools), len(toolUsage))
	}
	for _, spec := range tools {
		if _, ok := toolUsage[spec.name]; !ok {
			t.Errorf("tool %q has no usage entry in toolUsage map", spec.name)
		}
	}
}
