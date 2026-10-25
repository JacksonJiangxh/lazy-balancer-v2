package db

import (
	"os"
	"strings"
	"testing"
)

// security_policies.anomaly_threshold 的类型①默认值必须单源（DefaultAnomalyThreshold）：
// fresh CREATE 的 DDL DEFAULT 与 NOT-NULL 窗口期库的重建 DDL DEFAULT 一旦写字面量，
// 调整常量后两类库的落库默认静默分叉（导入 restoreTable 缺键/带外省略该列时
// 同一备份在 fresh 与重建库落不同值）。DB 侧值钉测只覆盖数值，覆盖不到「DDL
// 是否引用常量」，故此处对 DDL 文本做结构断言。
func TestSecurityPoliciesAnomalyThresholdDefault_isSingleSource(t *testing.T) {
	source, err := os.ReadFile("db.go")
	if err != nil {
		t.Fatalf("read db.go: %v", err)
	}
	text := string(source)
	if strings.Contains(text, "anomaly_threshold INTEGER DEFAULT 5") {
		t.Fatal("DDL 仍硬编码 anomaly_threshold 默认字面量 5：须改用 DefaultAnomalyThreshold（与启动归一/钉测同源）")
	}
	if got := strings.Count(text, "anomaly_threshold INTEGER DEFAULT "); got != 2 {
		t.Fatalf("anomaly_threshold DDL 默认值子句出现 %d 次, want 2（fresh CREATE + 重建 DDL 两处同源）", got)
	}
	// 两处 DDL 都必须把常量作为默认值来源（fresh 串接 / 重建 Sprintf 参数）。
	if got := strings.Count(text, "DefaultAnomalyThreshold"); got < 3 {
		t.Fatalf("DefaultAnomalyThreshold 引用次数=%d, want >=3（两处 DDL + 归一）", got)
	}
}
