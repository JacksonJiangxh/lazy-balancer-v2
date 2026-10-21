package middleware

// 历史问题-3：global_config 集群版本触发器 OF 清单的单源漂移护栏。
// 漏列故障形态：新增「仅写漏列」的端点/直改 SQL 时不 bump cluster_version，
// 稳态变更经 304 门滞留主节点（历史修复 autoban 六列、历史问题 自动备份组均曾因
// 同类遗漏修过）。故用两条机器断言钉住：①ClusterBasicSettings（同步快照
// 契约）的每个 JSON 字段必须命中清单；②每个补列都能独立触发 bump。

import (
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func TestGlobalConfigSyncedColumns_coverClusterBasicSettings(t *testing.T) {
	columns := make(map[string]struct{}, len(globalConfigSyncedColumns))
	dupes := map[string]int{}
	for _, column := range globalConfigSyncedColumns {
		if _, exists := columns[column]; exists {
			dupes[column]++
		}
		columns[column] = struct{}{}
	}
	if len(dupes) > 0 {
		t.Fatalf("duplicate columns in globalConfigSyncedColumns: %v", dupes)
	}

	typ := reflect.TypeOf(models.ClusterBasicSettings{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		if _, ok := columns[tag]; !ok {
			t.Errorf("ClusterBasicSettings.%s (json %q) 未列入 globalConfigSyncedColumns——该列变化不会 bump cluster_version，从节点将滞留旧值",
				typ.Field(i).Name, tag)
		}
	}
}

// 三列此前仅靠「同语句 UPDATE 含其他 OF 列」偶然触发 bump；单独 UPDATE 必须
// 也能 bump（trigger 的 OF 成员资格）。
func TestClusterVersionTrigger_bumpsForRetentionAndSampleColumns(t *testing.T) {
	for _, column := range []string{"security_events_retention_days", "security_events_row_cap", "threat_traffic_sample_n"} {
		t.Run(column, func(t *testing.T) {
			database := newClusterVersionTestDB(t)
			if err := installClusterVersionTriggers(database); err != nil {
				t.Fatal(err)
			}
			if _, err := database.Exec("UPDATE global_config SET is_master=1, cluster_version=100 WHERE id=1"); err != nil {
				t.Fatal(err)
			}
			if got := clusterVersion(t, database); got != 100 {
				t.Fatalf("baseline cluster_version=%d, want 100", got)
			}
			// SQLite UPDATE OF 只要 SET 提到该列即触发（与值是否变化无关）；
			// 用 col=col 写入保持列值语义不变。
			if _, err := database.Exec("UPDATE global_config SET " + column + " = " + column + " WHERE id=1"); err != nil {
				t.Fatalf("update %s: %v", column, err)
			}
			if got := clusterVersion(t, database); got != 101 {
				t.Fatalf("cluster_version=%d after updating %s, want 101 (column missing from OF list)", got, column)
			}
		})
	}
}
