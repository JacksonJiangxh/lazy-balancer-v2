package handlers

import (
	"database/sql"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
)

// RowsAffected 读取失败时不得把「未知」当 0：归一计数会静默吞掉已发生的
// 语义变更（off→custom_only 的自定义规则开始生效），重播种计数会把「已插入」
// 误报成「未生效」。两处历史吞错点必须走同一定判元。
type unknownRowsAffectedResult struct{}

func (unknownRowsAffectedResult) LastInsertId() (int64, error) {
	return 0, errors.New("no last insert id")
}
func (unknownRowsAffectedResult) RowsAffected() (int64, error) {
	return 0, errors.New("injected rows-affected failure")
}

type knownRowsAffectedResult struct{ value int64 }

func (knownRowsAffectedResult) LastInsertId() (int64, error)   { return 0, nil }
func (r knownRowsAffectedResult) RowsAffected() (int64, error) { return r.value, nil }

func TestRowsAffectedOrUnknown_distinguishesFailureFromZero(t *testing.T) {
	var buffer strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&buffer)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	counted, known := rowsAffectedOrUnknown(unknownRowsAffectedResult{}, "导入", "归一计数")
	if known {
		t.Fatal("RowsAffected 失败必须返回 known=false（不得冒充 0 行）")
	}
	if counted != 0 {
		t.Fatalf("counted=%d, want 0（失败时数值无意义）", counted)
	}
	if !strings.Contains(buffer.String(), "归一计数") {
		t.Fatalf("读取失败必须留痕: %q", buffer.String())
	}

	counted, known = rowsAffectedOrUnknown(knownRowsAffectedResult{value: 3}, "导入", "归一计数")
	if !known || counted != 3 {
		t.Fatalf("counted=%d known=%v, want 3/true", counted, known)
	}

	var realResult sql.Result = knownRowsAffectedResult{value: 0}
	if counted, known := rowsAffectedOrUnknown(realResult, "导入", "重播种计数"); !known || counted != 0 {
		t.Fatalf("真实 0 行必须 known=true（与读取失败可判别）: counted=%d known=%v", counted, known)
	}
}

// 家族守卫：两处历史吞错点（off→custom_only 归一计数、默认拦截页重播种计数）
// 必须经 rowsAffectedOrUnknown 判定，不得再出现 `X, _ := result.RowsAffected()`。
func TestConfigBackup_normalizationSitesDoNotSwallowRowsAffected(t *testing.T) {
	source, err := os.ReadFile("config_backup.go")
	if err != nil {
		t.Fatalf("read config_backup.go: %v", err)
	}
	text := string(source)
	for _, swallowed := range []string{"n, _ := result.RowsAffected()", "affected, _ := result.RowsAffected()"} {
		if strings.Contains(text, swallowed) {
			t.Fatalf("仍存在吞错形态 %q：须改用 rowsAffectedOrUnknown（未知≠0）", swallowed)
		}
	}
	if got := strings.Count(text, "rowsAffectedOrUnknown(result"); got < 2 {
		t.Fatalf("rowsAffectedOrUnknown 调用点=%d, want >=2（归一计数与重播种计数）", got)
	}
}
