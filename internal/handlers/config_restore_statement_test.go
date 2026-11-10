package handlers

import (
	"strings"
	"testing"
)

// restoreTable 的 SQL 文本必须按行稳定：Go map 迭代序随机，若按迭代序拼列名，
// 每行生成一条不同 SQL，database/sql 的连接级 prepared statement 缓存会被
// O(N) 条语句灌满（万行导入 = 万条预编译）。

func TestRestoreRowStatement_stableColumnOrderAcrossRowKeyOrder(t *testing.T) {
	valid := map[string]bool{"a": true, "b": true, "c": true, "d": true}

	first := map[string]any{"a": 1, "b": "x", "c": nil, "d": 4}
	second := map[string]any{"d": 4, "c": nil, "b": "x", "a": 1}

	queryA, valuesA, okA := restoreRowStatement("t", first, valid)
	queryB, valuesB, okB := restoreRowStatement("t", second, valid)
	if !okA || !okB {
		t.Fatalf("ok=%v/%v, want both true", okA, okB)
	}
	if queryA != queryB {
		t.Fatalf("同一列集合必须生成同一 SQL 文本：\n%s\n%s", queryA, queryB)
	}
	if !strings.Contains(queryA, `"a","b","c","d"`) {
		t.Fatalf("列序必须字典序，got %s", queryA)
	}
	if len(valuesA) != len(valuesB) {
		t.Fatalf("参数个数不一致：%d vs %d", len(valuesA), len(valuesB))
	}
	for i := range valuesA {
		if valuesA[i] != valuesB[i] {
			t.Fatalf("第 %d 个参数随键序漂移：%v vs %v", i, valuesA[i], valuesB[i])
		}
	}
}

func TestRestoreRowStatement_skipsRowsWithoutKnownColumns(t *testing.T) {
	valid := map[string]bool{"a": true}
	if _, _, ok := restoreRowStatement("t", map[string]any{"unknown": 1}, valid); ok {
		t.Fatal("无任何可落库列的行必须跳过")
	}
}
