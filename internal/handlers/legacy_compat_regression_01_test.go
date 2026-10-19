package handlers

import "testing"

// completeBackupJSON 兼容历史审计测试的旧装配名；实现委托当前单源夹具。
func completeBackupJSON(t *testing.T, tables map[string][]map[string]any) string {
	t.Helper()
	return buildBackup(t, backupFixtureOptions{Tables: tables, FillAll: true, EmptyConfigIfNil: true})
}
