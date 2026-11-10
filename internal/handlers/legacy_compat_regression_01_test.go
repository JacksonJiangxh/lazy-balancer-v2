package handlers

import "testing"

// completeBackupJSON 是备份/导入族测试共用的完整备份装配入口（当前数十处调用），
// 实现委托 buildBackup 单源夹具；历史名称保留只为避免批量改调用点，不含兼容
// 语义——新用例直接调 buildBackup 亦可。
func completeBackupJSON(t *testing.T, tables map[string][]map[string]any) string {
	t.Helper()
	return buildBackup(t, backupFixtureOptions{Tables: tables, FillAll: true, EmptyConfigIfNil: true})
}
