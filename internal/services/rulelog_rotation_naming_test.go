package services

// 轮转副本命名以生产链为准：Caddy v2.11.7 的 logging FileWriter 把
// BackupTimeFormat/Compression 原样交给 timberjack，渲染侧不写这两个配置
// （只写 output/filename/roll_size_mb/roll_keep），故取 timberjack 默认值——
// 时间格式为虚线日期 + 毫秒（日期与时刻段均以 '-' 分隔）、压缩默认 gzip
// （副本名追加 .gz）。夹具必须用真实命名，否则删除侧正则与真实文件不符
// 却仍然全绿（残留不可见）。

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveRuleLogFiles_deletesRealTimberjackRotationCopies(t *testing.T) {
	dir := t.TempDir()
	restore := SetRuleLogDirForTest(dir)
	t.Cleanup(restore)

	// 本规则的副本：真实形态（虚线日期 + .gz）+ 未压缩形态 + 紧凑日期历史
	// 形态 + zstd 压缩形态。
	ownCopies := []string{
		"lb_live.log",
		"lb_live-2026-10-23T18-38-57.122-size.log.gz",
		"lb_live-2026-10-23T18-38-57.122-size.log",
		"lb_live-20261023T18-38-57.122-size.log",
		"lb_live-2026-10-23T18-39-01.004-size.log.zst",
	}
	// 兄弟规则副本（caddy_id 以本规则 id 为前缀）：一个都不能动。
	brotherCopies := []string{
		"lb_live-extra-2026-10-23T18-38-57.122-size.log.gz",
		"lb_live-1-2026-10-23T18-38-57.122-size.log.gz",
	}
	for _, name := range append(append([]string{}, ownCopies...), brotherCopies...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := RemoveRuleLogFiles("lb_live"); err != nil {
		t.Fatalf("RemoveRuleLogFiles: %v", err)
	}

	for _, name := range ownCopies {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("本规则日志 %s 未被删除（轮转副本永久残留）: %v", name, err)
		}
	}
	for _, name := range brotherCopies {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("兄弟规则副本 %s 被误删: %v", name, err)
		}
	}
}
