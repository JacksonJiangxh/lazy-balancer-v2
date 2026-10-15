package services

// 第 77 轮 HP77-1/HP77-5 修复钉测：拒绝/回滚分支的磁盘回退——
// RollbackIPListProjectionsToCommittedInLock 以已提交库值重渲染一次，
// 投影文件回已提交内容、零 /load（不发射任何 admin 请求）。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given：名单被启用 deny ACL 策略引用且已提交渲染在役（投影=已提交内容）。
// When：事务视图追加条目并经 RefreshIPListProjectionsFromTxInLock 重写投影
// （热路径形态——拒绝前的未提交落盘），随后调用回退。
// Then：投影文件回到已提交内容；回退过程零 /load；事务回滚后库视图不变。
func TestR77_RollbackProjectionToCommittedInLock_restoresProjectionFiles(t *testing.T) {
	stubSecurityLibsAvailable(t)
	newClusterTestService(t)
	admin := newHotPathTestAdmin(t)
	s := NewCaddyService(admin.srv.URL)
	listID := seedHotPathList(t, `[{"value":"203.0.113.5","remark":""}]`)
	policyID := seedHotPathPolicy(t, listID)
	if err := s.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}
	committed := mustReadProjection(t, policyID)

	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE security_ip_lists SET entries=? WHERE id=?`,
		`[{"value":"203.0.113.5","remark":""},{"value":"198.51.100.7","remark":""}]`, listID); err != nil {
		t.Fatalf("tx update: %v", err)
	}
	out, err := s.RefreshIPListProjectionsFromTxInLock(tx)
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if out != ProjectionConverged {
		t.Fatalf("名单-only 变更应收敛: %v", out)
	}
	fresh := mustReadProjection(t, policyID)
	if fresh == committed {
		t.Fatalf("前置失效：事务视图未重写投影（%q）", fresh)
	}

	loadsBefore := admin.loadCount()
	s.RollbackIPListProjectionsToCommittedInLock()
	if got := admin.loadCount(); got != loadsBefore {
		t.Fatalf("回退不得 /load: %d -> %d", loadsBefore, got)
	}
	if got := mustReadProjection(t, policyID); got != committed {
		t.Fatalf("回退后投影=%q, want 已提交内容 %q", got, committed)
	}
}
