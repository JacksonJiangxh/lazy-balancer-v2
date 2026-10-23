package handlers

// 崩溃窗口收敛（渲染期名单投影先于事务提交落盘）。
//
// 写路径的渲染是投影文件的唯一写入口，而渲染发生在事务提交之前；进程在
// 「投影已写、事务未提交」之间被杀时，磁盘上会残留未提交内容。收敛点不是
// 崩溃处理（进程已死），而是**重启后的首个渲染**：启动应用以已提交库值为
// 唯一真相源重渲染全量配置，逐 scope 重写投影（内容不一致→原子换内容，
// 一致→同字节跳写），因此只要启动渲染成功，在役投影必然等于已提交视图。
//
// 收敛保证的边界（本文件与 ApplyConfigOnStartup 的注释同源）：
//   - 只覆盖本轮启动渲染**实际引用**的投影。已提交视图不再引用的文件
//     （策略解绑/规则删除后的旧 scope、升级前旧哈希命名）不会被重写——它们
//     是零控制面效果的惰性孤儿，由 24h GC 回收；
//   - 「已提交视图渲染失败」（库数据损坏导致生成错误）没有可收敛目标：启动
//     按既有裁定回退 last-known-good，部分投影维持原状。该形态需要
//     「崩溃窗口 + 已提交数据同时损坏」双故障，单故障（本用例形态）必然收敛；
//   - 未初始化实例的启动守卫（无用户、无启用规则且运行配置含规则路由）跳过
//     整轮应用：该形态不可能产生本实例的名单写入（写名单需认证用户），因此
//     不存在需要收敛的崩溃窗口；
//   - 从监督器 last-known-good 回放到启动应用完成之间，运行配置可能仍引用
//     崩溃窗口写入的投影——窗口上界=「回放→标记→应用」之间的时长（秒级），
//     由启动协议定死，应用完成即收敛。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// snapshotProjectionFiles 读投影目录全部 .txt 投影（文件名→原始字节），
// 用于「已提交视图渲染结果」的逐字节基线。
func snapshotProjectionFiles(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(services.IPListDataDir)
	if err != nil {
		t.Fatalf("读投影目录 %s: %v", services.IPListDataDir, err)
	}
	out := make(map[string]string, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".txt") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(services.IPListDataDir, entry.Name()))
		if err != nil {
			t.Fatalf("读投影 %s: %v", entry.Name(), err)
		}
		out[entry.Name()] = string(raw)
	}
	return out
}

// Given：名单被启用策略引用 + 受信代理已启用（tp.txt 在役），已提交视图
// 渲染应用一次（磁盘投影 = 已提交内容）。
// When：模拟崩溃窗口——每个在役投影被改写为「事务视图已落盘、事务未提交」
// 的内容（追加一条从未提交的条目），进程级投影状态清空（重启）。
// Then：启动应用（已提交库值渲染）把每个在役投影逐字节收敛回已提交视图，
// DB 不被启动路径改写。
func TestStartupApply_convergesStaleProjectionsToCommittedView(t *testing.T) {
	f := newHotPathIPListFixture(t)
	f.h.cfg = &config.Config{CaddyAdminURL: f.adminSrv.URL}
	// 监督器不在场（裸跑/测试形态）——waitStartupReplayDone 立即返回。
	setupStartupReplayFixture(t, false)

	listID, policyID := f.seedReferencedList(`[{"value":"203.0.113.5","remark":""}]`)
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_ranges='["9.9.9.0/24"]' WHERE id=1`); err != nil {
		t.Fatalf("seed trusted proxy: %v", err)
	}
	if err := f.h.caddyService.GenerateAndApplyConfig(); err != nil {
		t.Fatalf("首次应用: %v", err)
	}

	// 已提交视图渲染结果（崩溃窗口的收敛目标）。
	committed := snapshotProjectionFiles(t)
	for _, name := range []string{"tp.txt", fmt.Sprintf("p%d-acl.txt", policyID)} {
		if _, ok := committed[name]; !ok {
			t.Fatalf("基线缺少在役投影 %s（目录内容 %v）", name, committed)
		}
	}

	// When：崩溃窗口——投影已按未提交事务视图落盘，事务未提交。
	for name, raw := range committed {
		path := filepath.Join(services.IPListDataDir, name)
		if err := os.WriteFile(path, []byte(raw+"198.51.100.7/32\n"), 0o644); err != nil {
			t.Fatalf("写陈旧投影 %s: %v", name, err)
		}
	}
	if got := committed["tp.txt"]; strings.Contains(got, "198.51.100.7") {
		t.Fatalf("前置失效：基线已含未提交条目 %q", got)
	}
	// 进程重启：投影备忘/引用集为进程级状态，重启后必为空表。
	services.ResetIPListProjectionStateForTest()

	// Then：启动应用把在役投影收敛回已提交视图。
	if err := f.h.ApplyConfigOnStartup(""); err != nil {
		t.Fatalf("启动应用: %v", err)
	}
	got := snapshotProjectionFiles(t)
	if len(got) != len(committed) {
		t.Fatalf("启动后投影文件数=%d, want %d（不得多写未引用 scope）", len(got), len(committed))
	}
	for name, want := range committed {
		if got[name] != want {
			t.Fatalf("启动后投影 %s 未收敛到已提交视图: got=%q want=%q", name, got[name], want)
		}
	}

	// 收敛只发生在磁盘：启动路径不得改写库。
	var entries string
	if err := db.DB.QueryRow(`SELECT entries FROM security_ip_lists WHERE id=?`, listID).Scan(&entries); err != nil {
		t.Fatalf("read list: %v", err)
	}
	if entries != `[{"value":"203.0.113.5","remark":""}]` {
		t.Fatalf("启动后名单条目=%q, want 已提交值", entries)
	}
}
