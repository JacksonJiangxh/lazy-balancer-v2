package services

// 威胁名单「文本损坏且无可用 .fast」不得按文本装载：垃圾/空条目集会静默变成
// 生效名单（deny 方向失去拦截、allow 方向全拒），唯一信号是一条 warn。读取
// 失败让引用策略走既有严格模式（IPRefMissing 跳过渲染 + 审计），UI 预览同样
// fail-visible。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestReadThreatIplistPath_dualFailureIsAnError(t *testing.T) {
	t.Run("corrupt text without fast", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "threat-x.iplist")
		if err := os.WriteFile(path, []byte("garbage-a\ngarbage-b\nnot-an-ip\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		vals, err := readThreatIplistPath(path)
		if err == nil {
			t.Fatalf("损坏文本且无 .fast 必须报错，返回条目 %v", vals)
		}
		if vals != nil {
			t.Fatalf("失败形态不得同时返回条目: %v", vals)
		}
		if !strings.Contains(err.Error(), "无 .fast 可回退") {
			t.Fatalf("错误文案应说明缺少可回退的编译产物: %v", err)
		}
	})

	t.Run("corrupt text with broken fast", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "threat-y.iplist")
		if err := os.WriteFile(path, []byte("# only comments\n\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		// 陈旧 .fast 存在但损坏（截断）：与缺失同属「不可用」，不得按空集装载。
		if err := os.WriteFile(path+".fast", []byte("lb-ipfast-v1\x00\x00"), 0o644); err != nil {
			t.Fatal(err)
		}
		vals, err := readThreatIplistPath(path)
		if err == nil {
			t.Fatalf("文本不可用且 .fast 不可读必须报错，返回条目 %v", vals)
		}
		if !strings.Contains(err.Error(), ".fast") {
			t.Fatalf("错误文案应点名 .fast: %v", err)
		}
	})
}

func TestReadThreatIplistForUI_dualFailureSurfacesError(t *testing.T) {
	restore := OverrideThreatWafDirForTest(t.TempDir())
	defer restore()
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), []byte("garbage-line\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	listName := ""
	for _, sl := range db.ThreatSystemLists() {
		if sl.Source == "ustc" {
			listName = sl.Name
		}
	}
	if listName == "" {
		t.Fatal("未找到 ustc 威胁系统名单名")
	}
	if _, err := ReadThreatIplistForUI(listName); err == nil {
		t.Fatal("UI 预览必须暴露读取失败（空集会让管理员误以为名单为空）")
	}
	// 对照：文件缺失仍是「未更新/禁用源」空集形态，不改变既有契约。
	otherName := ""
	for _, sl := range db.ThreatSystemLists() {
		if sl.Source == "firehol_l1" {
			otherName = sl.Name
		}
	}
	if otherName == "" {
		t.Fatal("未找到 firehol_l1 威胁系统名单名")
	}
	if vals, err := ReadThreatIplistForUI(otherName); err != nil || len(vals) != 0 {
		t.Fatalf("缺失文件应返回空集且无错误，got vals=%v err=%v", vals, err)
	}
}
