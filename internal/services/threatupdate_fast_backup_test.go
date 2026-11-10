package services

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func seedThreatFastBackupFixture(t *testing.T) (iplistPath string, oldText, oldFast []byte) {
	t.Helper()
	iplistPath = filepath.Join(t.TempDir(), "threat-ustc.iplist")
	oldText = []byte("192.0.2.1\n")
	if err := WriteThreatIplistCompiled(iplistPath, oldText); err != nil {
		t.Fatalf("seed compiled threat files: %v", err)
	}
	oldFast, err := os.ReadFile(iplistPath + ".fast")
	if err != nil {
		t.Fatal(err)
	}
	return iplistPath, oldText, oldFast
}

func TestWriteThreatIplistCompiled_hardLinkFallbackUpdatesAtomically(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failLinks bool
	}{
		{name: "hard link regression", failLinks: false},
		{name: "portable copy fallback", failLinks: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			iplistPath, _, oldFast := seedThreatFastBackupFixture(t)
			linkErr := errors.New("forced hard-link failure")
			linkCalls := 0
			oldLink := osLink
			osLink = func(oldname, newname string) error {
				linkCalls++
				if tc.failLinks {
					return linkErr
				}
				return os.Link(oldname, newname)
			}
			t.Cleanup(func() { osLink = oldLink })

			newText := []byte("198.51.100.7\n")
			if err := WriteThreatIplistCompiled(iplistPath, newText); err != nil {
				t.Fatalf("update with failLinks=%v: %v", tc.failLinks, err)
			}
			if linkCalls != 1 {
				t.Fatalf("link calls=%d, want 1", linkCalls)
			}
			gotText, err := os.ReadFile(iplistPath)
			if err != nil || string(gotText) != string(newText) {
				t.Fatalf("new text=%q err=%v", gotText, err)
			}
			gotFast, err := os.ReadFile(iplistPath + ".fast")
			if err != nil {
				t.Fatal(err)
			}
			if string(gotFast) == string(oldFast) {
				t.Fatal("new compiled bytes were overwritten by the old backup")
			}
			leftovers, err := filepath.Glob(filepath.Join(filepath.Dir(iplistPath), ".lbbak-fast-backup-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatalf("backup leftovers=%v err=%v", leftovers, err)
			}
		})
	}
}

func TestWriteThreatIplistCompiled_copyBackupRestoresOldFastAfterTextRenameFailure(t *testing.T) {
	iplistPath, _, oldFast := seedThreatFastBackupFixture(t)
	linkErr := errors.New("forced hard-link failure")
	oldLink := osLink
	var sabotageErr error
	osLink = func(_, _ string) error {
		// Precheck 后把文本目标替换为目录：新 fast 已 rename，文本 rename 必败，
		// 因而只能依靠硬链接失败时制作的副本回滚。
		if err := os.Remove(iplistPath); err != nil {
			sabotageErr = err
		} else if err := os.Mkdir(iplistPath, 0o700); err != nil {
			sabotageErr = err
		}
		return linkErr
	}
	t.Cleanup(func() { osLink = oldLink })

	err := WriteThreatIplistCompiled(iplistPath, []byte("198.51.100.7\n"))
	if sabotageErr != nil {
		t.Fatalf("sabotage text rename target: %v", sabotageErr)
	}
	if err == nil {
		t.Fatal("text rename failure must be visible")
	}
	if errors.Is(err, linkErr) {
		t.Fatalf("returned initial link error before attempting copy fallback: %v", err)
	}
	gotFast, readErr := os.ReadFile(iplistPath + ".fast")
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(gotFast) != string(oldFast) {
		t.Fatal("rollback did not restore the exact old fast bytes from the copy backup")
	}
}

func TestWriteThreatIplistCompiled_copyBackupFailureIsVisibleAndLeavesLiveFiles(t *testing.T) {
	iplistPath, oldText, oldFast := seedThreatFastBackupFixture(t)
	linkErr := errors.New("forced hard-link failure")
	oldLink := osLink
	var sabotageErr error
	osLink = func(_, backupPath string) error {
		// 副本目标被目录占据，原子 copy 的最终 rename 必败；live 文件不得被截断。
		if err := os.Mkdir(backupPath, 0o700); err != nil {
			sabotageErr = err
		}
		return linkErr
	}
	t.Cleanup(func() { osLink = oldLink })

	err := WriteThreatIplistCompiled(iplistPath, []byte("198.51.100.7\n"))
	if sabotageErr != nil {
		t.Fatalf("sabotage backup target: %v", sabotageErr)
	}
	if err == nil || !errors.Is(err, linkErr) || !strings.Contains(err.Error(), "复制旧 .fast 备份失败") {
		t.Fatalf("err=%v, want joined link and copy-backup failure", err)
	}
	gotText, readErr := os.ReadFile(iplistPath)
	if readErr != nil || string(gotText) != string(oldText) {
		t.Fatalf("live text changed after backup failure: %q, %v", gotText, readErr)
	}
	gotFast, readErr := os.ReadFile(iplistPath + ".fast")
	if readErr != nil || string(gotFast) != string(oldFast) {
		t.Fatalf("live fast changed after backup failure: %v", readErr)
	}
}
