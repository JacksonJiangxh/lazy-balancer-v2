package services

import (
	"context"
	"errors"
	"testing"
)

// 更新失败后 /security/{crs,ip2region}/update/status 的 version
// 必须是「已安装版本」，不是本次尝试安装的 tag。修复前 run 在安装前就把
// state.version 写成远端 tag，fail 分支不复位——失败/取消后接口报未安装的版本。

func TestCRSUpdateStatus_failedRunReportsInstalledVersion(t *testing.T) {
	m := newTestCRSManager(t)
	seedCRSVersionRow(t, "v4.14.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v4.15.0", nil }
	m.downloadTarball = func(context.Context, string, string, downloadProgressFunc) error {
		return errors.New("下载中断")
	}
	m.reloader = func() error { return nil }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatalf("start update: %v", err)
	}
	<-done

	snap := m.StatusSnapshot()
	if snap.Status != string(CRSStatusFailed) {
		t.Fatalf("status=%q, want failed", snap.Status)
	}
	if snap.Version != "v4.14.0" {
		t.Fatalf("status version=%q, want 已安装版本 v4.14.0（不是尝试安装的 v4.15.0）", snap.Version)
	}
	if version, _, _, _, _, _, _ := crsVersionRow(t); version != "v4.14.0" {
		t.Fatalf("db version=%q, want v4.14.0（失败不得写版本行）", version)
	}
}

func TestIP2RegionUpdateStatus_failedRunReportsInstalledVersion(t *testing.T) {
	m := newTestIP2RegionManager(t)
	seedIP2RegionVersionRow(t, "v3.0.0", true)
	m.fetchLatestTag = func(context.Context) (string, error) { return "v3.1.0", nil }
	m.downloadXDB = func(context.Context, string, string, downloadProgressFunc) error {
		return errors.New("下载中断")
	}
	m.reloader = func() error { return nil }

	done, err := m.StartUpdate("manual", nil)
	if err != nil {
		t.Fatalf("start update: %v", err)
	}
	<-done

	snap := m.StatusSnapshot()
	if snap.Status != string(IP2RegionStatusFailed) {
		t.Fatalf("status=%q, want failed", snap.Status)
	}
	if snap.Version != "v3.0.0" {
		t.Fatalf("status version=%q, want 已安装版本 v3.0.0（不是尝试安装的 v3.1.0）", snap.Version)
	}
}
