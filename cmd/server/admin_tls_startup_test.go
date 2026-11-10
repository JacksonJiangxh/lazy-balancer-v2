package main

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 启动监听协议不得因「配置读不到」而降级为明文 HTTP：startupAdminTLSConfig
// 必须把读失败上抛（run 直接拒绝启动），而不是像宽容 loader 那样回退
// Enabled=false 继续以明文提供管理面。
func TestStartupAdminTLSConfig_readFailureIsFatal(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	oldCurrent := db.GetDB()
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldCurrent)
	})

	// Given 正常库（db.Initialize 已种 global_config 行）→ 启动读取成功。
	cfg, err := startupAdminTLSConfig()
	if err != nil {
		t.Fatalf("正常配置读取失败: %v", err)
	}
	if cfg.Mode == "" {
		t.Fatalf("启动读取返回空 Mode: %+v", cfg)
	}

	// When 配置行缺失（库不可读/旧库/带外改库的等价形态）。
	if _, derr := db.DB.Exec(`DELETE FROM global_config WHERE id=1`); derr != nil {
		t.Fatalf("delete global_config row: %v", derr)
	}

	// Then 必须返回错误——调用方据此拒绝启动，绝不会进入明文 ListenAndServe。
	cfg, err = startupAdminTLSConfig()
	if err == nil {
		t.Fatalf("配置读失败必须报错，实际返回 cfg=%+v（会以明文监听管理端口）", cfg)
	}
	if !strings.Contains(err.Error(), "明文") {
		t.Fatalf("error=%q, want 含「明文」的可操作提示", err.Error())
	}
}
