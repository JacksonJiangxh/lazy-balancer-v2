package db

// 默认 CA 提供商读侧两条导出函数（GetDefaultCAProvider / IsCAProviderEnabled）
// 是证书签发与设置校验的唯一入口：任务未显式指定提供商时，每次签发/续期都经
// services.loadCAProvider → GetDefaultCAProvider 取默认值；设置保存经
// ValidateDefaultCAProvider → IsCAProviderEnabled 判启用。归一分支（行缺失 /
// NULL / 启用 / 禁用）此前零测试看守，改语义时只在生产签发失败才暴露。

import (
	"testing"
)

func openCADefaultTestDB(t *testing.T) {
	t.Helper()
	openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	// 生产启动序：default_ca_provider_id 是 newColumns 通道列（fresh DDL 不携带）。
	if err := ensureNewColumns(map[string]string{
		"global_config.default_ca_provider_id": newColumnsRegistry["global_config.default_ca_provider_id"],
	}, nil); err != nil {
		t.Fatalf("add default_ca_provider_id column: %v", err)
	}
}

func TestGetDefaultCAProvider_normalizesMissingRowAndNull(t *testing.T) {
	openCADefaultTestDB(t)
	exec := func(query string) {
		t.Helper()
		if _, err := DB.Exec(query); err != nil {
			t.Fatalf("seed %q: %v", query, err)
		}
	}
	assertProvider := func(want int) {
		t.Helper()
		got, err := GetDefaultCAProvider()
		if err != nil {
			t.Fatalf("GetDefaultCAProvider: %v", err)
		}
		if got != want {
			t.Fatalf("GetDefaultCAProvider()=%d, want %d", got, want)
		}
	}

	// 形状 1：global_config 无行（空库/表新建未播种）→ 0 而非 ErrNoRows。
	assertProvider(0)

	// 形状 2：行在、值为 NULL（旧备份/带外改库形态）→ 0。
	exec(`INSERT INTO global_config (id, caddy_config) VALUES (1, '{}')`)
	exec(`UPDATE global_config SET default_ca_provider_id=NULL WHERE id=1`)
	assertProvider(0)

	// 形状 3：显式配置 → 原值直读（渲染/消费层零兜底）。
	exec(`UPDATE global_config SET default_ca_provider_id=7 WHERE id=1`)
	assertProvider(7)

	// 形状 4：0 是合法值（=回退到运行时首个启用提供商），不得被 NULL 归一混淆。
	exec(`UPDATE global_config SET default_ca_provider_id=0 WHERE id=1`)
	assertProvider(0)
}

func TestIsCAProviderEnabled_reportsEnabledDisabledMissingAndNull(t *testing.T) {
	openCADefaultTestDB(t)
	insert := func(id int, enabled string) {
		t.Helper()
		if _, err := DB.Exec(`INSERT INTO ca_providers (id, name, provider, directory_url, enabled)
			VALUES (?, 'p', 'letsencrypt', 'https://acme.example/dir', `+enabled+`)`, id); err != nil {
			t.Fatalf("seed ca_providers id=%d enabled=%s: %v", id, enabled, err)
		}
	}

	// 启用 → true；禁用 → false；行缺失 → false（调用方据此回「不存在或已禁用」）。
	insert(1, "1")
	insert(2, "0")
	for _, tc := range []struct {
		name string
		id   int
		want bool
	}{
		{"enabled", 1, true},
		{"disabled", 2, false},
		{"missing", 99, false},
	} {
		got, err := IsCAProviderEnabled(tc.id)
		if err != nil {
			t.Fatalf("%s: IsCAProviderEnabled(%d): %v", tc.name, tc.id, err)
		}
		if got != tc.want {
			t.Fatalf("%s: IsCAProviderEnabled(%d)=%v, want %v", tc.name, tc.id, got, tc.want)
		}
	}

	// 边界形状：enabled 为 NULL（可空列，仅带外改库可达）按「禁用」处理——
	// 扫描错误会让设置校验返回内部 500，而不是「不存在或已禁用」的显性提示。
	insert(3, "NULL")
	got, err := IsCAProviderEnabled(3)
	if err != nil {
		t.Fatalf("enabled NULL 必须归一为禁用而非扫描错误: %v", err)
	}
	if got {
		t.Fatal("enabled NULL 不得报告为启用")
	}
}
