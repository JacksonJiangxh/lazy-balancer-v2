package services

import (
	"strings"
	"testing"
)

// ValidateDefaultCAProvider 的三分支（唯一调用点是配置保存）：
//   - 0 = 未指定 → 运行时回落首个启用提供商，合法；
//   - 存在且启用 → 合法；
//   - 不存在 / 存在但禁用 → 明确错误（保存被 400 拒绝）。
func TestValidateDefaultCAProvider(t *testing.T) {
	_, database := newClusterTestService(t)

	// 0 是显式合法值。
	if err := ValidateDefaultCAProvider(0); err != nil {
		t.Fatalf("id=0 应合法（回落首个启用提供商），got %v", err)
	}

	var id int
	if err := database.QueryRow(`SELECT id FROM ca_providers ORDER BY id LIMIT 1`).Scan(&id); err != nil {
		t.Fatalf("seed ca provider missing: %v", err)
	}
	if _, err := database.Exec(`UPDATE ca_providers SET enabled=1 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err := ValidateDefaultCAProvider(id); err != nil {
		t.Fatalf("启用中的提供商 %d 应合法，got %v", id, err)
	}

	// 存在但禁用：错误必须同时说明「不存在或已禁用」。
	if _, err := database.Exec(`UPDATE ca_providers SET enabled=0 WHERE id=?`, id); err != nil {
		t.Fatal(err)
	}
	err := ValidateDefaultCAProvider(id)
	if err == nil {
		t.Fatal("已禁用的提供商必须被拒绝")
	}
	if !strings.Contains(err.Error(), "disabled") || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("禁用分支错误文案=%q，必须同时点名不存在/已禁用两种可能", err)
	}

	// 不存在的 id。
	if err := ValidateDefaultCAProvider(id + 999999); err == nil {
		t.Fatal("不存在的提供商必须被拒绝")
	}
}
