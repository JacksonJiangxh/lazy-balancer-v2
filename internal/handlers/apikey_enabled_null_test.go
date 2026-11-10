package handlers

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// api_keys.is_enabled 为 NULL 的行（仅带外改库可达）鉴权侧刻意 fail-closed：
// 列表按 COALESCE(is_enabled,1) 显示「启用」，而 ResolveAPIKeyIdentity 的裸比较
// 拒绝该行。这是有意取舍——放行 NULL 会让历史脏行静默获得鉴权。

func TestResolveAPIKeyIdentity_nullIsEnabledFailsClosed(t *testing.T) {
	database := setupAPIKeyTestDB(t)

	plaintext := "lb_null_enabled_key_0001"
	hash := sha256.Sum256([]byte(plaintext))
	if _, err := database.Exec(`INSERT INTO api_keys (id, name, key_hash, key_prefix, created_by, is_enabled) VALUES (30, 'null-enabled', ?, ?, 1, NULL)`,
		hex.EncodeToString(hash[:]), plaintext[:12]); err != nil {
		t.Fatal(err)
	}

	if _, err := db.ResolveAPIKeyIdentity(database, plaintext); !errors.Is(err, db.ErrAPIKeyNotFound) {
		t.Fatalf("is_enabled=NULL 必须 fail-closed（401），got %v", err)
	}

	// 列表口径仍显示「启用」（排障可见性），不得据此推断鉴权会放行。
	var listedEnabled int
	if err := database.QueryRow(`SELECT COALESCE(is_enabled,1) FROM api_keys WHERE id=30`).Scan(&listedEnabled); err != nil {
		t.Fatal(err)
	}
	if listedEnabled != 1 {
		t.Fatalf("列表口径 is_enabled=%d, want 1（已知的有意差异）", listedEnabled)
	}
}
