package handlers

// 仅被受信代理网段引用（trusted_proxy_range_refs ∧ trusted_proxy_enabled=1）
// 时也算「已引用」（tp.txt 投影消费，名单实际生效中）。修复前的窄引用实现只
// 查 ip_acl_list_refs/ip_whitelist_refs，此形态误报黄条「名单未生效」；改调
// services.IPListsReferencedByEnabledPolicy（热路径资格门四面单源）后
// 与生效面同口径。

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestAutobanStatus_listReferencedViaTrustedProxyRefs(t *testing.T) {
	router := newAutobanTestEnv(t)
	var listID int64
	if err := db.DB.QueryRow(`SELECT id FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, services.AutobanPresetListName).Scan(&listID); err != nil {
		t.Fatalf("preset list missing: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE global_config SET trusted_proxy_enabled=1, trusted_proxy_range_refs=? WHERE id=1`, fmt.Sprintf(`[%d]`, listID)); err != nil {
		t.Fatalf("seed trusted proxy refs: %v", err)
	}

	rec := getRequest(t, router, "/security/autoban/status")
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Data struct {
			ListReferenced bool `json:"list_referenced"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, rec.Body.String())
	}
	if !resp.Data.ListReferenced {
		t.Fatal("预置名单仅被受信代理网段引用时 list_referenced 应为 true（tp.txt 投影消费=名单生效中，不得误报黄条）")
	}
}
