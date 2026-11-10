package handlers

// 契约：受信代理引用名单条目必须与内联通道同宽度判据（最小 /8 与
//     /29、全空间网段拒绝）——否则可经名单通道等价绕过内联防线；
//   受信代理引用校验与 UI 同口径拒绝内置名单（system=1）——
//     威胁名单真实条目在 .iplist 文件（DB entries 恒空），继续以 DB 列校验
//     会让条格式门与 2000 条总量门整体失效。

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestUpdateConfig_trustedProxyRefs_rejectsOverwideListEntry(t *testing.T) {
	for _, entry := range []string{"0.0.0.0/0", "10.0.0.0/4", "::/0", "2001:db8::/28"} {
		t.Run(entry, func(t *testing.T) {
			router := newTrustedProxyRefsRouter(t)
			listID := seedTrustedRefList(t, "overwide-list", fmt.Sprintf(`[{"value":%q,"remark":""}]`, entry))

			body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, listID)
			rec := putConfig(t, router, body)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "过宽") {
				t.Fatalf("引用条目 %s 过宽必须 400 且提示过宽，got %d %s", entry, rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUpdateConfig_trustedProxyRefs_acceptsOfficialCDNv6Range(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	listID := seedTrustedRefList(t, "cloudflare-v6", `[{"value":"2a06:98c0::/29","remark":""}]`)
	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, listID)
	rec := putConfig(t, router, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("官方 CDN IPv6 网段引用应接受，got %d %s", rec.Code, rec.Body.String())
	}
}

func TestUpdateConfig_trustedProxyRefs_rejectsBuiltinList(t *testing.T) {
	router := newTrustedProxyRefsRouter(t)
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries, system) VALUES ('内置威胁名单', ?, 1)`,
		`[{"value":"198.51.100.0/24","remark":""}]`)
	if err != nil {
		t.Fatalf("seed builtin list: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	body := fmt.Sprintf(`{"source":"caddy","trusted_proxy_ranges":"[]","trusted_proxy_range_refs":"[%d]"}`, id)
	rec := putConfig(t, router, body)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "内置") {
		t.Fatalf("内置名单引用必须 400（与 UI 仅列自定义名单同口径），got %d %s", rec.Code, rec.Body.String())
	}
}
