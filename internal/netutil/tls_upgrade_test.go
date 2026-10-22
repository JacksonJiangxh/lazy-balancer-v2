package netutil

import (
	"net/http"
	"testing"
)

// 重放状态集合的唯一判定点——MCP 回环转发与集群同主机升级客户端
// 共用本函数，任何一侧新增/删除状态码都必须同时改变两侧语义。
func TestIsTLSUpgradeRedirect(t *testing.T) {
	upgrades := []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect}
	for _, code := range upgrades {
		if !IsTLSUpgradeRedirect(code) {
			t.Errorf("IsTLSUpgradeRedirect(%d)=false, want true", code)
		}
	}
	for _, code := range []int{http.StatusOK, http.StatusNoContent, http.StatusSeeOther, http.StatusNotModified, http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError} {
		if IsTLSUpgradeRedirect(code) {
			t.Errorf("IsTLSUpgradeRedirect(%d)=true, want false", code)
		}
	}
}
