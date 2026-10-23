package services

// 同步包声明哈希非空但未携带内容 → 拒绝应用(主端瞬态 IO 下轮自愈);
// ReportNode 落库前 last_sync_error 与从端写侧同口径截断(≤512B);
// ApproveNode 重复审批(非 pending)→ 409 语义错误而非 404。

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/models"
)

func osReadFileForTest(t *testing.T, path string) (string, error) {
	t.Helper()
	data, err := os.ReadFile(path)
	return string(data), err
}

// 产出该形状,从端应用「无操作」后漂移永不收敛;必须拒绝。
func TestApplyWafFileBundle_rejectsHashWithoutContent(t *testing.T) {
	crsDir := t.TempDir()
	xdbPath := t.TempDir() + "/ip2region.xdb"
	t.Cleanup(OverrideWafLivePathsForTest(crsDir, xdbPath))
	// 预置 live 内容,断言拒绝后 live 树未动
	writeTestFile(t, xdbPath, "LOCAL-XDB")
	crsRulePath := filepath.Join(crsDir, "rules", "a.conf")
	if err := os.MkdirAll(filepath.Dir(crsRulePath), 0755); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, crsRulePath, "LOCAL-CRS")

	bundle := &WafFileBundle{IP2RegionSha: "deadbeef", IP2RegionTag: "v1"}
	if _, _, _, err := ApplyWafFileBundle(bundle); err == nil || !strings.Contains(err.Error(), "未携带内容") {
		t.Fatalf("hash-without-content must be rejected, got %v", err)
	}
	gotRaw, rerr := osReadFileForTest(t, xdbPath)
	if rerr != nil || gotRaw != "LOCAL-XDB" {
		t.Fatalf("live tree must be untouched after rejection, got %q err=%v", gotRaw, rerr)
	}

	crsBundle := &WafFileBundle{CRSSha256: "deadbeef"}
	if _, _, _, err := ApplyWafFileBundle(crsBundle); err == nil || !strings.Contains(err.Error(), "未携带内容") {
		t.Fatalf("crs hash-without-content must be rejected, got %v", err)
	}
	// 拒绝路径不得动本地 CRS 树（注释声称「CRS 路径未动」必须由断言承担）。
	if got, err := osReadFileForTest(t, crsRulePath); err != nil || got != "LOCAL-CRS" {
		t.Fatalf("CRS 树在拒绝路径被改动: %q err=%v", got, err)
	}
}

// 口径对齐,health_json 里的长错误不再撑大 nodes 行)。
func TestReportNode_truncatesLastSyncError(t *testing.T) {
	svc, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-trunc")

	bigError := strings.Repeat("错", 64*1024)
	report := models.ClusterReport{AppliedVersion: 1, LastSyncError: bigError}
	if err := svc.ReportNode(context.Background(), nodeID, report, time.Now()); err != nil {
		t.Fatalf("report node: %v", err)
	}
	var stored []byte
	if err := database.QueryRow("SELECT last_sync_error FROM nodes WHERE id=?", nodeID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if len(stored) > 512 {
		t.Fatalf("last_sync_error len=%d, want ≤512", len(stored))
	}
	// 截断必须保留前缀与合法 UTF-8 边界：只断长度时「返回空串」也能通过，
	// 运维取证面（节点页/上报）会静默失效。
	if !utf8.Valid(stored) {
		t.Fatal("截断后不是合法 UTF-8（多字节字符被拦腰截断）")
	}
	if len(stored) == 0 || !strings.HasPrefix(string(stored), "错错") {
		t.Fatalf("stored=%q, want 保留原消息前缀", string(stored))
	}
}

// 不存在的节点维持 ErrNodeNotFound(404 语义)。
func TestApproveNode_conflictVsNotFound(t *testing.T) {
	svc, database := newClusterTestService(t)
	nodeID := insertApprovedClusterNode(t, database, "slave-approved")

	if err := svc.ApproveNode(context.Background(), nodeID, time.Now()); !errors.Is(err, ErrNodeNotPending) {
		t.Fatalf("re-approve must return ErrNodeNotPending, got %v", err)
	}
	if err := svc.ApproveNode(context.Background(), 99999, time.Now()); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing node must return ErrNodeNotFound, got %v", err)
	}
}
