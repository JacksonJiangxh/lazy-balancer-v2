package services

import (
	"database/sql"
	"strings"
	"testing"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
)

// 审计详情可携带对端文本（集群主节点错误体/响应头），必须在落库单点净化：
// 剥离控制字符（含换行——否则可伪造「；结果：成功」段落）并截断 4KB。

func newAuditDetailTestDB(t *testing.T) *sql.DB {
	t.Helper()
	oldAuditDB := db.AuditDB
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	db.AuditDB = auditDB
	t.Cleanup(func() {
		db.AuditDB = oldAuditDB
		_ = auditDB.Close()
	})
	return auditDB
}

func TestRecordAuditLog_stripsPeerControlCharacters(t *testing.T) {
	auditDB := newAuditDetailTestDB(t)

	RecordAuditLog("system", "切换失败", "集群模式", "目标：从节点\n；结果：成功\r\t伪造", "")

	var detail string
	if err := auditDB.QueryRow(`SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(detail, "\n\r\t") {
		t.Fatalf("审计详情不得保留控制字符（会伪造段落），got %q", detail)
	}
	if !strings.Contains(detail, "伪造") {
		t.Fatalf("可打印正文必须保留，got %q", detail)
	}
}

func TestRecordAuditLog_capsDetailAtUTF8Boundary(t *testing.T) {
	auditDB := newAuditDetailTestDB(t)

	// 5KB 中文：截断必须落在合法 UTF-8 边界且不超过上限。
	RecordAuditLog("system", "同步失败", "集群同步", strings.Repeat("错", 2000), "")

	var detail string
	if err := auditDB.QueryRow(`SELECT detail FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if len(detail) > auditDetailMaxBytes {
		t.Fatalf("审计详情长度 %d 超过上限 %d", len(detail), auditDetailMaxBytes)
	}
	if !utf8.ValidString(detail) {
		t.Fatal("截断必须回退到合法 UTF-8 边界")
	}
	if len(detail) < auditDetailMaxBytes-3 {
		t.Fatalf("截断不应过度收缩，got %d bytes", len(detail))
	}
}

func TestSanitizeAuditDetail_shortTextUnchanged(t *testing.T) {
	in := "目标：从节点；主节点 → 从节点"
	if got := sanitizeAuditDetail(in); got != in {
		t.Fatalf("sanitizeAuditDetail 不得改写正常文本：%q", got)
	}
}
