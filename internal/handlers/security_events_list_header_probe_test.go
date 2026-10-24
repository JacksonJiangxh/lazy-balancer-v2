package handlers

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
)

// 列表侧「隐藏键数」探针必须与截断同口径（字节）：length(TEXT) 是字符数，
// 多字节头值（未编码中文 Referer/非 ASCII 自定义头）会「字节超 16KiB 而字符
// 不超」——字符口径返回 0，列表弹框丢弃被切断的成员却不写隐藏计数。
func TestSecurityEventListHeadersTotalSQL_usesByteLengthForOversizeProbe(t *testing.T) {
	database, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })

	// 6000 个汉字 ≈ 18KB UTF-8、字符数 ≈ 6KB：字节超限、字符不超限。
	value := `{"X-Multi":"` + strings.Repeat("中", 6000) + `"}`
	var charLen, byteLen int
	if err := database.QueryRow(`SELECT length(?), length(CAST(? AS BLOB))`, value, value).Scan(&charLen, &byteLen); err != nil {
		t.Fatal(err)
	}
	if byteLen <= securityEventListFieldCap || charLen > securityEventListFieldCap {
		t.Fatalf("夹具形态不符：chars=%d bytes=%d cap=%d", charLen, byteLen, securityEventListFieldCap)
	}

	var total int
	if err := database.QueryRow(`SELECT `+securityEventListHeadersTotalSQL("payload")+` FROM (SELECT ? AS payload)`, value).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 1 {
		t.Fatalf("隐藏键数=%d, want 1（字节超限必须计入被丢弃成员）", total)
	}

	// 未超限的行仍返回 0（探针不得误报隐藏计数）。
	small := `{"Host":["a.example.com"]}`
	if err := database.QueryRow(`SELECT `+securityEventListHeadersTotalSQL("payload")+` FROM (SELECT ? AS payload)`, small).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 0 {
		t.Fatalf("未超限行隐藏键数=%d, want 0", total)
	}
}
