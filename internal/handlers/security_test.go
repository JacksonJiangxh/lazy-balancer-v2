package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// GetCRSInfo/GetIP2RegionInfo 对齐 ——仅行缺失
// (ErrNoRows)合法回落默认值,真实 DB 故障 500 可见(此前一律吞为默认)。
func TestGetCRSInfo_dbFailureReturns500(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 换坏库:关掉真库换一个无表库使查询报错(非 ErrNoRows)
	bad, err := sql.Open("sqlite", t.TempDir()+"/bad.db")
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	oldDB := db.DB
	db.DB = bad
	t.Cleanup(func() { db.DB = oldDB })
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.GetCRSInfo(c)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("CRS status=%d, want 500 on real DB failure", w.Code)
	}
	w2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(w2)
	h.GetIP2RegionInfo(c2)
	if w2.Code != http.StatusInternalServerError {
		t.Fatalf("IP2Region status=%d, want 500 on real DB failure", w2.Code)
	}
}

// IP 弹框增强(批准):近 N 天该 IP 事件计数——索引范围 COUNT。days 解析与
// 分页参数同口径：非整数显式 400、<1 沿用默认、超上限钳制。
func TestGetIPEventCount(t *testing.T) {
	h := newBackupTestHandlers(t)
	// 种子：2 条 30 天内 + 1 条 40 天前 + 1 条 100 天前（metrics 库）——
	// 只有同时覆盖「默认窗口」与「上限窗口」的种子才能分辨钳制是否生效。
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,action,client_ip,rule_caddy_id) VALUES
		(datetime('now','-1 day'),'blocked','1.2.3.4','r1'),
		(datetime('now','-2 day'),'logged','1.2.3.4','r1'),
		(datetime('now','-40 day'),'blocked','1.2.3.4','r1'),
		(datetime('now','-100 day'),'blocked','1.2.3.4','r1'),
		(datetime('now','-1 day'),'blocked','5.6.7.8','r1')`); err != nil {
		t.Fatalf("seed security events: %v", err)
	}
	router := gin.New()
	router.GET("/security/events/count", h.GetIPEventCount)

	get := func(query string) *httptest.ResponseRecorder {
		t.Helper()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/events/count"+query, nil))
		return rec
	}
	assertCount := func(query string, want int) {
		t.Helper()
		rec := get(query)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", query, rec.Code, rec.Body.String())
		}
		var resp struct {
			Code int `json:"code"`
			Data struct {
				Count int `json:"count"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: unmarshal response: %v (body=%s)", query, err, rec.Body.String())
		}
		if resp.Data.Count != want {
			t.Fatalf("%s: count=%d, want %d", query, resp.Data.Count, want)
		}
	}

	assertCount("?ip=1.2.3.4", 2)            // 缺省 30 天
	assertCount("?ip=1.2.3.4&days=365", 4)   // 上限窗口覆盖 100 天前
	assertCount("?ip=1.2.3.4&days=99999", 4) // 超上限钳到 365
	assertCount("?ip=1.2.3.4&days=0", 2)     // <1 与缺省同口径
	assertCount("?ip=1.2.3.4&days=-7", 2)    // 负值同口径
	assertCount("?ip=9.9.9.9", 0)            // 无事件 IP
	// 非整数显式 400（静默回落会让拼写错误完全无信号）。
	for _, bad := range []string{"abc", "30d", "1.5"} {
		if rec := get("?ip=1.2.3.4&days=" + bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("days=%s: status=%d, want 400 (body=%s)", bad, rec.Code, rec.Body.String())
		}
	}
	// 缺 ip 400。
	if rec := get(""); rec.Code != http.StatusBadRequest {
		t.Fatalf("missing ip: status=%d, want 400", rec.Code)
	}
}

// 更新日志两代拼接后仍受单代上限约束：各代独立 128KiB 截断会让响应体放大到
// 两倍（暴露面/带宽随轮转边界翻倍），拼接后必须裁到同一上限并保留尾部
// （日志看的是最近输出）。截断点落在 UTF-8 字符边界上。
func TestReadUpdateLogWithRotation_cappedAt128KB(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "update.log")
	writeGeneration := func(target, prefix string, lines int) {
		t.Helper()
		var b strings.Builder
		for range lines {
			// 每行 ~1KB 的 ASCII 内容（≤500 行上限内，单代接近 128KiB）。
			b.WriteString(prefix + "-" + strings.Repeat("x", 1000) + "\n")
		}
		if err := os.WriteFile(target, []byte(b.String()), 0o600); err != nil {
			t.Fatalf("write %s: %v", target, err)
		}
	}
	writeGeneration(path+".1", "old", 130)
	writeGeneration(path, "new", 130)

	got := readUpdateLogWithRotation(path)
	if len(got) > updateLogMaxBytes {
		t.Fatalf("len=%d, want ≤ %d（两代拼接后必须裁到单代上限）", len(got), updateLogMaxBytes)
	}
	if !utf8.ValidString(got) {
		t.Fatal("截断点必须落在 UTF-8 字符边界，不得产出半个字符")
	}
	// 尾部保留：当前代的最后一行必须在（保留尾部而非头部）。
	if !strings.HasSuffix(got, strings.Repeat("x", 1000)+"\n") {
		t.Fatalf("尾部被丢弃：输出末尾不是当前代最后一行（len=%d）", len(got))
	}
	// 头部应已被裁掉（旧代内容不再完整保留）。
	if strings.HasPrefix(got, "old-") {
		t.Fatal("拼接结果未裁剪：旧代头部仍在")
	}
}
