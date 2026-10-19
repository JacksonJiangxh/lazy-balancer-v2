package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestGetLogStats_databaseRowsUseExportedRealFilenames(t *testing.T) {
	h := newBackupTestHandlers(t)
	dataDir := t.TempDir()
	h.cfg.DataDir = dataDir
	if err := os.WriteFile(filepath.Join(dataDir, db.AuditDBFilename), make([]byte, 321), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, db.MetricsDBFilename), make([]byte, 654), 0o600); err != nil {
		t.Fatal(err)
	}

	router := gin.New()
	router.GET("/logs/stats", h.GetLogStats)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/logs/stats?key=audit,security_events", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var payload struct {
		Data struct {
			Logs []struct {
				Key       string `json:"key"`
				SizeBytes int64  `json:"size_bytes"`
				DBBytes   *int64 `json:"db_bytes"`
			} `json:"logs"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	rows := make(map[string]struct {
		size int64
		db   *int64
	}, len(payload.Data.Logs))
	for _, row := range payload.Data.Logs {
		rows[row.Key] = struct {
			size int64
			db   *int64
		}{size: row.SizeBytes, db: row.DBBytes}
	}
	if len(rows) != 2 || rows["audit"].size != 321 {
		t.Fatalf("audit row=%+v rows=%v, want real audit database size 321", rows["audit"], rows)
	}
	if rows["security_events"].db == nil || *rows["security_events"].db != 654 {
		t.Fatalf("security_events db bytes=%v, want real metrics database size 654", rows["security_events"].db)
	}
}
