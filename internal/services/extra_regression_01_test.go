package services

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// 消费端自愈补建；同名用户列表保留不动。
func TestAutobanListEntries_selfHealsMissingSystemRow(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`DELETE FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO security_ip_lists (name,description,category,entries,system)
		VALUES (?, 'user-owned', '恶意 IP', '[]', 0)`, AutobanPresetListName); err != nil {
		t.Fatal(err)
	}

	entries, id, err := AutobanListEntries()
	if err != nil {
		t.Fatalf("AutobanListEntries with missing system row: %v", err)
	}
	if id <= 0 || len(entries) != 0 {
		t.Fatalf("entries=%v id=%d, want empty list with positive id", entries, id)
	}
	var systemRows, userRows int
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=1`, AutobanPresetListName).Scan(&systemRows); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=? AND COALESCE(system,0)=0`, AutobanPresetListName).Scan(&userRows); err != nil {
		t.Fatal(err)
	}
	if systemRows != 1 || userRows != 1 {
		t.Fatalf("system rows=%d user rows=%d, want 1/1 (healed + user list preserved)", systemRows, userRows)
	}
}

// 无审计/无横幅（调用方 recordCaddyApplyResult(nil) 仅在状态已 set 时持久化）。
func TestRefreshIPListProjections_convergedSinksDegradation(t *testing.T) {
	_, database := newClusterTestService(t)
	config := generateCaddyConfigFromStore(database)
	payload, err := json.Marshal(caddyPayload(config))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/config/" {
			_, _ = w.Write(payload)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	s := NewCaddyService(srv.URL)
	setLastRenderDegradation("stale degradation")
	t.Cleanup(func() { setLastRenderDegradation("") })

	outcome, err := s.refreshIPListProjectionsInLock(database)
	if err != nil || outcome != ProjectionConverged {
		t.Fatalf("outcome=%v err=%v, want Converged", outcome, err)
	}
	if got := LastRenderDegradation(); got != "" {
		t.Fatalf("LastRenderDegradation=%q after Converged hot path, want cleared", got)
	}
}
