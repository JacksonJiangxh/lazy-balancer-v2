package handlers

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 历史修复: an XDB failure after the CRS phase must not delete a correct CRS
// version record. Cover both changed and already-current CRS trees because the
// changed flag alone cannot distinguish the latter from a CRS failure.
func TestLbbakImport_xdbFailurePreservesAppliedCrsRecord(t *testing.T) {
	for _, tt := range []struct {
		name       string
		mutateLive bool
	}{
		{name: "CRS changed before XDB failure", mutateLive: true},
		{name: "CRS already current before XDB failure", mutateLive: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// Given a valid CRS/XDB bundle and a deterministic XDB version-write failure.
			h := newBackupTestHandlers(t)
			audit79SeedAdmin(t)
			t.Cleanup(services.ResetIP2RegionSearcherForTest)
			g := newBackupSectionRouter(h)
			crsDir, xdbPath := overrideTestWafPaths(t)
			if err := os.MkdirAll(filepath.Join(crsDir, "rules"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(crsDir, "VERSION"), []byte("v4.29.0\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(crsDir, "rules", "crs-setup.conf"), []byte("# backup crs\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(xdbPath, validXdbBytes(t), 0o644); err != nil {
				t.Fatal(err)
			}
			bundle := services.BuildWafFileBundle()
			if bundle == nil || len(bundle.CRSTarGz) == 0 || len(bundle.Xdb) == 0 {
				t.Fatal("fixture must contain both CRS and XDB payloads")
			}
			if tt.mutateLive {
				if err := os.WriteFile(filepath.Join(crsDir, "rules", "crs-setup.conf"), []byte("# different live crs\n"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Mkdir(xdbPath+".version", 0o755); err != nil {
				t.Fatal(err)
			}
			backup := buildBackup(t, backupFixtureOptions{Sections: []string{"security"}, Tables: map[string][]map[string]any{
				"security_crs_version":       {{"id": 1, "version": "v4.29.0", "auto_update": 1}},
				"security_ip2region_version": {{"id": 1, "version": "xdb-backup", "auto_update": 1}},
			}, Config: nil})

			payload, err := buildLbbakPayload([]byte(backup), bundle)
			if err != nil {
				t.Fatal(err)
			}

			// When importing the bundle.
			response := postLbbakImport(g, t, payload, "")

			// Then only the failed XDB record is discarded; CRS is not misattributed.
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var crsRows, xdbRows int
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_crs_version WHERE version='v4.29.0'`).Scan(&crsRows); err != nil {
				t.Fatal(err)
			}
			if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_ip2region_version WHERE version='xdb-backup'`).Scan(&xdbRows); err != nil {
				t.Fatal(err)
			}
			if crsRows != 1 || xdbRows != 0 {
				t.Fatalf("partial-failure records CRS=%d XDB=%d, want 1/0; body=%s", crsRows, xdbRows, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "CRS 规则库文件落盘失败") {
				t.Fatalf("successful CRS must not be reported as failed: %s", response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "IP2Region") {
				t.Fatalf("actual XDB failure must remain visible: %s", response.Body.String())
			}
		})
	}
}

// 历史修复: a write/compile failure must leave the previous live .iplist intact.
// 历史修复 the live .fast as a directory deterministically fails after the
// new text has been staged, without depending on filesystem permissions.
func TestLbbakImport_threatCompileFailurePreservesLiveIplist(t *testing.T) {
	// Given an old live text file and a failure at compiled-file replacement.
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	wafDir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(wafDir)
	t.Cleanup(restore)
	iplistPath := filepath.Join(wafDir, "threat-ustc.iplist")
	const oldContent = "198.51.100.250/32\n"
	if err := os.WriteFile(iplistPath, []byte(oldContent), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(iplistPath+".fast", 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET updated_at='2020-01-01 00:00:00' WHERE name='ustc'`); err != nil {
		t.Fatal(err)
	}
	body := buildLbbakWithExtraThreatEntry(t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_threat_sources": {{"name": "ustc", "display_name": "USTC", "url": "https://blackip.ustc.edu.cn/list.php?txt", "format": "plain", "update_enabled": 1, "apply_enabled": 1, "updated_at": "2030-01-01 00:00:00"}},
	}, EmptyConfigIfNil: true}),

		[]byte("203.0.113.1\n"))

	// When the threat component fails during lbbak import.
	response := postLbbakImport(g, t, body, "")

	// Then the response and DB retain local state, and the text file is not overwritten.
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "威胁库") || !strings.Contains(response.Body.String(), "ustc") {
		t.Fatalf("threat failure must be visible: %s", response.Body.String())
	}
	raw, err := os.ReadFile(iplistPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != oldContent {
		t.Fatalf("failed import replaced live iplist: got %q want %q", raw, oldContent)
	}
	var updatedAt string
	if err := db.DB.QueryRow(`SELECT COALESCE(updated_at,'') FROM security_threat_sources WHERE name='ustc'`).Scan(&updatedAt); err != nil {
		t.Fatal(err)
	}
	if updatedAt == "2030-01-01 00:00:00" {
		t.Fatalf("failed source DB row was not restored: updated_at=%q", updatedAt)
	}
}

func TestLbbakImport_threatOnlyCommitFailureWarnsFileLanded(t *testing.T) {
	// Given a threat-only lbbak whose DB commit will be rejected by Caddy.
	h := newBackupTestHandlers(t)
	g := newBackupSectionRouter(h)
	overrideTestWafPaths(t)
	wafDir := t.TempDir()
	restore := services.OverrideThreatWafDirForTest(wafDir)
	t.Cleanup(restore)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return errors.New("cli: reject threat-only import") })
	body := buildLbbakWithExtraThreatEntry(t, buildBackup(t, backupFixtureOptions{FillAll: true, Tables: map[string][]map[string]any{
		"security_threat_sources": {{"name": "ustc", "display_name": "USTC", "url": "https://blackip.ustc.edu.cn/list.php?txt", "format": "plain", "update_enabled": 1, "apply_enabled": 1}},
	}, EmptyConfigIfNil: true}),

		[]byte("203.0.113.7\n"))

	// When the files land but the transaction fails.
	response := postLbbakImport(g, t, body, "")

	// Then the file/DB split is explicitly reported, not silent.
	if response.Code != http.StatusBadRequest {
		t.Fatalf("import status=%d body=%s, want 400", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "文件已按备份落盘") {
		t.Fatalf("threat-only landed file must produce split warning: %s", response.Body.String())
	}
	raw, err := os.ReadFile(filepath.Join(wafDir, "threat-ustc.iplist"))
	if err != nil || !strings.Contains(string(raw), "203.0.113.7") {
		t.Fatalf("threat file did not land: raw=%q err=%v", raw, err)
	}
}

// 历史修复: only the three built-in source names are valid lbbak threat entry
// names. This rejects Windows separators/traversal and arbitrary extra files on
// every host platform.
func TestParseLbbak_rejectsUnsafeThreatEntryNames(t *testing.T) {
	for _, entryName := range []string{
		"threat/..\\evil.iplist",
		"threat/...iplist",
		"threat/evil.iplist",
		"threat/C:\\temp\\payload.iplist",
	} {
		t.Run(entryName, func(t *testing.T) {
			// Given a structurally valid archive with an unsafe threat entry name.
			raw := craftLbbakRaw(t, map[string][]byte{
				"manifest.json": []byte(`{"format":"lbbak","checksum":{"config.json":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"}}`),
				"config.json":   []byte(`{}`),
				entryName:       []byte("203.0.113.1\n"),
			})

			// When / Then parsing rejects it before any filesystem path is built.
			if _, err := parseLbbak(raw); err == nil {
				t.Fatalf("unsafe threat entry %q was accepted", entryName)
			}
		})
	}
	// Regression: the canonical built-in entry remains valid.
	raw := craftLbbakRaw(t, map[string][]byte{
		"manifest.json":      []byte(`{"format":"lbbak","checksum":{"config.json":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"}}`),
		"config.json":        []byte(`{}`),
		"threat/ustc.iplist": []byte("203.0.113.1\n"),
	})
	if _, err := parseLbbak(raw); err != nil {
		t.Fatalf("valid threat entry regression: %v", err)
	}
}
