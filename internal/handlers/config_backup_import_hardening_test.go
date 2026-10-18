package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func audit79SeedAdmin(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'admin','hash','admin',1)`); err != nil {
		t.Fatalf("seed admin: %v", err)
	}
}

func audit79RuleTables() map[string][]map[string]any {
	return map[string][]map[string]any{
		"lb_rules": {{
			"caddy_id": "lb_audit79", "name": "audit79", "protocol": "http",
			"domain": "audit79.example.test", "listen_port": 18080,
			"strategy": "weighted_round_robin", "enabled": 0,
			"health_check_interval": 10, "health_check_timeout": 2,
			"health_check_unhealthy_threshold": 3, "health_check_healthy_threshold": 2,
			"tcp_try_interval": 250,
		}},
		"upstreams": {{
			"rule_id": "lb_audit79", "host": "127.0.0.1", "port": 9000,
			"weight": 1, "enabled": 1, "protocol": "http", "max_connections": 0,
		}},
	}
}

// U04B-01: bindings must be checked against the post-import rule/policy view;
// rules-only replacement must not leave bindings attached to deleted rules.
func TestImportConfigBackup_postImportRuleBindingView(t *testing.T) {
	t.Run("security-only uses live rules", func(t *testing.T) {
		// Given a live rule and a security-only backup that binds a restored policy to it.
		h := newBackupTestHandlers(t)
		audit79SeedAdmin(t)
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
			VALUES ('lb_live','live','http','live.example.test',18081,'weighted_round_robin',0)`); err != nil {
			t.Fatal(err)
		}
		body := r41BackupJSON(t, []string{"security"}, map[string][]map[string]any{
			"security_policies":        {{"id": 7, "name": "restored", "mode": "off", "enabled": 1}},
			"security_policy_bindings": {{"rule_caddy_id": "lb_live", "policy_id": 7}},
		}, nil)

		// When previewing and importing the security section.
		preview := r41PostValidate(t, h, body)
		response := postBackupImport(t, h, body)

		// Then the live rule completes the post-import view and the binding is restored.
		if !preview.Valid {
			t.Errorf("security-only preview rejected a live-rule binding: %s", preview.Error)
		}
		if response.Code != http.StatusOK {
			t.Fatalf("security-only import status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		var bindings int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_live' AND policy_id=7`).Scan(&bindings); err != nil || bindings != 1 {
			t.Fatalf("restored bindings=%d err=%v, want 1", bindings, err)
		}
	})

	t.Run("rules-only prunes dangling live bindings", func(t *testing.T) {
		// Given live bindings to both a rule being replaced and the incoming rule.
		h := newBackupTestHandlers(t)
		audit79SeedAdmin(t)
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled)
			VALUES ('lb_old','old','http','old.example.test',18082,'weighted_round_robin',0);
			INSERT INTO security_policies (id,name,mode,enabled) VALUES (7,'live-policy','off',1);
			INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_old',7),('lb_new',7)`); err != nil {
			t.Fatal(err)
		}
		tables := audit79RuleTables()
		tables["lb_rules"][0]["caddy_id"] = "lb_new"
		tables["upstreams"][0]["rule_id"] = "lb_new"
		body := r41BackupJSON(t, []string{"rules"}, tables, nil)

		// When importing only the rules section.
		response := postBackupImport(t, h, body)

		// Then only the binding whose target exists after import survives.
		if response.Code != http.StatusOK {
			t.Fatalf("rules-only import status=%d body=%s, want 200", response.Code, response.Body.String())
		}
		var oldBindings, newBindings int
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_old'`).Scan(&oldBindings); err != nil {
			t.Fatal(err)
		}
		if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id='lb_new' AND policy_id=7`).Scan(&newBindings); err != nil {
			t.Fatal(err)
		}
		if oldBindings != 0 || newBindings != 1 {
			t.Fatalf("post-import bindings old=%d new=%d, want 0/1", oldBindings, newBindings)
		}
		if !strings.Contains(response.Body.String(), "清理") || !strings.Contains(response.Body.String(), "绑定") {
			t.Fatalf("dangling binding cleanup must be visible in warnings: %s", response.Body.String())
		}
	})
}

// U04B-02: an allowed source name must not make a forged download URL or parser
// format acceptable. Imported rows converge to the built-in source definition.
func TestValidateImportedSources_restoreCanonicalEndpoints(t *testing.T) {
	// Given allowed names carrying attacker-controlled endpoint metadata.
	threat := map[string]any{"name": "ustc", "url": "http://127.0.0.1:2019/config/", "format": "json"}
	crawler := map[string]any{"name": "googlebot", "url": "http://169.254.169.254/latest", "format": "plain"}

	// When running the import source gates.
	threatErr := validateImportedThreatSources([]map[string]any{threat})
	crawlerErr := validateImportedCrawlerSources([]map[string]any{crawler})

	// Then the accepted rows contain only the canonical URL and format.
	if threatErr != nil || crawlerErr != nil {
		t.Fatalf("canonical source normalization rejected built-in names: threat=%v crawler=%v", threatErr, crawlerErr)
	}
	if threat["url"] != "https://blackip.ustc.edu.cn/list.php?txt" || threat["format"] != "plain" {
		t.Errorf("threat endpoint was not canonicalized: %+v", threat)
	}
	if crawler["url"] != "https://developers.google.com/static/crawling/ipranges/common-crawlers.json" || crawler["format"] != "json" {
		t.Errorf("crawler endpoint was not canonicalized: %+v", crawler)
	}
	if err := validateImportedThreatSources([]map[string]any{{"name": "evil", "url": "https://evil.invalid", "format": "plain"}}); err == nil {
		t.Error("unknown threat source name must still be rejected")
	}
}

// U04B-03: users-only import must not run security/rule/block-page
// post-processing against tables that were not selected.
func TestImportConfigBackup_unselectedSectionsHaveNoPostProcessing(t *testing.T) {
	// Given live state that each currently unguarded post-processor would rewrite.
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	if _, err := db.DB.Exec(`INSERT INTO users (id,username,password_hash,role,is_enabled) VALUES (1,'operator','hash','admin',1);
		INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,strategy,enabled,updated_by)
			VALUES ('lb_live','live','http','live.example.test',18083,'weighted_round_robin',0,99);
		INSERT INTO security_custom_rules (id,name,conditions,action,enabled) VALUES (99,'custom','[]','block',1);
		INSERT INTO security_policies (id,name,mode,custom_rules,enabled) VALUES (7,'live-policy','off','[99]',1);
		INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (99,'lb_live','live.example.test','issued');
		UPDATE security_block_pages SET content='' WHERE id=1;
		INSERT INTO security_block_pages (id,name,content,is_default) VALUES (2,'second-default','<html>custom</html>',1)`); err != nil {
		t.Fatal(err)
	}
	body := r41BackupJSON(t, []string{"users"}, map[string][]map[string]any{
		"users": {{"id": 1, "username": "operator", "password_hash": "hash", "role": "admin", "is_enabled": 1}},
	}, map[string]any{})
	router := gin.New()
	router.POST("/config/import", func(c *gin.Context) {
		c.Set("username", "operator")
		c.Set("user_id", 1)
		c.Set("role", "admin")
		h.ImportConfigBackup(c)
	})
	request := httptest.NewRequest(http.MethodPost, "/config/import", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When importing only users.
	router.ServeHTTP(response, request)

	// Then every unselected table remains byte-for-byte in its prior state.
	if response.Code != http.StatusOK {
		t.Fatalf("users-only import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var mode, firstContent string
	var updatedBy, secondDefault, certJobs int
	if err := db.DB.QueryRow(`SELECT mode FROM security_policies WHERE id=7`).Scan(&mode); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT updated_by FROM lb_rules WHERE caddy_id='lb_live'`).Scan(&updatedBy); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT content FROM security_block_pages WHERE id=1`).Scan(&firstContent); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT is_default FROM security_block_pages WHERE id=2`).Scan(&secondDefault); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE id=99`).Scan(&certJobs); err != nil {
		t.Fatal(err)
	}
	if mode != "off" || updatedBy != 99 || firstContent != "" || secondDefault != 1 || certJobs != 1 {
		t.Fatalf("unselected state changed: mode=%q updated_by=%d first_content=%q second_default=%d cert_jobs=%d", mode, updatedBy, firstContent, secondDefault, certJobs)
	}
}

// U04B-05: v2 rule rows must pass the same health/retry/header/path/domain
// constraints as the save path after import normalization.
func TestValidateV2BackupRules_saveSideValueDomain(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "health timeout equals interval", mutate: func(r map[string]any) { r["health_check_interval"], r["health_check_timeout"] = 5, 5 }},
		{name: "retry duration above maximum", mutate: func(r map[string]any) { r["tcp_try_duration"] = 60001 }},
		{name: "retry interval above maximum", mutate: func(r map[string]any) { r["tcp_try_interval"] = 60001 }},
		{name: "host header contains CRLF", mutate: func(r map[string]any) { r["host_header"] = "backend.example\r\nX-Injected: true" }},
		{name: "health path lacks slash", mutate: func(r map[string]any) { r["health_check_path"] = "health" }},
		{name: "dns server malformed", mutate: func(r map[string]any) { r["dns_server"] = "not a dns server" }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given an otherwise valid stored-rule row.
			tables := audit79RuleTables()
			tt.mutate(tables["lb_rules"][0])

			// When / Then the import gate rejects the invalid value.
			if err := validateV2BackupRules(tables); err == nil {
				t.Fatalf("invalid rule passed import validation: %+v", tables["lb_rules"][0])
			}
		})
	}
	// Regression: the unmodified stored-rule shape remains valid.
	if err := validateV2BackupRules(audit79RuleTables()); err != nil {
		t.Fatalf("valid rule regression: %v", err)
	}
}

func TestValidateBackupRuleReferences_saveSideUpstreamValueDomain(t *testing.T) {
	tests := []struct {
		name      string
		upstreams []map[string]any
	}{
		{name: "empty host", upstreams: []map[string]any{{"rule_id": "lb_audit79", "host": "", "port": 9000, "weight": 1, "enabled": 1}}},
		{name: "invalid host", upstreams: []map[string]any{{"rule_id": "lb_audit79", "host": "bad host", "port": 9000, "weight": 1, "enabled": 1}}},
		{name: "zero port", upstreams: []map[string]any{{"rule_id": "lb_audit79", "host": "127.0.0.1", "port": 0, "weight": 1, "enabled": 1}}},
		{name: "port above range", upstreams: []map[string]any{{"rule_id": "lb_audit79", "host": "127.0.0.1", "port": 65536, "weight": 1, "enabled": 1}}},
		{name: "negative weight", upstreams: []map[string]any{{"rule_id": "lb_audit79", "host": "127.0.0.1", "port": 9000, "weight": -1, "enabled": 1}}},
		{name: "negative connections", upstreams: []map[string]any{{"rule_id": "lb_audit79", "host": "127.0.0.1", "port": 9000, "weight": 1, "max_connections": -1, "enabled": 1}}},
		{name: "duplicate host port", upstreams: []map[string]any{
			{"rule_id": "lb_audit79", "host": "127.0.0.1", "port": 9000, "weight": 1, "enabled": 1},
			{"rule_id": "lb_audit79", "host": "127.0.0.1", "port": 9000, "weight": 2, "enabled": 1},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given upstream rows owned by a valid rule.
			tables := audit79RuleTables()
			tables["upstreams"] = tt.upstreams

			// When / Then save-side upstream validation is not 绕过ed.
			if err := validateBackupRuleReferences(tables); err == nil {
				t.Fatalf("invalid upstreams passed import validation: %+v", tt.upstreams)
			}
		})
	}
	if err := validateBackupRuleReferences(audit79RuleTables()); err != nil {
		t.Fatalf("valid upstream regression: %v", err)
	}
}

func TestValidateConvertedV1Rules_saveSideValueDomain(t *testing.T) {
	base := func() convertedRule {
		return convertedRule{
			Name: "v1", Protocol: "http", Domain: "v1.example.test", ListenPort: 18084,
			Strategy: "weighted_round_robin", HealthInt: 10, HealthFails: 3, Enabled: true,
			Upstreams: []convertedUpstream{{Host: "127.0.0.1", Port: 9000, Weight: 100, Enabled: true, Protocol: "http"}},
		}
	}
	tests := []struct {
		name   string
		mutate func(*convertedRule)
	}{
		{name: "host header CRLF", mutate: func(r *convertedRule) { r.HostHeader = "backend.example\r\nX-Injected: true" }},
		{name: "duplicate upstream", mutate: func(r *convertedRule) { r.Upstreams = append(r.Upstreams, r.Upstreams[0]) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given a converted v1 rule with a save-side violation.
			rule := base()
			tt.mutate(&rule)

			// When / Then the v1 soft-skip gate rejects it before insertion.
			valid, _, _ := validateConvertedV1Rules([]convertedRule{rule})
			if len(valid) != 0 {
				t.Fatalf("invalid v1 rule passed validation: %+v", valid[0])
			}
		})
	}
	valid, skips, _ := validateConvertedV1Rules([]convertedRule{base()})
	if len(valid) != 1 || len(skips) != 0 {
		t.Fatalf("valid v1 regression: valid=%d skips=%v", len(valid), skips)
	}
}

// U04B-06: auto-backup PATCH rows must be validated after merging omitted
// frequency/day fields from the live configuration.
func TestImportAutoBackupSettings_validatesMergedLiveSchedule(t *testing.T) {
	tests := []struct {
		name       string
		liveFreq   string
		liveDay    int
		cfg        map[string]any
		wantStatus int
	}{
		{name: "live weekly plus imported day nine", liveFreq: "weekly", liveDay: 1, cfg: map[string]any{"auto_backup_day": 9}, wantStatus: http.StatusBadRequest},
		{name: "imported weekly plus live day twenty", liveFreq: "daily", liveDay: 20, cfg: map[string]any{"auto_backup_frequency": "weekly"}, wantStatus: http.StatusBadRequest},
		{name: "valid merged weekly schedule", liveFreq: "weekly", liveDay: 3, cfg: map[string]any{"auto_backup_day": 7}, wantStatus: http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given live values for the fields omitted by the backup.
			h := newBackupTestHandlers(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET auto_backup_frequency=?, auto_backup_day=? WHERE id=1`, tt.liveFreq, tt.liveDay); err != nil {
				t.Fatal(err)
			}
			body := r78BackupJSON(t, nil, tt.cfg, []string{"users"})

			// When running both preview and import.
			preview := r78ValidateResponse(t, h, body)
			response := r78Import(h, t, body)

			// Then both make the same decision about the final merged schedule.
			wantValid := tt.wantStatus == http.StatusOK
			if preview.Valid != wantValid {
				t.Errorf("preview valid=%v error=%q, want %v", preview.Valid, preview.Error, wantValid)
			}
			if response.Code != tt.wantStatus {
				t.Fatalf("import status=%d body=%s, want %d", response.Code, response.Body.String(), tt.wantStatus)
			}
		})
	}
}

// U04B-07: branding_json is a mirror, not the source of truth. Import must
// materialize the file and re-render dependent branding output.
func TestImportConfigBackup_materializesBranding(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantAppName string
	}{
		{name: "custom branding", content: `{"app_name":"Restored","footer_text":"Footer","landing_text":"New landing","version":""}`, wantAppName: "Restored"},
		{name: "empty branding resets template", content: "", wantAppName: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given an old local branding file and a default page rendered from it.
			h := newBackupTestHandlers(t)
			h.cfg.DataDir = t.TempDir()
			old := `{"app_name":"Old","landing_text":"Old landing"}`
			if err := os.WriteFile(filepath.Join(h.cfg.DataDir, "branding.json"), []byte(old), 0o644); err != nil {
				t.Fatal(err)
			}
			if _, err := db.DB.Exec(`UPDATE security_block_pages SET content='old page' WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			body := r78BackupJSON(t, nil, map[string]any{"branding_json": tt.content}, []string{"users"})

			// When importing the mirrored value and then refreshing the mirror once more.
			response := r78Import(h, t, body)
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			if _, err := services.RefreshBrandingMirror(h.cfg.DataDir); err != nil {
				t.Fatal(err)
			}

			// Then the file, DB mirror, and default page all retain the restored source value.
			raw, err := os.ReadFile(filepath.Join(h.cfg.DataDir, "branding.json"))
			if err != nil {
				t.Fatal(err)
			}
			var mirrored string
			if err := db.DB.QueryRow(`SELECT branding_json FROM global_config WHERE id=1`).Scan(&mirrored); err != nil {
				t.Fatal(err)
			}
			if tt.content != "" {
				if string(raw) != tt.content || mirrored != tt.content {
					t.Fatalf("branding not materialized: file=%q db=%q want=%q", raw, mirrored, tt.content)
				}
			} else if !json.Valid(raw) || !strings.Contains(string(raw), `"app_name": ""`) || mirrored != string(raw) {
				t.Fatalf("empty branding must become the full empty template: file=%q db=%q", raw, mirrored)
			}
			if got := loadBrandingConfig(h.cfg.DataDir).AppName; tt.wantAppName != "" && got != tt.wantAppName {
				t.Fatalf("loaded app name=%q, want %q", got, tt.wantAppName)
			}
			if tt.content != "" {
				var page string
				if err := db.DB.QueryRow(`SELECT content FROM security_block_pages WHERE id=1`).Scan(&page); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(page, tt.wantAppName) {
					t.Fatalf("default page was not re-rendered from restored branding: %q", page)
				}
			}
		})
	}
}

func TestImportConfigBackup_malformedBrandingWarnsAndKeepsFile(t *testing.T) {
	// Given a valid local file and an invalid backup mirror value.
	h := newBackupTestHandlers(t)
	h.cfg.DataDir = t.TempDir()
	old := `{"app_name":"Old","landing_text":"Old landing"}`
	path := filepath.Join(h.cfg.DataDir, "branding.json")
	if err := os.WriteFile(path, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	body := r78BackupJSON(t, nil, map[string]any{"branding_json": "not-json"}, []string{"users"})

	// When importing it.
	response := r78Import(h, t, body)

	// Then the file source and DB mirror stay on the last valid value, visibly warned.
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "品牌配置") {
		t.Fatalf("malformed branding must warn: %s", response.Body.String())
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != old {
		t.Fatalf("invalid branding replaced live file: raw=%q err=%v", raw, err)
	}
	var mirrored string
	if err := db.DB.QueryRow(`SELECT branding_json FROM global_config WHERE id=1`).Scan(&mirrored); err != nil {
		t.Fatal(err)
	}
	if mirrored != old {
		t.Fatalf("invalid branding corrupted DB mirror: %q", mirrored)
	}
}

// U04B-08: replacing crawler configuration must immediately rebuild the file
// consumed by caddygeoip, rather than waiting for restart or a later download.
func TestImportConfigBackup_rebuildsCrawlerSnapshot(t *testing.T) {
	// Given a stale runtime snapshot and a backup carrying a different crawler list.
	h := newBackupTestHandlers(t)
	audit79SeedAdmin(t)
	// B3-历史问题（历史）：go:linkname 改写 services 未导出变量 →
	// 正式测试缝 services.SetCrawlerIPListFileForTest（返回还原闭包）。
	snapshotPath := filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(services.SetCrawlerIPListFileForTest(snapshotPath))
	if err := os.WriteFile(snapshotPath, []byte(`{"googlebot":["192.0.2.0/24"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	body := r41BackupJSON(t, []string{"security"}, map[string][]map[string]any{
		"security_crawler_sources": {{"name": "googlebot", "url": "https://developers.google.com/static/crawling/ipranges/common-crawlers.json", "format": "json", "update_enabled": 1}},
		"security_ip_lists":        {{"id": 41, "name": services.CrawlerIPListName("googlebot"), "category": "搜索引擎爬虫", "entries": `[{"value":"198.51.100.0/24"}]`, "system": 1}},
	}, nil)

	// When importing the security section.
	response := postBackupImport(t, h, body)

	// Then the runtime snapshot is rebuilt from the imported DB rows.
	if response.Code != http.StatusOK {
		t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	raw, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatal(err)
	}
	if len(snapshot["googlebot"]) != 1 || snapshot["googlebot"][0] != "198.51.100.0/24" {
		t.Fatalf("crawler runtime snapshot is stale: %s", raw)
	}
}

// U04B-09: runtime retention fields follow the save-side bounds.
func TestValidateV2BackupRuntimeSettings_securityEventRetentionBounds(t *testing.T) {
	tests := []struct {
		name    string
		key     string
		value   any
		wantErr bool
	}{
		{name: "negative retention", key: "security_events_retention_days", value: -1, wantErr: true},
		{name: "excess retention", key: "security_events_retention_days", value: 3651, wantErr: true},
		{name: "fractional retention", key: "security_events_retention_days", value: 1.5, wantErr: true},
		{name: "negative row cap", key: "security_events_row_cap", value: -1, wantErr: true},
		{name: "excess row cap", key: "security_events_row_cap", value: 100000001, wantErr: true},
		{name: "non numeric row cap", key: "security_events_row_cap", value: "abc", wantErr: true},
		{name: "automatic retention", key: "security_events_retention_days", value: 0},
		{name: "maximum retention", key: "security_events_retention_days", value: 3650},
		{name: "automatic row cap", key: "security_events_row_cap", value: 0},
		{name: "maximum row cap", key: "security_events_row_cap", value: 100000000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Given / When / Then the runtime gate matches UpdateConfig.
			err := validateV2BackupRuntimeSettings(map[string]any{tt.key: tt.value}, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validation error=%v, wantErr=%v", err, tt.wantErr)
			}
		})
	}
}

func TestImportConfigBackup_normalizesRequestBodyIntegerShapes(t *testing.T) {
	for _, raw := range []any{"abc", 1.5} {
		t.Run("global "+fmt.Sprint(raw), func(t *testing.T) {
			// Given a non-integer global request-body value.
			h := newBackupTestHandlers(t)
			body := r78BackupJSON(t, nil, map[string]any{"request_body_max_size_mb": raw}, []string{"users"})

			// When importing it.
			response := r78Import(h, t, body)

			// Then the schema default is stored instead of non-integer text/REAL.
			if response.Code != http.StatusOK {
				t.Fatalf("import status=%d body=%s, want 200", response.Code, response.Body.String())
			}
			var stored int
			if err := db.DB.QueryRow(`SELECT request_body_max_size_mb FROM global_config WHERE id=1`).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored != db.DefaultRequestBodyMaxSizeMB {
				t.Fatalf("request body size=%d, want default %d", stored, db.DefaultRequestBodyMaxSizeMB)
			}
		})
	}
	for _, raw := range []any{"abc", 1.5} {
		t.Run("rule "+fmt.Sprint(raw), func(t *testing.T) {
			// Given a non-integer rule-level override.
			tables := audit79RuleTables()
			tables["lb_rules"][0]["request_body_max_size_mb"] = raw

			// When / Then import normalization restores the rule-level zero default.
			if err := validateV2BackupRules(tables); err != nil {
				t.Fatalf("rule normalization rejected non-integer shape: %v", err)
			}
			normalized, ok := tables["lb_rules"][0]["request_body_max_size_mb"].(int)
			if !ok || normalized != 0 {
				t.Fatalf("rule request body size=%v (%T), want integer 0", tables["lb_rules"][0]["request_body_max_size_mb"], tables["lb_rules"][0]["request_body_max_size_mb"])
			}
		})
	}
}

// U04B-12: all listed NOT NULL DEFAULT columns normalize explicit JSON null.
// path_rules also proves defaults are applied before match-type validation.
func TestImportConfigBackup_normalizesRemainingNullDefaults(t *testing.T) {
	t.Run("restore table defaults", func(t *testing.T) {
		// Given explicit NULLs in a transaction using the real restore helper.
		h := newBackupTestHandlers(t)
		_ = h
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port) VALUES ('lb_null','null','http','null.example.test',18085)`); err != nil {
			t.Fatal(err)
		}
		tx, err := db.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		for _, item := range []struct {
			table string
			row   map[string]any
		}{
			{table: "users", row: map[string]any{"username": "null-role", "password_hash": "hash", "role": nil, "is_enabled": 1}},
			{table: "path_rules", row: map[string]any{"rule_id": "lb_null", "sort_order": nil, "match_type": nil, "path": "/null"}},
			{table: "security_crs_version", row: map[string]any{"id": 2, "version": "v", "schedule_days": nil, "schedule_time": nil}},
			{table: "security_ip2region_version", row: map[string]any{"id": 2, "version": "v", "schedule_days": nil, "schedule_time": nil}},
		} {
			if err := restoreTable(context.Background(), tx, db.DB, item.table, []map[string]any{item.row}); err != nil {
				t.Fatalf("restore %s: %v", item.table, err)
			}
		}

		// Then every value equals its schema default.
		var role, matchType string
		var sortOrder int
		if err := tx.QueryRow(`SELECT role FROM users WHERE username='null-role'`).Scan(&role); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(`SELECT sort_order,match_type FROM path_rules WHERE rule_id='lb_null'`).Scan(&sortOrder, &matchType); err != nil {
			t.Fatal(err)
		}
		if role != "user" || sortOrder != 0 || matchType != "prefix" {
			t.Fatalf("null defaults role=%q sort=%d match=%q", role, sortOrder, matchType)
		}
		for _, table := range []string{"security_crs_version", "security_ip2region_version"} {
			var days, hhmm string
			if err := tx.QueryRow(`SELECT schedule_days,schedule_time FROM `+table+` WHERE id=2`).Scan(&days, &hhmm); err != nil {
				t.Fatal(err)
			}
			if days != "1,2,3,4,5,6,7" || hhmm != "04:00" {
				t.Fatalf("%s schedule defaults=%q/%q", table, days, hhmm)
			}
		}
	})

	t.Run("path defaults precede validation", func(t *testing.T) {
		// Given an import whose path match type and sort order are explicit NULL.
		h := newBackupTestHandlers(t)
		audit79SeedAdmin(t)
		tables := audit79RuleTables()
		tables["path_rules"] = []map[string]any{{"rule_id": "lb_audit79", "sort_order": nil, "match_type": nil, "path": "/null"}}
		tables["lb_rules"][0]["custom_routes_enabled"] = 1
		body := r41BackupJSON(t, []string{"rules"}, tables, nil)

		// When / Then both preview and import use the schema defaults, not a 400/500.
		if preview := r41PostValidate(t, h, body); !preview.Valid {
			t.Errorf("preview rejected NULL path defaults: %s", preview.Error)
		}
		if response := postBackupImport(t, h, body); response.Code != http.StatusOK {
			t.Fatalf("import rejected NULL path defaults: status=%d body=%s", response.Code, response.Body.String())
		}
	})
}

// U04B-13: JSON null is not a JSON object, while empty/object shapes retain
// their existing behavior.
func TestValidateCredentialsJSONObject_rejectsNull(t *testing.T) {
	// Given / When / Then all object/non-object shapes follow the credential contract.
	for _, raw := range []string{"null", "[]", `"text"`, "1"} {
		if err := validateCredentialsJSONObject(raw); err == nil {
			t.Errorf("credentials %s must be rejected", raw)
		}
	}
	for _, raw := range []string{"", "{}", `{"key":"value"}`} {
		if err := validateCredentialsJSONObject(raw); err != nil {
			t.Errorf("credentials %q regression: %v", raw, err)
		}
	}
}
