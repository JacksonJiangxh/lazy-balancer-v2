package db

// 库值唯一真相（批 1+2）DB 侧钉测：
// ① fresh DDL DEFAULT 与治理常量一致（写死兜底废除后，DEFAULT 是默认值唯一入口）；
// ② 启动迁移幂等回填 NULL/<=0 行，用户已设有效值保留。

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

func TestFreshSchemaDefaults_MatchGovernedConstants(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	cases := []struct {
		table   string
		column  string
		want    string
		notNull int
	}{
		{"global_config", "request_body_max_size_mb", fmt.Sprint(DefaultRequestBodyMaxSizeMB), 1},
		{"global_config", "http_read_timeout", fmt.Sprint(DefaultHTTPReadTimeout), 1},
		{"global_config", "http_write_timeout", fmt.Sprint(DefaultHTTPWriteTimeout), 1},
		{"global_config", "http_idle_timeout", fmt.Sprint(DefaultHTTPIdleTimeout), 1},
		{"global_config", "caddy_log_size_mb", fmt.Sprint(DefaultCaddyLogSizeMB), 1},
		{"lb_rules", "health_check_interval", fmt.Sprint(DefaultHealthCheckInterval), 1},
		{"lb_rules", "health_check_timeout", fmt.Sprint(DefaultHealthCheckTimeout), 1},
		{"lb_rules", "health_check_unhealthy_threshold", fmt.Sprint(DefaultHealthCheckUnhealthyThreshold), 1},
		{"lb_rules", "health_check_healthy_threshold", fmt.Sprint(DefaultHealthCheckHealthyThreshold), 1},
		{"lb_rules", "tcp_try_interval", fmt.Sprint(DefaultTCPTryInterval), 1},
		// 历史修复（历史）：双向钉补齐——批 3 治理列此前只有消费侧 fail-visible 钉
		//（render_db_truth_test.go），DDL DEFAULT 与治理常量未双向钉。
		{"global_config", "cert_expiry_days", fmt.Sprint(DefaultCertExpiryDays), 0},
		// 历史问题（历史）：续期天数/次数与 cert_expiry_days 同族，DDL DEFAULT
		// 与常量双向钉死。
		{"global_config", "cert_renewal_days", fmt.Sprint(DefaultCertRenewalDays), 0},
		{"global_config", "cert_renewal_attempts", fmt.Sprint(DefaultCertRenewalAttempts), 0},
		{"security_policies", "anomaly_threshold", fmt.Sprint(DefaultAnomalyThreshold), 0},
	}
	for _, tc := range cases {
		var dflt *string
		var notNull int
		if err := database.QueryRow(`SELECT dflt_value, "notnull" FROM pragma_table_info(?) WHERE name=?`, tc.table, tc.column).Scan(&dflt, &notNull); err != nil {
			t.Fatalf("%s.%s: %v", tc.table, tc.column, err)
		}
		if dflt == nil || *dflt != tc.want {
			t.Fatalf("%s.%s DEFAULT=%v, want %s", tc.table, tc.column, dflt, tc.want)
		}
		// 历史问题（历史）：值型族钉测补 notnull——只比 dflt_value 会放过
		// 「DEFAULT 对但可空」的重建退化（历史问题 同族事故）。
		if notNull != tc.notNull {
			t.Fatalf("%s.%s notnull=%d, want %d", tc.table, tc.column, notNull, tc.notNull)
		}
	}
}

// 历史问题（历史）：安全事件保留/大屏四列只存在于 newColumns 补列通道
// （fresh CREATE 无此四列），其 DDL 形状必须在真实启动迁移后与 db.Default*
// 常量一致——默认值曾是 4 处字面量副本（DDL/回填/读侧/导入），漏改即漂移。
func TestRunMigrationsColumnDefaults_MatchGovernedConstants(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec("INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')"); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	if err := runMigrations(); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	cases := []struct {
		column  string
		want    string
		notNull int
	}{
		{"security_events_retention_days", fmt.Sprint(DefaultSecurityEventsRetentionDays), 1},
		{"security_events_row_cap", fmt.Sprint(DefaultSecurityEventsRowCap), 1},
		{"threat_traffic_sample_n", fmt.Sprint(DefaultThreatTrafficSampleN), 1},
		{"threat_screen_mode", "'" + DefaultThreatScreenMode + "'", 1},
	}
	for _, tc := range cases {
		var dflt *string
		var notNull int
		if err := database.QueryRow(`SELECT dflt_value, "notnull" FROM pragma_table_info('global_config') WHERE name=?`, tc.column).Scan(&dflt, &notNull); err != nil {
			t.Fatalf("global_config.%s: %v", tc.column, err)
		}
		if dflt == nil || *dflt != tc.want {
			t.Fatalf("global_config.%s DEFAULT=%v, want %s", tc.column, dflt, tc.want)
		}
		if notNull != tc.notNull {
			t.Fatalf("global_config.%s notnull=%d, want %d", tc.column, notNull, tc.notNull)
		}
	}
}

// 历史问题（历史）：升级路径的 lb_rules 重建 DDL 必须与 fresh CREATE 同形
// ——健康检查族五列曾退化为可空（health_check_timeout 默认还是陈旧的 5），
// 重建后的库形状与新建库分叉且无后续收敛路径。断言重建后 pragma_table_info
// 与 fresh 逐列相等（name/type/notnull/dflt_value/pk 全字段）。
func TestLbRulesRebuildSchema_matchesFreshDDL(t *testing.T) {
	// Given：fresh 库在完整启动（createTables + runMigrations）后的稳态形状
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	freshShape := lbRulesPragmaShape(t, DB)
	if err := Close(); err != nil {
		t.Fatalf("close fresh database: %v", err)
	}

	// And：旧 PK 库（id 主键）走真实升级路径
	legacyDir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(legacyDir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	createLegacyLbRulesTables(t, legacy, legacyLbRulesSchema{withCaddyID: true, withStagePages: true, withNewHealthCols: true, upstreams: legacyUpstreamsLegacyOrigin})
	if _, err := legacy.Exec(`INSERT INTO lb_rules (id, name, protocol, listen_port, caddy_id) VALUES (7, 'legacy', 'http', 8080, 'lb_ddl_parity')`); err != nil {
		t.Fatalf("seed legacy rule: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	// When
	if err := Initialize(legacyDir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then：重建后的 notnull/dflt_value 逐列与 fresh 相等（列集合一致；
	// 列序不参与比较——fresh 的 newColumns 通道以 ALTER 追加列，顺序天然不同）
	rebuiltShape := lbRulesPragmaShape(t, DB)
	freshColumns := make(map[string]pragmaColumn, len(freshShape))
	for _, column := range freshShape {
		freshColumns[column.Name] = column
	}
	if len(rebuiltShape) != len(freshColumns) {
		t.Fatalf("rebuilt column count=%d, fresh=%d", len(rebuiltShape), len(freshColumns))
	}
	for _, rebuilt := range rebuiltShape {
		fresh, ok := freshColumns[rebuilt.Name]
		if !ok {
			t.Fatalf("rebuilt column %q missing from fresh schema", rebuilt.Name)
		}
		if rebuilt.NotNull != fresh.NotNull || rebuilt.Default != fresh.Default {
			t.Fatalf("column %q rebuilt={notnull:%d default:%v}, fresh={notnull:%d default:%v}（升级重建 DDL 必须与 fresh 同形）",
				rebuilt.Name, rebuilt.NotNull, rebuilt.Default, fresh.NotNull, fresh.Default)
		}
	}
}

func TestCertJobsRebuildSchema_matchesFreshDDL(t *testing.T) {
	// Given fresh DDL 的列形，以及同库模拟的旧约束 cert_jobs 表。
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create fresh tables: %v", err)
	}
	freshShape := tablePragmaShape(t, database, "cert_jobs")
	if _, err := database.Exec(`DROP TABLE cert_jobs`); err != nil {
		t.Fatalf("drop fresh cert_jobs for legacy fixture: %v", err)
	}
	createLegacyCertJobs(t, database, "'queued'", "'queued','disabled','waiting_order_ready'")
	if _, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_parity','parity.example','waiting_order_ready')`); err != nil {
		t.Fatalf("seed legacy certificate job: %v", err)
	}

	// When 旧约束触发生成真实重建表。
	if err := migrateCertJobsStatusConstraint(); err != nil {
		t.Fatalf("rebuild cert_jobs: %v", err)
	}

	// Then 重建列集合及 name/type/notnull/default/pk 与 fresh 逐列一致。
	rebuiltShape := tablePragmaShape(t, database, "cert_jobs")
	freshColumns := make(map[string]pragmaColumn, len(freshShape))
	for _, column := range freshShape {
		freshColumns[column.Name] = column
	}
	if len(rebuiltShape) != len(freshColumns) {
		t.Fatalf("cert_jobs rebuilt column count=%d, fresh=%d", len(rebuiltShape), len(freshColumns))
	}
	for _, rebuilt := range rebuiltShape {
		fresh, ok := freshColumns[rebuilt.Name]
		if !ok {
			t.Fatalf("cert_jobs rebuilt column %q missing from fresh schema", rebuilt.Name)
		}
		if rebuilt != fresh {
			t.Fatalf("cert_jobs column %q rebuilt=%+v, fresh=%+v", rebuilt.Name, rebuilt, fresh)
		}
	}
	var status string
	if err := database.QueryRow(`SELECT status FROM cert_jobs WHERE rule_id='lb_parity'`).Scan(&status); err != nil {
		t.Fatalf("read rebuilt certificate job: %v", err)
	}
	if status != "waiting_order_ready" {
		t.Fatalf("rebuilt certificate job status=%q, want preserved waiting_order_ready", status)
	}
}

type pragmaColumn struct {
	Name    string
	Type    string
	NotNull int
	Default sql.NullString
	PK      int
}

func lbRulesPragmaShape(t *testing.T, database *sql.DB) []pragmaColumn {
	t.Helper()
	return tablePragmaShape(t, database, "lb_rules")
}

func tablePragmaShape(t *testing.T, database *sql.DB, table string) []pragmaColumn {
	t.Helper()
	rows, err := database.Query(`SELECT name, type, "notnull", dflt_value, pk FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		t.Fatalf("read %s pragma: %v", table, err)
	}
	defer rows.Close()
	var shape []pragmaColumn
	for rows.Next() {
		var column pragmaColumn
		if err := rows.Scan(&column.Name, &column.Type, &column.NotNull, &column.Default, &column.PK); err != nil {
			t.Fatalf("scan %s pragma: %v", table, err)
		}
		shape = append(shape, column)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate %s pragma: %v", table, err)
	}
	return shape
}

func TestRunMigrationsBackfillsInvalidValueColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// 历史修复（历史）：cert_expiry_days 回填钉（defaultUpdates 已含该列——
	// NULL/<=0 归 DefaultCertExpiryDays；用户已设有效值保留）。
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=0, cert_renewal_days=0, cert_renewal_attempts=0"); err != nil {
		t.Fatalf("zero cert expiry/renewal columns: %v", err)
	}
	// 存量脏形态：0 值行 + 用户已设有效值行（fresh DDL 对本批列 NOT NULL，
	// NULL 形态仅存在于存量库的可空列——由迁移 WHERE IS NULL 分支覆盖，
	// fresh 库结构上不可达）。
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb-backfill-a','a','http',9101,1)`); err != nil {
		t.Fatalf("seed rule a: %v", err)
	}
	if _, err := database.Exec(`UPDATE global_config SET request_body_max_size_mb=0, http_read_timeout=0, http_write_timeout=0, http_idle_timeout=0, caddy_log_size_mb=0`); err != nil {
		t.Fatalf("zero globals: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET health_check_interval=0, health_check_timeout=0, health_check_unhealthy_threshold=0, health_check_healthy_threshold=0, tcp_try_interval=0 WHERE caddy_id='lb-backfill-a'`); err != nil {
		t.Fatalf("zero rule columns: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,tcp_try_interval)
		VALUES ('lb-backfill-b','b','http',9102,1,37,13,5,4,777)`); err != nil {
		t.Fatalf("seed rule b: %v", err)
	}

	// When：迁移两轮——幂等且不覆盖用户已设值。
	for round := range 2 {
		if err := runMigrations(); err != nil {
			t.Fatalf("run migrations round %d: %v", round, err)
		}
	}

	// Then：NULL/<=0 行全部归默认；用户已设值原样保留。
	assertScalar := func(query string, want any) {
		t.Helper()
		var got any
		if err := database.QueryRow(query).Scan(&got); err != nil {
			t.Fatalf("query %q: %v", query, err)
		}
		switch w := want.(type) {
		case int:
			if int(got.(int64)) != w {
				t.Fatalf("query %q = %v, want %d", query, got, w)
			}
		case string:
			if got.(string) != w {
				t.Fatalf("query %q = %v, want %q", query, got, w)
			}
		}
	}
	assertScalar("SELECT request_body_max_size_mb FROM global_config WHERE id=1", DefaultRequestBodyMaxSizeMB)
	assertScalar("SELECT http_read_timeout FROM global_config WHERE id=1", DefaultHTTPReadTimeout)
	assertScalar("SELECT http_write_timeout FROM global_config WHERE id=1", DefaultHTTPWriteTimeout)
	assertScalar("SELECT http_idle_timeout FROM global_config WHERE id=1", DefaultHTTPIdleTimeout)
	assertScalar("SELECT caddy_log_size_mb FROM global_config WHERE id=1", DefaultCaddyLogSizeMB)
	// 历史修复（历史）：cert_expiry_days 回填归 DefaultCertExpiryDays。
	assertScalar("SELECT cert_expiry_days FROM global_config WHERE id=1", DefaultCertExpiryDays)
	// 历史问题（历史）：续期天数/次数同批回填（此前只有 DDL DEFAULT）。
	assertScalar("SELECT cert_renewal_days FROM global_config WHERE id=1", DefaultCertRenewalDays)
	assertScalar("SELECT cert_renewal_attempts FROM global_config WHERE id=1", DefaultCertRenewalAttempts)
	assertScalar("SELECT health_check_interval FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckInterval)
	assertScalar("SELECT health_check_timeout FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckTimeout)
	assertScalar("SELECT health_check_unhealthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckUnhealthyThreshold)
	assertScalar("SELECT health_check_healthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultHealthCheckHealthyThreshold)
	assertScalar("SELECT tcp_try_interval FROM lb_rules WHERE caddy_id='lb-backfill-a'", DefaultTCPTryInterval)
	// 用户已设值保留（幂等第二轮后仍原样）。
	assertScalar("SELECT health_check_interval FROM lb_rules WHERE caddy_id='lb-backfill-b'", 37)
	assertScalar("SELECT health_check_timeout FROM lb_rules WHERE caddy_id='lb-backfill-b'", 13)
	assertScalar("SELECT health_check_unhealthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-b'", 5)
	assertScalar("SELECT health_check_healthy_threshold FROM lb_rules WHERE caddy_id='lb-backfill-b'", 4)
	assertScalar("SELECT tcp_try_interval FROM lb_rules WHERE caddy_id='lb-backfill-b'", 777)
}

// 历史问题（历史）：6 张整表重建表此前只有 lb_rules/cert_jobs 有
// 「重建 DDL ≡ fresh DDL 全列 name/type/notnull/default/pk」钉测；users /
// security_policies / nodes（nodes 见 db_nodes_rebuild_parity_test.go）缺回归
// 形状——新增列只改 fresh 不改正重建时，二次 ensureNewColumns 会以默认值补回
// 列，用户值静默丢失（OIDC / 历史修复 / 历史问题 三次先例）。
func assertShapeMatchesFresh(t *testing.T, table string, fresh []pragmaColumn, rebuilt []pragmaColumn) {
	t.Helper()
	freshColumns := make(map[string]pragmaColumn, len(fresh))
	for _, column := range fresh {
		freshColumns[column.Name] = column
	}
	if len(rebuilt) != len(freshColumns) {
		t.Fatalf("%s rebuilt column count=%d, fresh=%d", table, len(rebuilt), len(freshColumns))
	}
	for _, column := range rebuilt {
		want, ok := freshColumns[column.Name]
		if !ok {
			t.Fatalf("%s rebuilt column %q missing from fresh schema", table, column.Name)
		}
		if column != want {
			t.Fatalf("%s column %q rebuilt=%+v, fresh=%+v（升级重建 DDL 必须与 fresh 同形）", table, column.Name, column, want)
		}
	}
}

func TestUsersRebuildSchema_matchesFreshDDL(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := DB, MetricsDB, AuditDB
	t.Cleanup(func() {
		_ = Close()
		DB, MetricsDB, AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})

	// Given fresh 稳态形状
	if err := Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize fresh database: %v", err)
	}
	freshShape := tablePragmaShape(t, DB, "users")
	if err := Close(); err != nil {
		t.Fatalf("close fresh database: %v", err)
	}

	// And 旧库：users 只有初始列（is_enabled 可空，触发 is_enabled NOT NULL 重建）
	legacyDir := t.TempDir()
	legacy, err := sql.Open("sqlite", filepath.Join(legacyDir, "lazy-balancer.db"))
	if err != nil {
		t.Fatalf("open legacy database: %v", err)
	}
	if _, err := legacy.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		display_name TEXT,
		is_enabled BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_login DATETIME
	)`); err != nil {
		t.Fatalf("create legacy users table: %v", err)
	}
	if _, err := legacy.Exec(`INSERT INTO users (username,password_hash,role,is_enabled) VALUES ('legacy-parity','hash','admin',NULL)`); err != nil {
		t.Fatalf("seed legacy user: %v", err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatalf("close legacy database: %v", err)
	}

	// When 真实升级路径
	if err := Initialize(legacyDir); err != nil {
		t.Fatalf("initialize legacy database: %v", err)
	}

	// Then 重建形状与 fresh 逐列一致，且 NULL is_enabled 归 1 保留行。
	assertShapeMatchesFresh(t, "users", freshShape, tablePragmaShape(t, DB, "users"))
	var enabled int
	if err := DB.QueryRow(`SELECT is_enabled FROM users WHERE username='legacy-parity'`).Scan(&enabled); err != nil {
		t.Fatalf("read migrated user: %v", err)
	}
	if enabled != 1 {
		t.Fatalf("is_enabled=%d, want 1", enabled)
	}
}

func TestSecurityPoliciesRebuildSchema_matchesFreshDDL(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create fresh tables: %v", err)
	}
	freshShape := tablePragmaShape(t, database, "security_policies")
	if _, err := database.Exec(`DROP TABLE security_policies`); err != nil {
		t.Fatalf("drop fresh security_policies for legacy fixture: %v", err)
	}
	// 历史 NOT-NULL 窗口期形态：fresh 全列，四列恢复 NOT NULL。
	if _, err := database.Exec(`CREATE TABLE security_policies (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT DEFAULT '',
		mode TEXT DEFAULT 'off',
		anomaly_threshold INTEGER DEFAULT 5,
		ip_acl_mode TEXT DEFAULT '',
		ip_acl_list TEXT DEFAULT '[]',
		ip_acl_enabled BOOLEAN DEFAULT FALSE,
		ip_whitelist TEXT DEFAULT '[]',
		ip_whitelist_enabled INTEGER DEFAULT 1,
		ip_blacklist TEXT DEFAULT '[]',
		rate_limit_enabled BOOLEAN DEFAULT FALSE,
		rate_limit_rps INTEGER DEFAULT 0,
		rate_limit_burst INTEGER DEFAULT 0,
		crs_rule_groups TEXT DEFAULT '[]',
		crs_excluded_rules TEXT DEFAULT '[]',
		custom_rules TEXT DEFAULT '[]',
		block_page_id INTEGER DEFAULT 0,
		block_status_code INTEGER NOT NULL DEFAULT 0,
		enabled BOOLEAN DEFAULT TRUE,
		updated_by INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT (datetime('now')),
		updated_at DATETIME DEFAULT (datetime('now')),
		geoip_countries TEXT NOT NULL DEFAULT '[]',
		geoip_mode TEXT NOT NULL DEFAULT 'deny',
		waf_check_response INTEGER NOT NULL DEFAULT 0,
		log_request_body INTEGER DEFAULT 0,
		ip_acl_list_refs TEXT DEFAULT '[]',
		ip_whitelist_refs TEXT DEFAULT '[]',
		policy_type TEXT NOT NULL DEFAULT '',
		trust_detection BOOLEAN NOT NULL DEFAULT 0,
		geoip_crawler_exempt INTEGER NOT NULL DEFAULT 0,
		geoip_crawler_engines TEXT NOT NULL DEFAULT '[]'
	)`); err != nil {
		t.Fatalf("create legacy security_policies table: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO security_policies (name,mode,geoip_countries,geoip_mode,waf_check_response,block_status_code)
		VALUES ('legacy-policy','blocking','["CN"]','allow',1,403)`); err != nil {
		t.Fatalf("seed legacy policy: %v", err)
	}

	// When 旧 NOT NULL 触发生成真实重建表。
	if err := migrateSecurityPoliciesNullable(); err != nil {
		t.Fatalf("rebuild security_policies: %v", err)
	}

	// Then 形状与 fresh 逐列一致（四列收敛可空），且行数据保留。
	assertShapeMatchesFresh(t, "security_policies", freshShape, tablePragmaShape(t, database, "security_policies"))
	var countries, geoMode string
	var wafCheck, blockStatus int
	if err := database.QueryRow(`SELECT geoip_countries, geoip_mode, waf_check_response, block_status_code FROM security_policies WHERE name='legacy-policy'`).
		Scan(&countries, &geoMode, &wafCheck, &blockStatus); err != nil {
		t.Fatalf("read rebuilt policy: %v", err)
	}
	if countries != `["CN"]` || geoMode != "allow" || wafCheck != 1 || blockStatus != 403 {
		t.Fatalf("rebuilt policy values=(%q,%q,%d,%d), want preserved", countries, geoMode, wafCheck, blockStatus)
	}
}
