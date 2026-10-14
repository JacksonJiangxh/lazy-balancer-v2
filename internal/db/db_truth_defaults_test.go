package db

// 库值唯一真相（批 1+2）DB 侧钉测：
// ① fresh DDL DEFAULT 与治理常量一致（写死兜底废除后，DEFAULT 是默认值唯一入口）；
// ② 启动迁移幂等回填 NULL/<=0 行，用户已设有效值保留。

import (
	"fmt"
	"testing"
)

func TestFreshSchemaDefaults_MatchGovernedConstants(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	cases := []struct {
		table  string
		column string
		want   string
	}{
		{"global_config", "request_body_max_size_mb", fmt.Sprint(DefaultRequestBodyMaxSizeMB)},
		{"global_config", "http_read_timeout", fmt.Sprint(DefaultHTTPReadTimeout)},
		{"global_config", "http_write_timeout", fmt.Sprint(DefaultHTTPWriteTimeout)},
		{"global_config", "http_idle_timeout", fmt.Sprint(DefaultHTTPIdleTimeout)},
		{"global_config", "caddy_log_size_mb", fmt.Sprint(DefaultCaddyLogSizeMB)},
		{"lb_rules", "health_check_interval", fmt.Sprint(DefaultHealthCheckInterval)},
		{"lb_rules", "health_check_timeout", fmt.Sprint(DefaultHealthCheckTimeout)},
		{"lb_rules", "health_check_unhealthy_threshold", fmt.Sprint(DefaultHealthCheckUnhealthyThreshold)},
		{"lb_rules", "health_check_healthy_threshold", fmt.Sprint(DefaultHealthCheckHealthyThreshold)},
		{"lb_rules", "tcp_try_interval", fmt.Sprint(DefaultTCPTryInterval)},
		// G6（历史）：双向钉补齐——批 3 治理列此前只有消费侧 fail-visible 钉
		//（render_db_truth_test.go），DDL DEFAULT 与治理常量未双向钉。
		{"global_config", "cert_expiry_days", fmt.Sprint(DefaultCertExpiryDays)},
		{"security_policies", "anomaly_threshold", fmt.Sprint(DefaultAnomalyThreshold)},
	}
	for _, tc := range cases {
		var dflt *string
		if err := database.QueryRow(`SELECT dflt_value FROM pragma_table_info(?) WHERE name=?`, tc.table, tc.column).Scan(&dflt); err != nil {
			t.Fatalf("%s.%s: %v", tc.table, tc.column, err)
		}
		if dflt == nil || *dflt != tc.want {
			t.Fatalf("%s.%s DEFAULT=%v, want %s", tc.table, tc.column, dflt, tc.want)
		}
	}
}

func TestRunMigrationsBackfillsInvalidValueColumns(t *testing.T) {
	database := openMigrationTestDB(t)
	if err := createTables(); err != nil {
		t.Fatalf("create tables: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO global_config (id,caddy_config) VALUES (1,'{}')`); err != nil {
		t.Fatalf("seed global config: %v", err)
	}
	// G6（历史）：cert_expiry_days 回填钉（defaultUpdates 已含该列——
	// NULL/<=0 归 DefaultCertExpiryDays；用户已设有效值保留）。
	if _, err := database.Exec("UPDATE global_config SET cert_expiry_days=0"); err != nil {
		t.Fatalf("zero cert_expiry_days: %v", err)
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
	// G6（历史）：cert_expiry_days 回填归 DefaultCertExpiryDays。
	assertScalar("SELECT cert_expiry_days FROM global_config WHERE id=1", DefaultCertExpiryDays)
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
