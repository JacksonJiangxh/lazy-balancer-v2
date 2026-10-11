package db

import (
	"database/sql"
	"testing"

	_ "github.com/glebarez/go-sqlite"
)

// 本次上游合并（2026-10-11，C1/C2 决策：切上游 origin_domain / response_mode）
// 的两处存量数据搬迁回归：先搬后删语义、显式值优先、幂等。
func TestMergeMigration_hostHeaderToOriginDomainAndActionToResponseMode(t *testing.T) {
	database, err := sql.Open("sqlite", t.TempDir()+"/merge-mig.db")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	// 遗留库形态：同时含自研旧列（host_header / action+status_code+redirect_url…）
	// 与上游新列（origin_domain / response_mode…）。
	if _, err := database.Exec(`
		CREATE TABLE upstreams (id INTEGER PRIMARY KEY, rule_id TEXT, host TEXT, port INTEGER, origin_domain TEXT NOT NULL DEFAULT '', host_header TEXT NOT NULL DEFAULT '');
		INSERT INTO upstreams (id,rule_id,host,port,host_header) VALUES (1,'r','a',1,'legacy.example');
		INSERT INTO upstreams (id,rule_id,host,port,origin_domain,host_header) VALUES (2,'r','b',2,'explicit.example','other.example');
		INSERT INTO upstreams (id,rule_id,host,port) VALUES (3,'r','c',3);
		CREATE TABLE path_rules (id INTEGER PRIMARY KEY, rule_id TEXT, response_mode TEXT NOT NULL DEFAULT '', response_status INTEGER NOT NULL DEFAULT 200, response_body TEXT NOT NULL DEFAULT '', response_content_type TEXT NOT NULL DEFAULT '', redirect_to TEXT NOT NULL DEFAULT '', action TEXT NOT NULL DEFAULT 'proxy', status_code INTEGER NOT NULL DEFAULT 0, redirect_url TEXT NOT NULL DEFAULT '', content_type TEXT NOT NULL DEFAULT '');
		INSERT INTO path_rules (id,rule_id,action,status_code,redirect_url) VALUES (1,'r','respond',302,'https://x/y');
		INSERT INTO path_rules (id,rule_id,action,status_code,response_body,content_type) VALUES (2,'r','respond',403,'<b>no</b>','text/html');
		INSERT INTO path_rules (id,rule_id,action,status_code) VALUES (3,'r','proxy',0);
	`); err != nil {
		t.Fatal(err)
	}

	oldDB := DB
	DB = database
	defer func() { DB = oldDB }()

	if err := migrateUpstreamHostHeaderToOriginDomain(); err != nil {
		t.Fatal(err)
	}
	if err := migratePathRuleActionToResponseMode(); err != nil {
		t.Fatal(err)
	}
	// 幂等：重跑零副作用。
	if err := migrateUpstreamHostHeaderToOriginDomain(); err != nil {
		t.Fatal(err)
	}
	if err := migratePathRuleActionToResponseMode(); err != nil {
		t.Fatal(err)
	}

	// host_header → origin_domain：空 origin_domain 取 host_header；显式值优先；
	// 两者皆空保持空。
	var od1, od2, od3 string
	database.QueryRow("SELECT origin_domain FROM upstreams WHERE id=1").Scan(&od1)
	database.QueryRow("SELECT origin_domain FROM upstreams WHERE id=2").Scan(&od2)
	database.QueryRow("SELECT origin_domain FROM upstreams WHERE id=3").Scan(&od3)
	if od1 != "legacy.example" || od2 != "explicit.example" || od3 != "" {
		t.Fatalf("origin_domain migration got (%q,%q,%q)", od1, od2, od3)
	}

	// action='respond' → response_mode：3xx 走 redirect 且搬目标；其余走 static
	// 且搬内容/类型；proxy 行保持空（转发）。
	var m1, r1, m2, b2, ct2, m3 string
	database.QueryRow("SELECT response_mode, redirect_to FROM path_rules WHERE id=1").Scan(&m1, &r1)
	database.QueryRow("SELECT response_mode, response_body, response_content_type FROM path_rules WHERE id=2").Scan(&m2, &b2, &ct2)
	database.QueryRow("SELECT response_mode FROM path_rules WHERE id=3").Scan(&m3)
	if m1 != "redirect" || r1 != "https://x/y" {
		t.Fatalf("redirect migration got (%q,%q)", m1, r1)
	}
	if m2 != "static" || b2 != "<b>no</b>" || ct2 != "text/html" {
		t.Fatalf("static migration got (%q,%q,%q)", m2, b2, ct2)
	}
	if m3 != "" {
		t.Fatalf("proxy row response_mode should stay empty, got %q", m3)
	}
}
