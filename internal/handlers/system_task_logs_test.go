package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"

	sqlitedriver "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

type certJobRetryConnector struct {
	dsn      string
	inner    driver.Driver
	failures *int
	attempts *int
	mu       *sync.Mutex
}

func (c certJobRetryConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &certJobRetryConn{Conn: conn, failures: c.failures, attempts: c.attempts, mu: c.mu}, nil
}

func (c certJobRetryConnector) Driver() driver.Driver { return c.inner }

type certJobRetryConn struct {
	driver.Conn
	failures *int
	attempts *int
	mu       *sync.Mutex
}

func (c *certJobRetryConn) Prepare(query string) (driver.Stmt, error) {
	if strings.Contains(query, "SELECT id, rule_id FROM cert_jobs") {
		c.mu.Lock()
		(*c.attempts)++
		fail := *c.failures > 0
		if fail {
			(*c.failures)--
		}
		c.mu.Unlock()
		if fail {
			return nil, errors.New("injected cert_jobs query failure")
		}
	}
	return c.Conn.Prepare(query)
}

func TestSystemTaskLogPathResolver_retriesCertJobLoadAfterFailure(t *testing.T) {
	// Given 真实 SQLite 表与一次注入的 cert_jobs 查询失败。
	failures, attempts := 1, 0
	var mu sync.Mutex
	database := sql.OpenDB(certJobRetryConnector{
		dsn: t.TempDir() + "/certjobs.db", inner: &sqlitedriver.Driver{},
		failures: &failures, attempts: &attempts, mu: &mu,
	})
	if _, err := database.Exec(`CREATE TABLE cert_jobs (id INTEGER PRIMARY KEY, rule_id TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id, rule_id) VALUES (1, 'lb_retry')`); err != nil {
		t.Fatal(err)
	}
	oldDB := db.DB
	db.DB = database
	db.SetDB(database)
	t.Cleanup(func() {
		_ = database.Close()
		db.DB = oldDB
		db.SetDB(oldDB)
	})
	resolver := &systemTaskLogPathResolver{}

	// When 首查失败，同一 resolver 立即重试。
	if got, err := resolver.resolve("cert-job:1"); err == nil || got != "" {
		t.Fatalf("first resolve path=%q err=%v, want injected failure", got, err)
	}
	got, err := resolver.resolve("cert-job:1")

	// Then 重试成功，且成功后的后续解析复用首批结果不重复查询。
	if err != nil || got != services.CertJobLogPath("lb_retry") {
		t.Fatalf("retry path=%q err=%v, want %q", got, err, services.CertJobLogPath("lb_retry"))
	}
	mu.Lock()
	attemptsAfterRetry := attempts
	mu.Unlock()
	if attemptsAfterRetry != 2 {
		t.Fatalf("cert_jobs query attempts=%d, want 2 (failed first + retry)", attemptsAfterRetry)
	}
	if gotAgain, err := resolver.resolve("cert-job:1"); err != nil || gotAgain != got {
		t.Fatalf("cached resolve path=%q err=%v, want %q", gotAgain, err, got)
	}
	mu.Lock()
	attemptsAfterCache := attempts
	mu.Unlock()
	if attemptsAfterCache != 2 {
		t.Fatalf("cert_jobs query attempts=%d after cache hit, want 2", attemptsAfterCache)
	}
}
