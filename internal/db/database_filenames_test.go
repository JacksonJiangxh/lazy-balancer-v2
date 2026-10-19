package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseFilenameConstants_matchRealInitializedFiles(t *testing.T) {
	oldAuditDB, oldMetricsDB := AuditDB, MetricsDB
	t.Cleanup(func() {
		if AuditDB != nil && AuditDB != oldAuditDB {
			_ = AuditDB.Close()
		}
		if MetricsDB != nil && MetricsDB != oldMetricsDB {
			_ = MetricsDB.Close()
		}
		AuditDB, MetricsDB = oldAuditDB, oldMetricsDB
	})
	dataDir := t.TempDir()
	if err := InitializeAuditDB(dataDir); err != nil {
		t.Fatalf("initialize audit database: %v", err)
	}
	if err := InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}

	for _, tc := range []struct {
		name string
		want string
	}{
		{name: AuditDBFilename, want: "lazy-balancer-audit.db"},
		{name: MetricsDBFilename, want: "lazy-balancer-metrics.db"},
	} {
		if tc.name != tc.want {
			t.Fatalf("filename constant=%q, want stable external name %q", tc.name, tc.want)
		}
		if filepath.Base(tc.name) != tc.name || filepath.Ext(tc.name) != ".db" {
			t.Fatalf("filename constant %q must be a bare .db filename", tc.name)
		}
		info, err := os.Stat(filepath.Join(dataDir, tc.name))
		if err != nil {
			t.Fatalf("real initialized database %q: %v", tc.name, err)
		}
		if !info.Mode().IsRegular() {
			t.Fatalf("initialized database %q is not a regular file", tc.name)
		}
	}
}
