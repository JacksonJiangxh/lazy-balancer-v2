package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// 历史修复 follow-up: snapshot writers may run concurrently (crawler task and
// backup import). A fixed ".tmp" sibling can collide; staging must be unique.
func TestWriteCrawlerIPListSnapshotAll_usesUniqueTemporaryFile(t *testing.T) {
	// Given the legacy fixed temp path occupied by an unrelated directory.
	oldPath := crawlerIPListFile
	crawlerIPListFile = filepath.Join(t.TempDir(), "crawler-ip-lists.json")
	t.Cleanup(func() { crawlerIPListFile = oldPath })
	if err := os.Mkdir(crawlerIPListFile+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}

	// When writing the runtime snapshot.
	if err := writeCrawlerIPListSnapshotAll(map[string][]string{"googlebot": {"198.51.100.0/24"}}); err != nil {
		t.Fatalf("snapshot write must not depend on the fixed .tmp path: %v", err)
	}

	// Then a complete JSON snapshot is atomically installed.
	raw, err := os.ReadFile(crawlerIPListFile)
	if err != nil {
		t.Fatal(err)
	}
	var snapshot map[string][]string
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("invalid snapshot JSON: %v (%s)", err, raw)
	}
	if len(snapshot["googlebot"]) != 1 || snapshot["googlebot"][0] != "198.51.100.0/24" {
		t.Fatalf("snapshot=%v", snapshot)
	}
}
