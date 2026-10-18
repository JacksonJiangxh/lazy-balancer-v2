package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHandlerCaddyPausePathMatchesEntrypoint(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docker-entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "CADDY_PAUSE_FILE="+caddyPauseFile) {
		t.Fatalf("entrypoint CADDY_PAUSE_FILE 与 handlers caddyPauseFile 不一致: %s", caddyPauseFile)
	}
}
