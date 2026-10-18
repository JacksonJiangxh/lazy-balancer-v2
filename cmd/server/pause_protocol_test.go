package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 三方 pause 路径必须同值：main / handlers / entrypoint shell。
func TestCaddyPausePathMatchesEntrypoint(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docker-entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "CADDY_PAUSE_FILE="+caddyPauseFilePath) {
		t.Fatalf("entrypoint CADDY_PAUSE_FILE 与 main caddyPauseFilePath 不一致: %s", caddyPauseFilePath)
	}
}
