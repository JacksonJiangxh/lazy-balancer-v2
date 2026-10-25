package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 协调协议的四条路径（pause / 监督器 pid / 启动回放标记 / 重启触发）在
// docker-entrypoint.sh 与 Go 侧各有一份字面量——单侧改动会让协作链静默
// 失配（supervisorAlive 恒 false → 双启抢 admin/监听口；回放标记失配 →
// 启动竞态复活旧 LKG 覆盖新配置；触发文件失配 → 崩溃自愈停摆）。
// 每条路径除取值相等外，还断言 entrypoint 的写入与清理两侧都在场。
func TestHandlerCaddyCoordinationPathsMatchEntrypoint(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "docker-entrypoint.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	cases := []struct {
		name  string
		path  string
		clues []string
	}{
		{
			name:  "pause",
			path:  caddyPauseFile,
			clues: []string{"CADDY_PAUSE_FILE=" + caddyPauseFile, `[ -f "$CADDY_PAUSE_FILE" ]`},
		},
		{
			name:  "supervisor pid",
			path:  caddySupervisorPidFile,
			clues: []string{"rm -f " + caddySupervisorPidFile, "echo $! > " + caddySupervisorPidFile},
		},
		{
			name:  "startup replay marker",
			path:  caddyStartupReplayMarkerFile,
			clues: []string{"CADDY_STARTUP_REPLAY_DONE=" + caddyStartupReplayMarkerFile, `rm -f "$CADDY_STARTUP_REPLAY_DONE"`, `: > "$CADDY_STARTUP_REPLAY_DONE"`},
		},
		{
			name:  "restart trigger",
			path:  caddyRestartTriggerFile,
			clues: []string{"echo restarted > " + caddyRestartTriggerFile},
		},
	}
	for _, tc := range cases {
		if tc.path == "" {
			t.Fatalf("%s: Go 侧路径为空", tc.name)
		}
		for _, clue := range tc.clues {
			if !strings.Contains(script, clue) {
				t.Fatalf("%s: entrypoint 缺少 %q（Go 侧路径 %s 失配）", tc.name, clue, tc.path)
			}
		}
	}
}

// caddyLogTypes 必须与路径表保持一一对应：未知类型的 400 文案直接
// 消费该枚举，第二份手写清单会在新增日志类型时漂移（路径有值、文案漏项）。
func TestCaddyLogTypes_matchLogPaths(t *testing.T) {
	if len(caddyLogTypes) != len(caddyLogPaths) {
		t.Fatalf("caddyLogTypes=%v 与 caddyLogPaths %d 键数量不一致", caddyLogTypes, len(caddyLogPaths))
	}
	seen := make(map[string]bool, len(caddyLogTypes))
	for _, logType := range caddyLogTypes {
		if seen[logType] {
			t.Fatalf("caddyLogTypes 重复条目 %q: %v", logType, caddyLogTypes)
		}
		seen[logType] = true
		if path, ok := caddyLogPaths[logType]; !ok || path == "" {
			t.Fatalf("caddyLogTypes 条目 %q 在 caddyLogPaths 中无路径", logType)
		}
	}
}
