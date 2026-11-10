package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 出厂引导配置存在两份逐字内容：config/Caddyfile（镜像内出厂文件，入口挂载
// 空目录时由它提供基线）与 docker-entrypoint.sh 的 heredoc（挂载覆盖后补写）。
// 同构性此前只由注释保证——heredoc 或文件单侧漂移（例如丢掉 metrics 块）会让
// 「空 /app/config 挂载」的部署静默失去指标采集，且不存在任何门禁会报。
const bootstrapHeredocMarker = "CADDYFILE"

// normalizeConfigLines 归一化比对口径：去行尾空白、去行首空格（heredoc 体可能
// 因脚本缩进多出空格），保留 TAB（Caddyfile 块缩进语义），丢弃空行与注释行
// ——注释属于各自的宿主文件（shell 侧已有自己的注释），同构性只约束配置内容。
func normalizeConfigLines(text string) []string {
	lines := make([]string, 0, 16)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimRight(line, " \t\r")
		line = strings.TrimLeft(line, " ")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}

// entrypointHeredoc 截取 <<'MARKER' 到独立定界行之间的内容。
func entrypointHeredoc(t *testing.T, text, marker string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	start := -1
	for index, line := range lines {
		if strings.Contains(line, "<<'"+marker+"'") || strings.Contains(line, "<<\""+marker+"\"") {
			start = index + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("docker-entrypoint.sh 未找到 heredoc 定界符 %s", marker)
	}
	body := make([]string, 0, 16)
	for index := start; index < len(lines); index++ {
		if strings.TrimSpace(lines[index]) == marker {
			return strings.Join(body, "\n")
		}
		body = append(body, lines[index])
	}
	t.Fatalf("docker-entrypoint.sh 的 heredoc %s 未闭合", marker)
	return ""
}

func TestBootstrapCaddyfileMatchesEntrypointHeredoc(t *testing.T) {
	root := filepath.Join("..", "..")
	fileBytes, err := os.ReadFile(filepath.Join(root, "config", "Caddyfile"))
	if err != nil {
		t.Fatalf("读取出厂引导配置失败: %v", err)
	}
	scriptBytes, err := os.ReadFile(filepath.Join(root, "docker-entrypoint.sh"))
	if err != nil {
		t.Fatalf("读取 entrypoint 失败: %v", err)
	}

	want := normalizeConfigLines(string(fileBytes))
	got := normalizeConfigLines(entrypointHeredoc(t, string(scriptBytes), bootstrapHeredocMarker))

	if len(want) == 0 {
		t.Fatal("config/Caddyfile 为空——出厂引导配置至少需要 admin 与 metrics 两段")
	}
	if len(want) != len(got) {
		t.Fatalf("引导配置行数不一致: config/Caddyfile=%d entrypoint heredoc=%d\n文件: %q\nheredoc: %q",
			len(want), len(got), want, got)
	}
	for index := range want {
		if want[index] != got[index] {
			t.Fatalf("引导配置第 %d 行不一致: config/Caddyfile=%q entrypoint heredoc=%q",
				index+1, want[index], got[index])
		}
	}
}
