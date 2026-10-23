package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// 启动协调协议的两个标记路径各有多份字面量：entrypoint 的 shell 变量与
// handlers 包的包级 var（pause 另有 main 包的包级 var）。任一侧改路径都不会
// 编译失败——只会在运行期表现为「标记永不出现/永不消除」，故用测试机械比对。
//
// handlers 不得反向依赖 main（包边界），测试侧只能读源码常量：AST 读 var 值 +
// 文本读 shell 赋值，零新增机制。
func handlersStringVar(t *testing.T, path, name string) string {
	t.Helper()
	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	got := ""
	found := false
	ast.Inspect(parsed, func(node ast.Node) bool {
		decl, ok := node.(*ast.GenDecl)
		if !ok || (decl.Tok != token.VAR && decl.Tok != token.CONST) {
			return true
		}
		for _, spec := range decl.Specs {
			valueSpec, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, ident := range valueSpec.Names {
				if ident.Name != name || index >= len(valueSpec.Values) {
					continue
				}
				literal, ok := valueSpec.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote %s: %v", name, err)
				}
				got = value
				found = true
			}
		}
		return true
	})
	if !found {
		t.Fatalf("%s 未找到字符串常量 %s", path, name)
	}
	return got
}

// entrypointAssignment 读 docker-entrypoint.sh 里 NAME=<value> 赋值的值
// （去掉包裹引号）——与 handlers 侧字面量同口径比对。
func entrypointAssignment(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join("..", "..", "docker-entrypoint.sh")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	prefix := name + "="
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, prefix) {
			return strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, prefix)), "\"'")
		}
	}
	t.Fatalf("%s 未找到 %s 赋值", path, name)
	return ""
}

func handlersCaddySource(t *testing.T) string {
	t.Helper()
	return filepath.Join("..", "..", "internal", "handlers", "caddy.go")
}

// 三方 pause 路径必须同值：main / handlers / entrypoint shell。
func TestCaddyPausePathMatchesEntrypoint(t *testing.T) {
	if got := entrypointAssignment(t, "CADDY_PAUSE_FILE"); got != caddyPauseFilePath {
		t.Fatalf("entrypoint CADDY_PAUSE_FILE=%q 与 main caddyPauseFilePath=%q 不一致", got, caddyPauseFilePath)
	}
}

// 测试注释声明「main / handlers / entrypoint 三方同值」，此处用 AST 读取
// handlers 包常量的值，保持第三方机械校验（该不变量已发生过路径同步事故）。
func TestCaddyPausePathMatchesHandlers(t *testing.T) {
	if got := handlersStringVar(t, handlersCaddySource(t), "caddyPauseFile"); got != caddyPauseFilePath {
		t.Fatalf("handlers caddyPauseFile=%q 与 main caddyPauseFilePath=%q 不一致", got, caddyPauseFilePath)
	}
}

// 启动回放标记（监督器 reapply_last_good 尾部写 → app waitStartupReplayDone
// 先等它再应用配置）：main 包不持有该路径（停机路径无需它），故比对两侧——
// entrypoint 的 CADDY_STARTUP_REPLAY_DONE 与 handlers 的
// caddyStartupReplayMarkerFile。漂移后果：标记永不出现 → 每次启动面板被扣押
// 到超时（30s）后才应用配置，且「回放→标记→应用」的时序保护失效，迟到的
// LKG 回放可覆盖新配置。
func TestCaddyStartupReplayMarkerMatchesEntrypoint(t *testing.T) {
	want := handlersStringVar(t, handlersCaddySource(t), "caddyStartupReplayMarkerFile")
	if got := entrypointAssignment(t, "CADDY_STARTUP_REPLAY_DONE"); got != want {
		t.Fatalf("entrypoint CADDY_STARTUP_REPLAY_DONE=%q 与 handlers caddyStartupReplayMarkerFile=%q 不一致", got, want)
	}
}

// 停机 pause 标记的三条行为语义（此前只有「路径三方同值」一层保护，
// 分支行为回归不会被任何门禁捕获——pause 语义失效的症状出现在容器编排层）。
func withTempPausePath(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "caddy-paused")
	previous := caddyPauseFilePath
	caddyPauseFilePath = path
	t.Cleanup(func() { caddyPauseFilePath = previous })
	return path
}

func TestWriteDrainPauseFile_createsWhenMissing(t *testing.T) {
	path := withTempPausePath(t)

	writeDrainPauseFile()

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("暂停标记未创建: %v", err)
	}
}

// 已存在的标记不覆盖：它可能是 stopCaddy（用户意图停机）写入的在场标记，
// 覆盖会改变监督器对本次停机的归因。
func TestWriteDrainPauseFile_keepsExistingMarker(t *testing.T) {
	path := withTempPausePath(t)
	if err := os.WriteFile(path, []byte("user-stop"), 0o644); err != nil {
		t.Fatal(err)
	}

	writeDrainPauseFile()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "user-stop" {
		t.Fatalf("已存在标记被覆盖为 %q", string(body))
	}
}

// 写失败必须留痕：pause 语义失效时监督器按崩溃重拉（抢绑 80/443 + 伪
// CRASHES），现象在监督器侧，app 侧零线索则排查无门。
func TestWriteDrainPauseFile_logsWriteFailure(t *testing.T) {
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(previous) })
	previousPath := caddyPauseFilePath
	caddyPauseFilePath = filepath.Join(t.TempDir(), "missing-dir", "caddy-paused")
	t.Cleanup(func() { caddyPauseFilePath = previousPath })

	writeDrainPauseFile()

	if !strings.Contains(logs.String(), "pause 标记") || !strings.Contains(logs.String(), "写入失败") {
		t.Fatalf("写入失败必须告警，got %q", logs.String())
	}
}

// 预算耗尽仍要写标记：否则排水窗口内监督器按崩溃重拉，正是本机制要消除的
// 伪 Crash 噪音；只是跳过 POST /stop。
func TestDrainCaddy_writesMarkerEvenWhenBudgetExhausted(t *testing.T) {
	path := withTempPausePath(t)

	drainCaddy("http://127.0.0.1:1", 0)

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("预算耗尽时仍必须写 pause 标记: %v", err)
	}
}

// admin 可达：POST {admin}/stop 必须发出（末尾斜杠归一）。
func TestDrainCaddy_postsStop(t *testing.T) {
	path := withTempPausePath(t)
	stopCalled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/stop" {
			select {
			case stopCalled <- struct{}{}:
			default:
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	drainCaddy(server.URL+"/", time.Second)

	select {
	case <-stopCalled:
	default:
		t.Fatal("未收到 POST /stop")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("排水前必须写 pause 标记: %v", err)
	}
}
