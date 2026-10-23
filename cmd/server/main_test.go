package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/services"
)

func TestRestartRequiredHandler_shutsDownHTTPServer(t *testing.T) {
	// Given
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{Handler: http.NewServeMux()}
	serverErrors := make(chan error, 1)
	go func() { serverErrors <- server.Serve(listener) }()
	quit := make(chan os.Signal, 1)
	restart, requestRestart := newRestartSignal()
	services.SetRestartRequiredHandler(requestRestart)
	t.Cleanup(func() { services.SetRestartRequiredHandler(nil) })

	// When
	requestRestart()
	requestRestart()
	serverErr := waitForServerStop(server, serverStopSignals{quit: quit, restart: restart, serverErrors: serverErrors})

	// Then
	if serverErr != nil {
		t.Fatalf("wait for server stop: %v", err)
	}
	if err := <-serverErrors; !errors.Is(err, http.ErrServerClosed) {
		t.Fatalf("serve error=%v, want http.ErrServerClosed", err)
	}
}

func TestNewAdminHTTPServer_largeTransferTimeouts(t *testing.T) {
	server := newAdminHTTPServer(":8080", nil)
	if server.ReadHeaderTimeout != 10*time.Second {
		t.Fatalf("ReadHeaderTimeout=%s, want 10s slow-header guard", server.ReadHeaderTimeout)
	}
	if server.ReadTimeout != 5*time.Minute {
		t.Fatalf("ReadTimeout=%s, want 5m for large config imports", server.ReadTimeout)
	}
	if server.WriteTimeout != 10*time.Minute {
		t.Fatalf("WriteTimeout=%s, want 10m for large backup downloads", server.WriteTimeout)
	}
	if server.IdleTimeout != 120*time.Second {
		t.Fatalf("IdleTimeout=%s, want existing 120s", server.IdleTimeout)
	}
}

func TestMain_exitsNonZero_whenHTTPListenFails(t *testing.T) {
	// Given
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "config.json")
	// caddy_admin_url 必须指向死端口：缺省会落到 config.go 的默认
	// http://localhost:2019——helper 的 ApplyConfigOnStartup 会把零规则配置
	// 应用到本机真实运行的 Caddy（host 网络共享 loopback），静默清空其路由。
	configJSON := fmt.Sprintf(`{"port":%d,"data_dir":%q,"static_dir":%q,"metrics_interval":5,"caddy_admin_url":"http://127.0.0.1:1"}`, port, filepath.Join(tempDir, "data"), tempDir)
	if err := os.WriteFile(configPath, []byte(configJSON), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=TestMainHelperProcess")
	command.Env = append(os.Environ(), "LAZY_BALANCER_MAIN_HELPER=1", "LAZY_BALANCER_TEST_CONFIG="+configPath)

	// When
	output, err := command.CombinedOutput()

	// Then
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() == 0 {
		t.Fatalf("process error=%v output=%q, want non-zero exit", err, output)
	}
	if !strings.Contains(string(output), "HTTP server stopped unexpectedly") {
		t.Fatalf("output=%q, want startup failure log", output)
	}
}

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv("LAZY_BALANCER_MAIN_HELPER") != "1" {
		return
	}
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	os.Args = []string{os.Args[0], "-config", os.Getenv("LAZY_BALANCER_TEST_CONFIG")}
	main()
	os.Exit(0)
}

// tzLogWriter 必须满足 io.Writer 契约：向下写的是 prefix+p，返回值只能是
// len(p)——直接把底层 n 转交会报 n > len(p)。当前唯一消费者忽略 n，但任何
// 缓冲/io.Copy/短写校验接入后都会按越界 n 使用。
func TestTZLogWriterWriteHonorsWriterContract(t *testing.T) {
	var sink bytes.Buffer
	writer := &tzLogWriter{w: &sink}
	payload := []byte("job finished\n")
	n, err := writer.Write(payload)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write 返回 n=%d, want %d（io.Writer 契约）", n, len(payload))
	}
	written := sink.String()
	if !strings.HasSuffix(written, string(payload)) {
		t.Fatalf("写出的内容缺少原文尾部: %q", written)
	}
	// 前缀=本地时区时间戳 + 一个空格（格式 2006/01/02 15:04:05 ）
	prefix := written[:len(written)-len(payload)]
	if len(prefix) != len("2006/01/02 15:04:05 ") {
		t.Fatalf("时间戳前缀长度=%d, want %d：%q", len(prefix), len("2006/01/02 15:04:05 "), prefix)
	}
	if _, err := time.ParseInLocation("2006/01/02 15:04:05 ", prefix, services.CurrentLocation()); err != nil {
		t.Fatalf("前缀不是本地时区时间戳: %q (%v)", prefix, err)
	}

	// 底层写失败必须上抛，且不得报告已写入字节。
	failing := &failingWriter{err: errors.New("sink closed")}
	if n, err := (&tzLogWriter{w: failing}).Write(payload); err == nil || n != 0 {
		t.Fatalf("底层失败: n=%d err=%v, want n=0 且错误上抛", n, err)
	}
}

type failingWriter struct{ err error }

func (w *failingWriter) Write([]byte) (int, error) { return 0, w.err }

// 启动期时区读侧：显式值直读，NULL/空串/缺行落到治理默认值 db.DefaultTimezone
// （DDL DEFAULT 单源）；读错误才上抛由调用方退回进程默认时区。
func TestStartupTimezoneShapes(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})

	if _, err := db.DB.Exec("UPDATE global_config SET timezone='Europe/Berlin' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if got, err := startupTimezone(db.DB); err != nil || got != "Europe/Berlin" {
		t.Fatalf("显式时区: got %q err=%v, want Europe/Berlin", got, err)
	}

	for _, tc := range []struct {
		name string
		stmt string
	}{
		{name: "NULL", stmt: "UPDATE global_config SET timezone=NULL WHERE id=1"},
		{name: "空串", stmt: "UPDATE global_config SET timezone='' WHERE id=1"},
		{name: "缺行", stmt: "DELETE FROM global_config WHERE id=1"},
	} {
		if _, err := db.DB.Exec(tc.stmt); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got, err := startupTimezone(db.DB)
		if err != nil {
			t.Fatalf("%s: 不得报错（应落到治理默认值）: %v", tc.name, err)
		}
		if got != db.DefaultTimezone {
			t.Fatalf("%s: got %q, want 治理默认值 %q", tc.name, got, db.DefaultTimezone)
		}
	}
}

// 关停链的 warmer 等待缝：空闲时必须立即返回（正常路径不吃关停预算），
// 预算耗尽（d<=0）直接放弃——不得在无预算时阻塞退出。
func TestWaitThreatRollupWarmerIdleSeam(t *testing.T) {
	started := time.Now()
	if !handlers.WaitThreatRollupWarmer(time.Second) {
		t.Fatal("无 warmer 运行时等待应成功返回")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("空闲等待耗时 %s，应远小于预算", elapsed)
	}
	if handlers.WaitThreatRollupWarmer(0) {
		t.Fatal("预算耗尽（d<=0）必须直接返回 false，不得等待")
	}
}
