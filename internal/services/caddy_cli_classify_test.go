package services

import (
	"context"
	"errors"
	"io/fs"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

// CLI 校验失败分类：只有「进程确实运行并以非零码退出」才算配置被拒；权限拒绝
// （启动失败，*fs.PathError）必须归为校验器不可用——否则 400+回滚会把环境故障
// 伪装成用户配置错误。
func TestClassifyCaddyValidateFailure_permissionDeniedIsUnavailable(t *testing.T) {
	runErr := &fs.PathError{Op: "fork/exec", Path: "/usr/local/bin/caddy", Err: syscall.EACCES}
	err := classifyCaddyValidateFailure(nil, runErr, nil)
	if !errors.Is(err, ErrCLIValidatorUnavailable) {
		t.Fatalf("permission denied 分类=%v, want ErrCLIValidatorUnavailable", err)
	}
	if IsConfigRejected(err) {
		t.Fatal("权限拒绝不得归为配置被拒（会 400 回滚并误导用户）")
	}
}

// 信号致死（崩溃/OOM）同样不是配置裁决：*exec.ExitError 但 !Exited()。
func TestClassifyCaddyValidateFailure_signalKilledIsUnavailable(t *testing.T) {
	runErr := exec.Command("/bin/sh", "-c", "kill -KILL $$").Run()
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) || exitErr.ProcessState.Exited() {
		t.Fatalf("前置失败：期望信号致死的 *exec.ExitError, got %v", runErr)
	}
	err := classifyCaddyValidateFailure(nil, runErr, []byte("killed"))
	if !errors.Is(err, ErrCLIValidatorUnavailable) {
		t.Fatalf("信号致死分类=%v, want ErrCLIValidatorUnavailable", err)
	}
	if IsConfigRejected(err) {
		t.Fatal("信号致死不得归为配置被拒")
	}
}

// 超时（ctx 到期）优先于退出形态判定：即便拿到 ExitError 也只能是「不可用」。
func TestClassifyCaddyValidateFailure_timeoutIsUnavailable(t *testing.T) {
	runErr := exec.Command("/bin/sh", "-c", "kill -KILL $$").Run()
	if runErr == nil {
		t.Fatal("前置失败：期望非零退出")
	}
	err := classifyCaddyValidateFailure(context.DeadlineExceeded, runErr, []byte("timeout"))
	if !errors.Is(err, ErrCLIValidatorUnavailable) {
		t.Fatalf("超时分类=%v, want ErrCLIValidatorUnavailable", err)
	}
}

// 边界：真实非零退出仍必须是「配置被拒」，并携带（截断后的）校验输出。
func TestClassifyCaddyValidateFailure_nonZeroExitIsRejection(t *testing.T) {
	runErr := exec.Command("/bin/sh", "-c", "exit 3").Run()
	if runErr == nil {
		t.Fatal("前置失败：期望非零退出")
	}
	err := classifyCaddyValidateFailure(nil, runErr, []byte("caddy: adapting config: boom"))
	if err == nil {
		t.Fatal("非零退出必须报错")
	}
	if errors.Is(err, ErrCLIValidatorUnavailable) {
		t.Fatalf("非零退出不得归为校验器不可用: %v", err)
	}
	if !strings.Contains(err.Error(), "拒绝配置") || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("拒绝错误缺少分类文本/校验输出: %v", err)
	}
}

// Go 运行时致命 abort（线程/内存耗尽）发生在配置解析之前：退出码非零但与
// 配置内容无关，必须归为校验器不可用——否则 ulimit 过紧的宿主上任何保存都会
// 被误报为「配置被拒」。
func TestClassifyCaddyValidateFailure_runtimeFatalIsUnavailable(t *testing.T) {
	runErr := exec.Command("/bin/sh", "-c", "exit 2").Run()
	if runErr == nil {
		t.Fatal("前置失败：期望非零退出")
	}
	output := []byte("runtime: failed to create new OS thread (have 3 already; errno=11)\n" +
		"fatal error: newosproc\n\nruntime stack:\nruntime.throw(...)")
	err := classifyCaddyValidateFailure(nil, runErr, output)
	if !errors.Is(err, ErrCLIValidatorUnavailable) {
		t.Fatalf("运行时致命分类=%v, want ErrCLIValidatorUnavailable", err)
	}
	if IsConfigRejected(err) {
		t.Fatal("运行时致命不得归为配置被拒（会 400 回滚并误导用户）")
	}
}
