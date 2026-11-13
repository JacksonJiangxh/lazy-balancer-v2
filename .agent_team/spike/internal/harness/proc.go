// Spike 辅助：外部进程启动/就绪探测/收尾。
package harness

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

// Proc 表示一个受管子进程。
type Proc struct {
	Name   string
	Cmd    *exec.Cmd
	out    *LogBuf
	mu     sync.Mutex
	exited bool
}

// Start 启动子进程并捕获 stdout/stderr。
func Start(name, bin string, args []string, env []string, dir string) (*Proc, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = append(cmd.Environ(), env...)
	cmd.Dir = dir
	buf := &LogBuf{}
	cmd.Stdout = buf
	cmd.Stderr = buf
	// 独立进程组，便于整组回收
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	p := &Proc{Name: name, Cmd: cmd, out: buf}
	go func() {
		_ = cmd.Wait()
		p.mu.Lock()
		p.exited = true
		p.mu.Unlock()
	}()
	return p, nil
}

// Output 返回迄今捕获的输出。
func (p *Proc) Output() string { return p.out.String() }

// Exited 报告进程是否已退出。
func (p *Proc) Exited() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exited
}

// Stop 强制结束整个进程组。
func (p *Proc) Stop() {
	if p == nil || p.Cmd == nil || p.Cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(p.Cmd.Process.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
	_ = p.Cmd.Process.Kill()
}

// WaitPort 等待 addr 可建立 TCP 连接。
func WaitPort(ctx context.Context, addr string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("port %s not ready within %s: %v", addr, timeout, lastErr)
}

// WaitFree 等待 addr 不再被监听（用于断言端口释放）。
func WaitFree(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err != nil {
			return true
		}
		_ = c.Close()
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// LogBuf 是并发安全的行缓冲。
type LogBuf struct {
	mu  sync.Mutex
	buf []byte
}

func (b *LogBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *LogBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.buf)
}