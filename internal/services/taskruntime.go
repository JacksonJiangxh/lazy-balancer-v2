package services

// 任务运行时控制注册表（v2.3.4 任务监控）：为常驻/调度循环任务提供
// 统一的 Start/Stop/IsRunning 控制面，main.go 启动时接线，任务监控
// 页面经 /system/tasks/:id/start|stop 消费。
// 未注册的任务族 = 无控制面（角色驱动或纯被动），状态只读展示。

import (
	"context"
	"sync"
)

// TaskRuntime 是单个可控任务的接线闭包。
type TaskRuntime struct {
	IsRunning func() bool
	Start     func()
	Stop      func()
}

var (
	taskRuntimeMu  sync.RWMutex
	taskRuntimeReg = map[string]TaskRuntime{}
)

// RegisterTaskRuntime 注册可控任务（main 启动时调用；同 id 覆盖）。
func RegisterTaskRuntime(id string, rt TaskRuntime) {
	taskRuntimeMu.Lock()
	defer taskRuntimeMu.Unlock()
	taskRuntimeReg[id] = rt
}

// TaskRuntimeState 查询任务控制面；ok=false 表示该任务不可控。
func TaskRuntimeState(id string) (running bool, controllable bool) {
	taskRuntimeMu.RLock()
	rt, ok := taskRuntimeReg[id]
	taskRuntimeMu.RUnlock()
	if !ok {
		return false, false
	}
	return rt.IsRunning(), true
}

// ControlTaskRuntime 执行 start/stop；返回是否生效。
func ControlTaskRuntime(id, action string) bool {
	taskRuntimeMu.RLock()
	rt, ok := taskRuntimeReg[id]
	taskRuntimeMu.RUnlock()
	if !ok {
		return false
	}
	switch action {
	case "start":
		rt.Start()
	case "stop":
		rt.Stop()
	case "restart":
		rt.Stop()
		rt.Start()
	default:
		return false
	}
	return true
}

// ---- 各常驻任务的可重启包装（保留原启动语义，追加 stop/start 闭环）----

// MakeLogCleanupRuntime 包装运行日志清理循环：可停可重启。
func MakeLogCleanupRuntime(logFile string) TaskRuntime {
	var mu sync.Mutex
	var cancel context.CancelFunc
	var done <-chan struct{}
	running := false
	return TaskRuntime{
		IsRunning: func() bool {
			mu.Lock()
			defer mu.Unlock()
			return running
		},
		Start: func() {
			mu.Lock()
			defer mu.Unlock()
			if running {
				return
			}
			ctx, c := context.WithCancel(context.Background())
			ch := StartRuntimeLogCleanupContext(ctx, logFile)
			cancel, done, running = c, ch, true
		},
		Stop: func() {
			mu.Lock()
			c, ch := cancel, done
			if !running || c == nil {
				mu.Unlock()
				return
			}
			running = false
			cancel, done = nil, nil
			mu.Unlock()
			c()
			if ch != nil {
				<-ch
			}
		},
	}
}

// MakeSecurityEventsIngestionRuntime 包装安全事件摄取循环。
func MakeSecurityEventsIngestionRuntime() TaskRuntime {
	var mu sync.Mutex
	var cancel context.CancelFunc
	var waitExited func()
	running := false
	return TaskRuntime{
		IsRunning: func() bool {
			mu.Lock()
			defer mu.Unlock()
			return running
		},
		Start: func() {
			mu.Lock()
			defer mu.Unlock()
			if running {
				return
			}
			ctx, c := context.WithCancel(context.Background())
			wait := StartSecurityEventsIngestion(ctx)
			cancel, waitExited, running = c, wait, true
		},
		Stop: func() {
			mu.Lock()
			if !running {
				mu.Unlock()
				return
			}
			c := cancel
			mu.Unlock()
			c()
			if waitExited != nil {
				waitExited()
			}
			mu.Lock()
			running = false
			cancel, waitExited = nil, nil
			mu.Unlock()
		},
	}
}

// MakeWatchdogRuntime 包装配置看门狗（重启需 adminURL，接线时注入）。
func MakeWatchdogRuntime(adminURL string) TaskRuntime {
	return TaskRuntime{
		IsRunning: func() bool { return ConfigWatchdogRunning() },
		Start:     func() { StartConfigWatchdog(adminURL) },
		Stop:      func() { StopConfigWatchdog() },
	}
}
