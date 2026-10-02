package services

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
)

var runtimeLogSizeMB atomic.Int64

var runtimeLogSizeRefresh struct {
	sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

var runtimeLogCleanup struct {
	sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func init() {
	runtimeLogSizeMB.Store(100)
	StartLogRotate(context.Background())
}

func StartLogRotate(ctx context.Context) <-chan struct{} {
	runtimeLogSizeRefresh.Lock()
	defer runtimeLogSizeRefresh.Unlock()
	if runtimeLogSizeRefresh.cancel != nil {
		runtimeLogSizeRefresh.cancel()
		<-runtimeLogSizeRefresh.done
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	runtimeLogSizeRefresh.cancel = cancel
	runtimeLogSizeRefresh.done = done
	go func() {
		defer close(done)
		refresh := func() {
			database := db.GetDB()
			if database == nil {
				return
			}
			var mb int
			if err := database.QueryRow("SELECT COALESCE(runtime_log_size_mb,100) FROM global_config WHERE id=1").Scan(&mb); err != nil {
				Logf("info", "refresh runtime log size: %v", err)
			} else if mb > 0 {
				runtimeLogSizeMB.Store(int64(mb))
			}
		}
		refresh()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				refresh()
			case <-workerCtx.Done():
				return
			}
		}
	}()
	return done
}

func StopLogRotate() {
	runtimeLogSizeRefresh.Lock()
	defer runtimeLogSizeRefresh.Unlock()
	if runtimeLogSizeRefresh.cancel == nil {
		return
	}
	runtimeLogSizeRefresh.cancel()
	<-runtimeLogSizeRefresh.done
	runtimeLogSizeRefresh.cancel = nil
	runtimeLogSizeRefresh.done = nil
}

// RotatingFileWriter writes to a log file and rotates it once it exceeds the
// size limit. Rotated files are suffixed with a timestamp and are subject to
// retention cleanup (log-cleanup 任务体的 RuntimeLogCleanupOnce——旧启动器
// StartRuntimeLogCleanup 已随 M2 任务引擎化退役).
type RotatingFileWriter struct {
	path string
	mu   sync.Mutex
	file *os.File
	size int64
}

func NewRotatingFileWriter(path string) (*RotatingFileWriter, error) {
	w := &RotatingFileWriter{path: path}
	if err := w.open(); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *RotatingFileWriter) open() error {
	// SECLB23-P3-1(第 23 轮审计):LogFileEnabled 恒 true 后裸二进制部署
	// /app/logs 不存在——open 必须建父目录,否则恒回退 stdout 轮转失效。
	if err := os.MkdirAll(filepath.Dir(w.path), 0o755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	var size int64
	if info, err := f.Stat(); err == nil {
		size = info.Size()
	}
	w.file = f
	w.size = size
	return nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		if err := w.open(); err != nil {
			return 0, fmt.Errorf("reopen log file: %w", err)
		}
	}
	if w.size+int64(len(p)) > runtimeLogSizeMB.Load()*1024*1024 {
		if err := w.rotateLocked(); err != nil {
			return 0, fmt.Errorf("rotate log file: %w", err)
		}
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingFileWriter) rotateLocked() error {
	if err := w.file.Close(); err != nil {
		return err
	}
	w.file = nil
	stamp := time.Now().Format("20060102-150405")
	rotated := fmt.Sprintf("%s.%s", w.path, stamp)
	// SYSB44-2(第 44 轮审计 P3):同秒多次轮转的碰撞后缀原为 UnixNano()%1000
	// 随机数——撞上既有副本名时 os.Rename 静默覆盖,吞掉上一份轮转日志。
	// 改循环递增 -2/-3/...(与 autobackup 同秒序号 -2..-201 同模式)直至文件名
	// 不存在,确定性避让;stat 出非「不存在」错误时按可选用(与原 lenient
	// 口径一致,rename 失败仍走下方回退)。
	for n := 2; ; n++ {
		if _, err := os.Stat(rotated); err != nil {
			break
		}
		rotated = fmt.Sprintf("%s.%s-%d", w.path, stamp, n)
	}
	if err := os.Rename(w.path, rotated); err != nil {
		// Rename failed (e.g. cross-device); keep appending to the old file.
		return w.open()
	}
	return w.open()
}

func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	return w.file.Close()
}

// RuntimeCleanupResult 单轮运行日志清理结果（log-cleanup 任务日志展示明细——
// 2026-10-01 用户裁定：清理了哪个文件必须可见；单轮执行体=
// RuntimeLogCleanupOnce，由任务引擎 log-cleanup 族按 24h 节拍驱动）。
type RuntimeCleanupResult struct {
	AppRemoved int // 应用日志过期副本删除数（app.log.*）
	TaskLogs   TaskLogHousekeepingResult
}

// TaskLogHousekeepingResult 任务日志清理明细。
type TaskLogHousekeepingResult struct {
	Deleted   []string // 超保留期删除（文件名）
	Rotated   []string // 超大小上限轮转（文件名+大小对比，如 "threat.log 11.3MB>10MB"）
	SizeCapMB int      // 生效的大小上限（task_log_size_mb）
}

// Summary 一行明细摘要（列表超 5 个收敛为「等 N 个」；空=「无」）。
func (r TaskLogHousekeepingResult) Summary() string {
	list := func(names []string) string {
		if len(names) == 0 {
			return "无"
		}
		if len(names) > 5 {
			return strings.Join(names[:5], "、") + fmt.Sprintf(" 等 %d 个", len(names))
		}
		return strings.Join(names, "、")
	}
	return fmt.Sprintf("任务日志：超期删除 %d 个[%s]、超限轮转 %d 个[%s]（大小上限 %dMB）",
		len(r.Deleted), list(r.Deleted), len(r.Rotated), list(r.Rotated), r.SizeCapMB)
}

// RuntimeLogCleanupOnce 单轮清理：应用日志过期副本删除 + 任务日志统一
// 清理轮转（taskLogsHousekeeping）。由任务引擎 log-cleanup 族驱动（M2 起
// 无独立启动器）。
func RuntimeLogCleanupOnce(logFile string) RuntimeCleanupResult {
	result := RuntimeCleanupResult{TaskLogs: taskLogsHousekeeping(logFile)}
	months := 3
	database := db.GetDB()
	if database == nil {
		return result
	}
	if err := database.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&months); err != nil || months < 1 {
		months = 3
	}
	cutoff := time.Now().AddDate(0, -months, 0)

	dir := filepath.Dir(logFile)
	base := filepath.Base(logFile) + "."
	entries, err := os.ReadDir(dir)
	if err != nil {
		return result
	}
	removed := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), base) {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				Logf("error", "清理过期运行日志失败 %s: %v", e.Name(), err)
			} else {
				removed++
				Logf("info", "已清理过期运行日志 %s", e.Name())
			}
		}
	}
	result.AppRemoved = removed
	return result
}

// taskLogsHousekeeping 任务日志统一清理与轮转（log-cleanup 任务体）——
// 返回清理明细（哪个文件被删/轮转——用户可见）。
func taskLogsHousekeeping(logFile string) TaskLogHousekeepingResult {
	result := TaskLogHousekeepingResult{SizeCapMB: int(getTaskLogSizeBytes() / 1024 / 1024)}
	// B3：tasks 根 + certjobs 子目录统一扫描（证书任务日志并入任务日志体系）
	dir := filepath.Join(filepath.Dir(logFile), "tasks")
	dirs := []string{dir}
	if cj := filepath.Join(dir, "certjobs"); cj != dir {
		dirs = append(dirs, cj)
	}
	type fileInfo struct {
		path string
		name string
		info os.FileInfo
	}
	var all []fileInfo
	for _, d := range dirs {
		entries, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			all = append(all, fileInfo{path: filepath.Join(d, e.Name()), name: e.Name(), info: info})
		}
	}
	if len(all) == 0 {
		return result
	}
	months := 3
	if database := db.GetDB(); database != nil {
		var m int
		if err := database.QueryRow("SELECT COALESCE(audit_retention_months,3) FROM global_config WHERE id=1").Scan(&m); err == nil && m >= 1 {
			months = m
		}
	}
	cutoff := time.Now().AddDate(0, -months, 0)
	// R63-P2-1：任务日志大小遵循「任务日志大小」配置项（task_log_size_mb，
	// 默认 10MB——曾硬编码 5MB 与配置/统计三方分裂）。
	sizeCap := getTaskLogSizeBytes()
	for _, f := range all {
		if f.info.ModTime().Before(cutoff) {
			if os.Remove(f.path) == nil {
				result.Deleted = append(result.Deleted, f.name)
			}
			continue
		}
		if f.info.Size() > sizeCap {
			if os.Rename(f.path, f.path+".1") == nil { // 轮转保一份
				result.Rotated = append(result.Rotated, fmt.Sprintf("%s %.1fMB>%dMB", f.name, float64(f.info.Size())/1024/1024, sizeCap/1024/1024))
			}
		}
	}
	return result
}
