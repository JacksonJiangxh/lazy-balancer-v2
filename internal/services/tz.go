package services

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"lazy-balancer-v2/internal/taskengine"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

var currentLocation atomic.Value
var applicationLogLevel atomic.Int32

const (
	logLevelDebug int32 = iota
	logLevelInfo
	logLevelWarn
	logLevelError
)

var timezoneRefresh struct {
	sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

func init() {
	currentLocation.Store(time.FixedZone("CST", 8*3600))
	applicationLogLevel.Store(logLevelInfo)
	StartTimezoneRefresh(context.Background())
}

func StartTimezoneRefresh(ctx context.Context) <-chan struct{} {
	timezoneRefresh.Lock()
	defer timezoneRefresh.Unlock()
	if timezoneRefresh.cancel != nil {
		timezoneRefresh.cancel()
		<-timezoneRefresh.done
	}
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	timezoneRefresh.cancel = cancel
	timezoneRefresh.done = done
	go func() {
		defer close(done)
		// D1-历史问题：30s tick 下持久失败逐轮同消息（最坏 2880 行/天）——改状态
		// 转换口径（ok→fail 一次 warn、持续静默、fail→ok 一次 info），与
		// metrics 采集族共用 logStateTransition。
		refresh := func() {
			if err := refreshLocation(); err != nil {
				if logStateTransition("timezone-refresh", true) != "" {
					Logf("warn", "refresh timezone: %v", err)
				}
				return
			}
			if logStateTransition("timezone-refresh", false) != "" {
				Logf("info", "refresh timezone recovered")
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

func StopTimezoneRefresh() {
	timezoneRefresh.Lock()
	defer timezoneRefresh.Unlock()
	if timezoneRefresh.cancel == nil {
		return
	}
	timezoneRefresh.cancel()
	<-timezoneRefresh.done
	timezoneRefresh.cancel = nil
	timezoneRefresh.done = nil
}

func refreshLocation() error {
	database := db.GetDB()
	if database == nil {
		return nil
	}
	var tz string
	if err := database.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tz); err != nil {
		return fmt.Errorf("read configured timezone: %w", err)
	}
	if _, err := ConfigureLocation(tz); err != nil {
		return fmt.Errorf("load configured timezone %q: %w", tz, err)
	}
	return nil
}

func ConfigureLocation(name string) (*time.Location, error) {
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, err
	}
	taskengine.SetLocation(loc) // 任务引擎时间遵循配置时区（启动+设置变更双路径）
	currentLocation.Store(loc)
	return loc, nil
}

func CurrentLocation() *time.Location {
	if loc, ok := currentLocation.Load().(*time.Location); ok && loc != nil {
		return loc
	}
	return time.UTC
}

func ConfigureLogLevel(level string) error {
	var threshold int32
	switch level {
	case "debug":
		threshold = logLevelDebug
	case "info":
		threshold = logLevelInfo
	case "warn":
		threshold = logLevelWarn
	case "error":
		threshold = logLevelError
	default:
		return fmt.Errorf("unsupported application log level %q", level)
	}
	applicationLogLevel.Store(threshold)
	if threshold == logLevelDebug {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}
	return nil
}

func CurrentLogLevel() string {
	switch applicationLogLevel.Load() {
	case logLevelDebug:
		return "debug"
	case logLevelWarn:
		return "warn"
	case logLevelError:
		return "error"
	default:
		return "info"
	}
}

func ShouldLog(level string) bool {
	var candidate int32
	switch level {
	case "debug":
		candidate = logLevelDebug
	case "info":
		candidate = logLevelInfo
	case "warn":
		candidate = logLevelWarn
	case "error":
		candidate = logLevelError
	default:
		return false
	}
	return candidate >= applicationLogLevel.Load()
}

func Logf(level, format string, args ...any) {
	if !ShouldLog(level) {
		return
	}
	switch level {
	case "warn":
		log.Printf("WARNING: "+format, args...)
	case "error":
		log.Printf("ERROR: "+format, args...)
	default:
		log.Printf(format, args...)
	}
}

// applicationLogWriter 按 "WARNING:"/"ERROR:" 行首前缀做级别过滤（历史修复，
// 历史·声明）——隐式依赖 main.go log.SetFlags(0)：标准 log 的时间戳/
// 文件名前缀会顶掉级别前缀使过滤全数落空。两侧契约互指（见 main.go 同名注释）。
// S历史问题：多行 payload（Logf 消息内嵌换行）逐行判定后重组——只看首行会把
// 后续低级别行一并放行（warn/error 档过滤被绕过）。
type applicationLogWriter struct {
	w io.Writer
}

func NewApplicationLogWriter(writer io.Writer) io.Writer {
	return &applicationLogWriter{w: writer}
}

func (writer *applicationLogWriter) Write(p []byte) (int, error) {
	threshold := applicationLogLevel.Load()
	if threshold <= logLevelInfo {
		return writer.w.Write(p)
	}
	trailingNewline := len(p) > 0 && p[len(p)-1] == '\n'
	body := p
	if trailingNewline {
		body = p[:len(p)-1]
	}
	if !bytes.ContainsRune(body, '\n') {
		// 单行热路径（标准 log 常态）：行首前缀判定一次，零额外分配。
		if !lineAllowedAtThreshold(body, threshold) {
			return len(p), nil
		}
		return writer.w.Write(p)
	}
	// S历史问题（历史）：多行 payload（Logf 消息内嵌换行）必须逐行判定并
	// 重组——只看首行会让 warn/error 档把后续 info 级行整体放行（级别过滤失效）。
	lines := bytes.Split(body, []byte("\n"))
	kept := make([][]byte, 0, len(lines))
	for _, line := range lines {
		if lineAllowedAtThreshold(line, threshold) {
			kept = append(kept, line)
		}
	}
	if len(kept) == 0 {
		return len(p), nil
	}
	out := bytes.Join(kept, []byte("\n"))
	if trailingNewline {
		out = append(out, '\n')
	}
	written, err := writer.w.Write(out)
	if err != nil {
		return written, err
	}
	// 多行过滤后 out 短于 p，sink 写满 out 即表示入参
	// 全部被消费——必须返回 len(p), nil（此前返回 sink 的 written<len(p) 且
	// err=nil，违反 io.Writer「n<len(p) 必须带 error」契约，短写敏感的消费者
	// （io.Copy/bufio）会把它当截断重试）。sink 自身短写时无法把 sink 字节
	// 映射回入参，按契约报 io.ErrShortWrite。
	if written < len(out) {
		return 0, io.ErrShortWrite
	}
	return len(p), nil
}

// lineAllowedAtThreshold 报告单行日志是否达到配置阈值（行首级别前缀判定）。
// 调用方不得把多行 payload 直接交给本函数——只看首行会让整体放行（S历史问题）。
func lineAllowedAtThreshold(line []byte, threshold int32) bool {
	line = trimLeadingASCIIWhitespace(line)
	if threshold >= logLevelError {
		return hasASCIIPrefixFold(line, "ERROR")
	}
	return hasASCIIPrefixFold(line, "WARN") || hasASCIIPrefixFold(line, "ERROR")
}

func trimLeadingASCIIWhitespace(value []byte) []byte {
	for len(value) > 0 {
		switch value[0] {
		case ' ', '\t', '\n', '\r', '\v', '\f':
			value = value[1:]
		default:
			return value
		}
	}
	return value
}

func hasASCIIPrefixFold(value []byte, prefix string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for index := range len(prefix) {
		candidate := value[index]
		if candidate >= 'a' && candidate <= 'z' {
			candidate -= 'a' - 'A'
		}
		if candidate != prefix[index] {
			return false
		}
	}
	return true
}

// ApplyLogLevel 读取全局日志级别并应用。main 在 db.Initialize 完成后立即调用，
// 集群配置导入（users 节）后亦调用——历史修复（历史）：此装配点同时执行
// 一次即时 refreshLocation。init 期启动的刷新 worker 首查时 DB 未就绪恒空转，
// 配置时区（尤其 DST 时区）此前最长要等 30s ticker 才生效，期间日志时间戳落在
// FixedZone+8 占位时区；装配点即时刷新消除该窗口，导入新时区亦即时生效。
func ApplyLogLevel() {
	level := "info"
	if db.DB != nil {
		_ = db.DB.QueryRow("SELECT COALESCE(log_level,'info') FROM global_config WHERE id=1").Scan(&level)
	}
	if err := ConfigureLogLevel(level); err != nil {
		Logf("error", "apply application log level: %v", err)
	}
	if err := refreshLocation(); err != nil {
		Logf("error", "refresh timezone: %v", err)
	}
}
