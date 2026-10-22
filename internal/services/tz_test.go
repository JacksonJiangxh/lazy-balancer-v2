package services

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestRefreshLocation_updates_current_location_without_mutating_timeLocal(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := db.DB.Exec("UPDATE global_config SET timezone='UTC' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}
	localBefore := time.Local

	// When
	err := refreshLocation()

	// Then
	if err != nil {
		t.Fatalf("refresh location: %v", err)
	}
	if time.Local != localBefore {
		t.Fatal("runtime timezone refresh mutated time.Local")
	}
	if CurrentLocation() != time.UTC {
		t.Fatalf("current location=%v, want UTC", CurrentLocation())
	}
}

func TestTimezoneRefresh_stops_and_waits_when_context_is_canceled(t *testing.T) {
	// Given
	StopTimezoneRefresh()
	ctx, cancel := context.WithCancel(context.Background())
	done := StartTimezoneRefresh(ctx)

	// When
	cancel()

	// Then: <-done 返回即证明循环已停止且等待闭合（阻塞则测试超时失败；
	// 原 <-done 之后的 select-default 分支恒不可达，已删）。
	<-done

	t.Cleanup(func() { StartTimezoneRefresh(context.Background()) })
}

// Given 一个永不退出的时区刷新 worker（可控挂起：done 永不关闭——等价于
// refresh 阻塞在 DB busy_timeout 的生产形态）。
// When StopTimezoneRefreshWithin 以 50ms 上限调用。
// Then 按 deadline 放弃等待并返回 false（不再无界 <-done）；字段保留，
// worker 最终退出后可再次 Stop 完成清零（可重启语义不变）。
func TestStopTimezoneRefreshWithin_givesUpWhenWorkerStuck(t *testing.T) {
	StopTimezoneRefresh() // 停掉 init 启动的真实 worker
	t.Cleanup(func() { StartTimezoneRefresh(context.Background()) })

	stuck := make(chan struct{}) // 永不关闭
	timezoneRefresh.Lock()
	timezoneRefresh.cancel = func() {}
	timezoneRefresh.done = stuck
	timezoneRefresh.Unlock()

	begin := time.Now()
	if StopTimezoneRefreshWithin(50 * time.Millisecond) {
		t.Fatal("卡住的 worker 必须返回 false（放弃等待）")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("等待未受预算约束：耗时 %s（预算 50ms）", elapsed)
	}

	close(stuck)
	if !StopTimezoneRefreshWithin(2 * time.Second) {
		t.Fatal("worker 退出后 Stop 必须返回 true")
	}
	timezoneRefresh.Lock()
	cleared := timezoneRefresh.cancel == nil && timezoneRefresh.done == nil
	timezoneRefresh.Unlock()
	if !cleared {
		t.Fatal("worker 退出后字段必须清零（可重启语义不变）")
	}
}

// Given 正常运行的时区刷新 worker（init 形态，空闲 select 循环）。
// When StopTimezoneRefreshWithin 以充裕预算调用。
// Then 快速返回 true——正常路径不等满预算。
func TestStopTimezoneRefreshWithin_fastPathDoesNotConsumeBudget(t *testing.T) {
	StopTimezoneRefresh()
	StartTimezoneRefresh(context.Background())
	t.Cleanup(func() {
		StopTimezoneRefresh()
		StartTimezoneRefresh(context.Background())
	})

	begin := time.Now()
	if !StopTimezoneRefreshWithin(5 * time.Second) {
		t.Fatal("正常 worker 必须在预算内退出")
	}
	if elapsed := time.Since(begin); elapsed > 2*time.Second {
		t.Fatalf("正常路径耗时 %s，不得在预算内空等", elapsed)
	}
}

func TestApplicationLogWriterFiltersRawStandardLogsAtConfiguredThreshold(t *testing.T) {
	tests := []struct {
		name    string
		level   string
		message string
		want    bool
	}{
		{name: "info allows ordinary lines", level: "info", message: "startup complete", want: true},
		{name: "warn drops ordinary lines", level: "warn", message: "startup complete", want: false},
		{name: "warn allows warning lines", level: "warn", message: "Warning: degraded startup", want: true},
		{name: "error drops warning lines", level: "error", message: "Warning: degraded startup", want: false},
		{name: "error allows error lines", level: "error", message: "ERROR: startup failed", want: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Given
			var output bytes.Buffer
			if err := ConfigureLogLevel(test.level); err != nil {
				t.Fatal(err)
			}
			logger := log.New(NewApplicationLogWriter(&output), "", 0)

			// When
			logger.Print(test.message)

			// Then
			if strings.Contains(output.String(), test.message) != test.want {
				t.Fatalf("output=%q want_visible=%v", output.String(), test.want)
			}
		})
	}
	t.Cleanup(func() { _ = ConfigureLogLevel("info") })
}

// DB 初始化完成点即时刷新时区——init 期 worker 首查时
// DB 未就绪恒空转，配置时区此前最长要等 30s ticker 才生效（FixedZone+8 占位
// 窗口）。ApplyLogLevel 是 main 在 db.Initialize 完成后的首个 services 装配点
// （亦为集群导入 users 节后的调用点），在此追加一次即时 refreshLocation。
func TestApplyLogLevel_refreshesTimezoneImmediately(t *testing.T) {
	oldLoc := CurrentLocation()
	StopTimezoneRefresh()
	t.Cleanup(func() {
		currentLocation.Store(oldLoc)
		StartTimezoneRefresh(context.Background())
	})
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	if _, err := db.DB.Exec("UPDATE global_config SET timezone='America/New_York' WHERE id=1"); err != nil {
		t.Fatalf("set timezone: %v", err)
	}

	// When：DB 就绪后的装配点调用（不等 30s ticker）
	ApplyLogLevel()

	// Then：DST 时区立即生效
	if got := CurrentLocation().String(); got != "America/New_York" {
		t.Fatalf("current location=%q, want America/New_York（DB 就绪后必须即时刷新，不得等 ticker）", got)
	}
}

// applicationLogWriter 透传 sink 的真实返回值——短写
// 返回 len(p) 偏离 io.Writer 契约（装饰器不得替 sink 谎报写入量）。
func TestApplicationLogWriter_writeReturnsSinkWrittenCount(t *testing.T) {
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })
	if err := ConfigureLogLevel("warn"); err != nil { // 进入过滤分支（info 直通分支本就透传）
		t.Fatal(err)
	}
	sink := &shortWriteSink{n: 3}
	w := NewApplicationLogWriter(sink)
	// 载荷带 WARN 前缀——warn 档放行进入写入分支（不带前缀会在过滤分支被丢弃，
	// 触达不到 sink）。
	n, err := w.Write([]byte("WARN hello world"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 3 {
		t.Fatalf("Write returned %d, want sink's 3（短写必须如实返回 written）", n)
	}
}

// 多行 payload 被逐行过滤后 out 短于 p 时，必须返回
// (len(p), nil)——sink 已写满被保留内容即代表入参全部被消费。旧实现返回
// sink 的 written(<len(p)) 且 err=nil，违反 io.Writer 契约（短写敏感消费者
// 会当成截断）。sink 自身短写则按契约报 io.ErrShortWrite。
func TestApplicationLogWriter_multilineFilterHonorsWriterContract(t *testing.T) {
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })
	if err := ConfigureLogLevel("warn"); err != nil {
		t.Fatal(err)
	}
	payload := []byte("WARNING: kept\nordinary dropped\nERROR: kept too\n")

	t.Run("filtered payload reports full consumption", func(t *testing.T) {
		var output bytes.Buffer
		n, err := NewApplicationLogWriter(&output).Write(payload)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("Write returned %d, want len(p)=%d（过滤掉的行也算已消费）", n, len(payload))
		}
		if got, want := output.String(), "WARNING: kept\nERROR: kept too\n"; got != want {
			t.Fatalf("output=%q, want %q", got, want)
		}
	})

	t.Run("sink short write surfaces io.ErrShortWrite", func(t *testing.T) {
		n, err := NewApplicationLogWriter(&shortWriteSink{n: 3}).Write(payload)
		if !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("err=%v, want io.ErrShortWrite", err)
		}
		if n != 0 {
			t.Fatalf("n=%d, want 0（无法映射回入参字节）", n)
		}
	})
}

// shortWriteSink 恒短写返回 (n, nil) 的 sink。
type shortWriteSink struct{ n int }

func (s *shortWriteSink) Write(p []byte) (int, error) {
	if s.n > len(p) {
		return len(p), nil
	}
	return s.n, nil
}

// 多行 payload（Logf 消息内嵌换行）必须逐行按级别过滤
// 后重组——只看首行会让 warn/error 档整体放行后续低级别行（级别过滤被绕过）。
func TestApplicationLogWriter_filtersEachLineOfMultilinePayload(t *testing.T) {
	oldLevel := CurrentLogLevel()
	t.Cleanup(func() { _ = ConfigureLogLevel(oldLevel) })

	t.Run("warn keeps warn and error lines only", func(t *testing.T) {
		if err := ConfigureLogLevel("warn"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		payload := []byte("WARNING: degraded\nordinary info line\nERROR: boom\n")
		if _, err := NewApplicationLogWriter(&output).Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := output.String(), "WARNING: degraded\nERROR: boom\n"; got != want {
			t.Fatalf("output=%q, want 仅 warn/error 行（info 行必须逐行滤除）", got)
		}
	})

	t.Run("error keeps error lines only", func(t *testing.T) {
		if err := ConfigureLogLevel("error"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		payload := []byte("WARNING: degraded\nERROR: boom\nstill ordinary\n")
		if _, err := NewApplicationLogWriter(&output).Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := output.String(), "ERROR: boom\n"; got != want {
			t.Fatalf("output=%q, want 仅 error 行", got)
		}
	})

	t.Run("single line path unchanged", func(t *testing.T) {
		if err := ConfigureLogLevel("warn"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		if _, err := NewApplicationLogWriter(&output).Write([]byte("WARN hello\n")); err != nil {
			t.Fatalf("write: %v", err)
		}
		if got, want := output.String(), "WARN hello\n"; got != want {
			t.Fatalf("output=%q, want 单行原样透传", got)
		}
	})
}

// 时区刷新路径必须与写侧同一校验器：空/空白时区（LoadLocation("")=UTC 合法）
// 不得静默把全站切到 UTC——刷新失败保留旧时区并返回错误（状态机留痕）。
func TestRefreshLocation_rejectsBlankTimezone(t *testing.T) {
	initServicesDB(t)
	if _, err := ConfigureLocation("Asia/Shanghai"); err != nil {
		t.Fatalf("seed location: %v", err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation("UTC") })
	if _, err := db.DB.Exec(`UPDATE global_config SET timezone='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	err := refreshLocation()

	// Then：拒绝空串、保留旧时区
	if err == nil {
		t.Fatal("空时区必须被拒绝（LoadLocation(\"\") 会静默返回 UTC）")
	}
	if got := CurrentLocation().String(); got != "Asia/Shanghai" {
		t.Fatalf("时区被静默切走: %q, want Asia/Shanghai", got)
	}
}
