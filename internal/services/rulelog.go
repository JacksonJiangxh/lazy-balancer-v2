package services

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// ruleLogDir 规则访问日志目录（写入端写死 /app/logs/rules）。包级 var 仅为
// 测试注入缝（handlers.wafAuditLogFile 同模式）；生产路径不得改写。
var ruleLogDir = "/app/logs/rules"

// SetRuleLogDirForTest 覆盖规则日志目录并返回恢复函数（handlers 侧端点测试
// 需要真实文件系统形态：目录/权限故障必须映射 500 而不是空日志）。
func SetRuleLogDirForTest(dir string) func() {
	original := ruleLogDir
	ruleLogDir = dir
	return func() { ruleLogDir = original }
}

func RuleLogPath(ruleID string) string {
	return filepath.Join(ruleLogDir, fmt.Sprintf("%s.log", RuleLogFileComponent(ruleID)))
}

// RuleLogFileComponent 是规则访问日志文件名主体的单源（写侧 RuleLogPath 与
// handlers 读侧共用），内部直接复用可逆编码 encodeFileComponent——此前经
// sanitizeRuleLogName 的纯透传二层已合并（两层同义委托只增加阅读跳转）。
// caddy_id 字母表 [A-Za-z0-9_-] 内的 ID 原样保留（既有文件命名零变化）；
// 含其他字符的 ID 不剔除字符——剔除不可逆且会让 `lb.dot` 与 `lbdot` 共用
// 同一日志文件（删除/读取互相污染），改为 "%" + hex(utf8)。编码分支服务于
// 集群快照/存量数据带入的带点 ID：v2 导入路径已由 ValidCertRuleID 拒绝
// 字母表外 ID（config_backup.go），故新写入不再产生此类 ID。
func RuleLogFileComponent(ruleID string) string {
	return encodeFileComponent(ruleID)
}

// fileComponentSafe 报告 value 是否仅含文件名安全字母表 [_-]
// （= caddy_id 字符集；rulelog 与 certjoblog 共用同一判定与编码）。
func fileComponentSafe(value string) bool {
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

// encodeFileComponent 把任意字符串转为文件名安全且**可逆**的主体：字母表内
// 原样返回（既有文件命名零变化），否则 "%" + hex(utf8)。'%' 不在字母表内，
// 与任何合法 ID 不可能碰撞，且不同 ID 恒得不同文件名（旧剔除实现会让
// `lb.dot`/`lbdot` 共文件与共写锁）。空串编码为 "%"（合法文件名主体）。
func encodeFileComponent(value string) string {
	if fileComponentSafe(value) {
		return value
	}
	return "%" + hex.EncodeToString([]byte(value))
}

// decodeFileComponent 还原 encodeFileComponent 的产物：非 '%' 前缀（字母表内
// ID 或旧实现剔除后的历史文件名）原样返回；hex 非法/为空时按字面值返回，
// 保证存量文件名恒可解析（向后兼容优先于严格性）。
func decodeFileComponent(component string) string {
	if !strings.HasPrefix(component, "%") {
		return component
	}
	raw, err := hex.DecodeString(component[1:])
	if err != nil || len(raw) == 0 {
		return component
	}
	return string(raw)
}

// ReadRuleLogFrom reads the access log from offset to EOF and returns the new
// lines plus the end offset, so callers can incrementally consume without any
// server-side state. Rotation is detected two ways: size < offset (新文件还没
// 长过旧偏移) 与「offset 不再落在行首」(新文件已长过旧偏移)——两者都从 0 重启。
// 日志文件尚不存在=正常空（规则刚创建/尚无流量，非法 caddy_id 另由端点
// 存在性门拦截）；其余 I/O 错误（权限/目录/EISDIR 等）必须上抛——静默返回
// 空会让「日志读不出来」与「没有日志」在 UI 与运维侧无从区分。
func ReadRuleLogFrom(ruleID string, offset int64) (lines []string, next int64, err error) {
	path := RuleLogPath(ruleID)
	f, openErr := os.Open(path)
	if openErr != nil {
		if errors.Is(openErr, os.ErrNotExist) {
			return nil, offset, nil
		}
		return nil, offset, fmt.Errorf("open rule log %s: %w", path, openErr)
	}
	defer f.Close()
	info, statErr := f.Stat()
	if statErr != nil {
		return nil, offset, fmt.Errorf("stat rule log %s: %w", path, statErr)
	}
	if info.Size() < offset {
		offset = 0
	} else if offset > 0 {
		// 轮转的第二种形态：新文件在两次轮询之间已增长到 ≥ 旧 offset
		// （默认 100MB 上限时约需 20MB/s 单规则写入，调大 roll_size_mb 后窗口
		// 更宽）。此时 size<offset 不成立，seek 会落进新文件中段 → 前段日志
		// 永久丢失且 offset 单调前进、log-stream 无 resync 通道。
		// 不变量：正常增长时返回的 offset 恒在行首，offset-1 必为 '\n'。
		// 「整窗无换行的超长单条记录」也会把 offset 推进到行中（maxRead 推进
		// 语义），故额外要求 offset 前 4KB 内确有换行才判轮转——真正的轮转文
		// 件几乎必然在窗口内带换行，纯二进制/超长单行不受影响。
		var prev [1]byte
		if _, readErr := f.ReadAt(prev[:], offset-1); readErr == nil && prev[0] != '\n' {
			window := int64(4096)
			if offset < window {
				window = offset
			}
			probe := make([]byte, window)
			if _, rerr := f.ReadAt(probe, offset-window); rerr == nil && bytes.ContainsRune(probe, '\n') {
				offset = 0
			}
		}
	}
	if offset < 0 {
		offset = 0
	}
	if _, seekErr := f.Seek(offset, io.SeekStart); seekErr != nil {
		return nil, offset, fmt.Errorf("seek rule log %s: %w", path, seekErr)
	}
	// Cap each poll so a huge or maliciously reset offset cannot force a
	// full-log allocation; the caller continues from the returned offset.
	// 8MB covers ~1.6-4K header-rich lines per 5s poll.
	const maxRead = 8 << 20
	data, readErr := io.ReadAll(io.LimitReader(f, maxRead+1))
	if readErr != nil {
		return nil, offset, fmt.Errorf("read rule log %s: %w", path, readErr)
	}
	if len(data) > maxRead {
		data = data[:maxRead]
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		// Hold back the unterminated trailing record so it is delivered
		// complete on the next poll instead of being skipped forever.
		// bytes.LastIndexByte 免去至多 8MB 窗口的
		// string(data) 整体复制（尾行未终结时每 5s 轮询各命中一次）。
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else if int64(len(data)) >= maxRead {
			// 整窗读满（达 maxRead）仍无换行——单条
			// 记录超过读取窗口（>8MB 单行/二进制/损坏日志）。旧式 data=nil 使
			// next==offset 原地不动，日志流永久卡死。至少前进一个窗口：丢弃
			// 本窗字节并把 next 推到窗口末，后续轮询从新 offset 继续。
			next = offset + int64(len(data))
			return nil, next, nil
		} else {
			// 未满窗且无换行（文件/记录暂未终结）：保持扣留语义——data 置空、
			// next 停在 offset，待写侧补全换行后下轮交付完整行（访问日志逐行
			// 落盘的正常中间态）。
			data = nil
		}
	}
	next = offset + int64(len(data))
	text := string(data)
	var parts []string
	if text != "" {
		parts = strings.Split(text, "\n")
		if parts[len(parts)-1] == "" {
			parts = parts[:len(parts)-1]
		}
	}
	return parts, next, nil
}

// ReadRuleLogTail returns the last maxLines lines of the rule's access log
// and the file offset at which they begin, reading backwards in blocks so
// even very large logs cost only a few reads.
// maxBackwardScan:向前扫描字节上限——无换行的损坏/二进制文件
// 防止 O(n²) 全量拷贝(100MB 无换行 ≈ 数十 GB 级复制)
const maxBackwardScan = 4 << 20 // 4MB

func ReadRuleLogTail(ruleID string, maxLines int) (content string, offset int64, err error) {
	path := RuleLogPath(ruleID)
	f, openErr := os.Open(path)
	if openErr != nil {
		if errors.Is(openErr, os.ErrNotExist) {
			return "", 0, nil
		}
		return "", 0, fmt.Errorf("open rule log %s: %w", path, openErr)
	}
	defer f.Close()
	info, statErr := f.Stat()
	if statErr != nil {
		return "", 0, fmt.Errorf("stat rule log %s: %w", path, statErr)
	}
	if info.Size() == 0 {
		return "", 0, nil
	}
	size := info.Size()
	const blockSize = int64(64 * 1024)
	// 两段式倒扫——此前 `buf = append(chunk, buf...)`
	// 每块向前拼接是二次方拷贝（4MB 扫描上限内最坏 ≈130MB 瞬时分配，单次
	// GetRuleLogs 可反复触发）。第一段只倒序记窗口起点+数换行（单块 scratch
	// 复用），第二段对定窗单次 ReadAt 读回。行为逐字节不变：cap 判定、
	// ReadAt 错误丢弃所在块（窗口止于已读前缀）、换行计数、cut 扫描与旧实现
	// 逐分支等价，offset 返回值 size-len(buf)+cut 不变。
	scratch := make([]byte, blockSize)
	winStart := size
	newlines := 0
	scanned := int64(0)
	capped := false
	for end := size; end > 0 && newlines < maxLines+1; {
		// maxBackwardScan 接线：无换行/损坏文件
		// 不再一路扫到文件头，超限即停并返回部分 tail（一次性 warn 留痕）。
		if scanned >= maxBackwardScan {
			capped = true
			break
		}
		start := end - blockSize
		if start < 0 {
			start = 0
		}
		n := int(end - start)
		if _, readErr := f.ReadAt(scratch[:n], start); readErr != nil {
			// 首块即失败=文件根本读不出来（目录/EISDIR/权限/介质错误），
			// 必须上抛而不是伪装成「空日志」；后续块的失败维持既有「窗口止于
			// 已读前缀」语义（部分 tail 优于整体失败）。
			if scanned == 0 {
				return "", 0, fmt.Errorf("read rule log %s: %w", path, readErr)
			}
			break
		}
		winStart = start
		scanned += int64(n)
		for _, b := range scratch[:n] {
			if b == '\n' {
				newlines++
			}
		}
		end = start
	}
	// 首报留痕+节流：命中上限逐规则只报一次 warn（用户反复打开
	// 日志弹框不再每读一次刷一行），读到未截断 tail 时补一条恢复 info——
	// 与排程读失败/日志轮转刷新的 logStateTransition 口径同源。
	if lvl := logStateTransition("rulelog-tail-cap-"+ruleID, capped); lvl != "" {
		if capped {
			Logf(lvl, "rule log tail for %s hit %dMB backward scan cap, returning partial tail", ruleID, maxBackwardScan>>20)
		} else {
			Logf(lvl, "rule log tail for %s resumed below the backward scan cap", ruleID)
		}
	}
	buf := make([]byte, size-winStart)
	if n, err := f.ReadAt(buf, winStart); err != nil && n < len(buf) {
		// 理论不可达（窗口内各块第一段均已读成功）；保持旧实现「读取错误即
		// 以已读前缀为窗口」的语义。
		buf = buf[:n]
	}
	// keep only the last maxLines lines; when the log holds fewer lines than
	// maxLines, cut stays 0 and everything is returned. An unterminated
	// trailing record still counts as a line.
	lines := 0
	cut := 0
	if len(buf) > 0 && buf[len(buf)-1] != '\n' {
		lines = 1
	}
	for i := len(buf) - 1; i >= 0; i-- {
		if buf[i] == '\n' {
			lines++
			if lines > maxLines {
				cut = i + 1
				break
			}
		}
	}
	return string(buf[cut:]), size - int64(len(buf)-cut), nil
}

// RemoveRuleLogFiles 删除规则的访问日志与全部轮转副本（基层 + `.<n>` +
// timberjack 时间戳副本）。返回聚合错误：文件不存在视为成功（幂等重试），
// 其余失败（权限/只读挂载/IO）必须回报——删除失败即磁盘残留，与
// RemoveCertJobLogFiles 同口径，调用方据此审计「清理失败」。首项失败不早退：
// 三个形态各自尝试，错误一并返回，避免「修好第一项就以为收敛」。
func RemoveRuleLogFiles(ruleID string) error {
	base := RuleLogPath(ruleID)
	var errs []error
	remove := func(path string) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Errorf("删除规则日志 %s: %w", path, err))
		}
	}
	remove(base)
	// .1..5 为历史 lumberjack 位移式副本兜底：规则访问日志的唯一生产者
	// Caddy FileWriter 恒用时间戳命名（下方 removeTimberjackRotations），
	// 保留删除仅为清理旧版本/外来 logrotate 残留，不新增该形态生产者。
	for i := 1; i <= 5; i++ {
		remove(fmt.Sprintf("%s.%d", base, i))
	}
	// timberjack 时间戳副本(<id>-<ts>-size.log[.gz],至多 roll_keep=5 份)此前
	// 永久残留——按前缀+完整时间戳尾部清扫。
	if err := removeTimberjackRotations(base); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// timberjackRotationSuffix 匹配 timberjack 轮转副本的固定尾部形态：
// `-<日期>T<时刻>.<毫秒>-size.log[.<压缩后缀>]`。生产链用的是
// timberjack 默认时间格式（虚线日期、时刻段同样以 '-' 分隔）与
// Caddy FileWriter 默认 gzip 压缩（副本名追加 `.gz`），故必须同时接受虚线
// 日期与可选压缩后缀；紧凑 `yyyyMMdd` 形态一并保留（读侧同族兼容）。
// 只认完整时间戳形状——仅判「stem 后首字符是数字」会让兄弟规则
// （如 lb_abc 与 lb_abc-1）的轮转副本被本规则清扫误删（rest 为
// "-1-2026…" 时首字符恰是数字）。
var timberjackRotationSuffix = regexp.MustCompile(`^-(?:\d{8}T\d{2}-\d{2}-\d{2}|\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})(?:\.\d{1,9})?-size\.log(?:\.gz|\.zst)?$`)

// removeTimberjackRotations 删除 base 同目录下 <base去扩展名>-<ts>-size.log 形态
// 的 timberjack 轮转副本。目录不存在=无副本（nil）；读目录/删除失败聚合返回。
func removeTimberjackRotations(base string) error {
	dir := filepath.Dir(base)
	stem := strings.TrimSuffix(filepath.Base(base), filepath.Ext(base))
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("读取规则日志目录 %s: %w", dir, err)
	}
	var errs []error
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, stem+"-") {
			continue
		}
		// 时间戳形状守卫：只有完整 <ts>-size.log 尾部才是本规则的轮转副本；
		// 兄弟规则（caddy_id 以本 stem 为前缀，如 lb_abc 与 lb_abc-1/
		// lb_abc-extra）的副本尾部不匹配 -> 保留。
		if !timberjackRotationSuffix.MatchString(name[len(stem):]) {
			continue
		}
		path := filepath.Join(dir, name)
		if rmErr := os.Remove(path); rmErr != nil && !os.IsNotExist(rmErr) {
			errs = append(errs, fmt.Errorf("删除规则日志 %s: %w", path, rmErr))
		}
	}
	return errors.Join(errs...)
}
