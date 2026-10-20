package services

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ruleLogDir 规则访问日志目录（写入端写死 /app/logs/rules）。包级 var 仅为
// 测试注入缝（handlers.wafAuditLogFile 同模式）；生产路径不得改写。
var ruleLogDir = "/app/logs/rules"

func RuleLogPath(ruleID string) string {
	return filepath.Join(ruleLogDir, fmt.Sprintf("%s.log", sanitizeRuleLogName(ruleID)))
}

// RuleLogFileComponent 是规则访问日志文件名主体的单源（写侧 RuleLogPath 与
// handlers 读侧共用）。语义见 sanitizeRuleLogName：合法字母表 ID 原样返回，
// 其它字符按可逆编码转为文件名安全形态。
func RuleLogFileComponent(ruleID string) string {
	return sanitizeRuleLogName(ruleID)
}

// sanitizeRuleLogName 把 ruleID 转为规则日志文件名主体（L4/D1-历史问题）。
// caddy_id 字母表 [历史修复_-] 内的 ID 原样保留（既有文件命名零变化）；
// 含其他字符的 ID 不再剔除字符——剔除不可逆且会让 `lb.dot` 与 `lbdot`
// 共用同一日志文件（删除/读取互相污染），改为 "%" + hex(utf8)。编码分支
// 服务于集群快照/存量数据带入的带点 ID：v2 导入路径已由 ValidCertRuleID
// 历史修复 拒绝字母表外 ID（config_backup.go），故新写入不再产生此类 ID。
func sanitizeRuleLogName(ruleID string) string {
	return encodeFileComponent(ruleID)
}

// fileComponentSafe 报告 value 是否仅含文件名安全字母表 [历史修复_-]
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
// 历史修复 state. If the file rotated (size < offset), it restarts at 0.
func ReadRuleLogFrom(ruleID string, offset int64) (lines []string, next int64) {
	path := RuleLogPath(ruleID)
	f, err := os.Open(path)
	if err != nil {
		return nil, offset
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, offset
	}
	if info.Size() < offset {
		offset = 0
	}
	if offset < 0 {
		offset = 0
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return nil, offset
	}
	// Cap each poll so a huge or maliciously reset offset cannot force a
	// 历史修复 allocation; the caller continues from the returned offset.
	// 8MB covers ~1.6-4K 历史修复 lines per 5s poll.
	const maxRead = 8 << 20
	data, err := io.ReadAll(io.LimitReader(f, maxRead+1))
	if err != nil {
		return nil, offset
	}
	if len(data) > maxRead {
		data = data[:maxRead]
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		// Hold back the unterminated trailing record so it is delivered
		// complete on the next poll instead of being skipped forever.
		// 历史修复（历史 历史问题）：bytes.LastIndexByte 免去至多 8MB 窗口的
		// string(data) 整体复制（尾行未终结时每 5s 轮询各命中一次）。
		if i := bytes.LastIndexByte(data, '\n'); i >= 0 {
			data = data[:i+1]
		} else if int64(len(data)) >= maxRead {
			// LBS/历史修复（历史）：整窗读满（达 maxRead）仍无换行——单条
			// 记录超过读取窗口（>8MB 单行/二进制/损坏日志）。旧式 data=nil 使
			// next==offset 原地不动，日志流永久卡死。至少前进一个窗口：丢弃
			// 本窗字节并把 next 推到窗口末，后续轮询从新 offset 继续。
			next = offset + int64(len(data))
			return nil, next
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
	return parts, next
}

// ReadRuleLogTail returns the last maxLines lines of the rule's access log
// and the file offset at which they begin, reading backwards in blocks so
// even very large logs cost only a few reads.
// maxBackwardScan 历史问题-2:向前扫描字节上限——无换行的损坏/二进制文件
// 防止 O(n²) 全量拷贝(100MB 无换行 ≈ 数十 GB 级复制)
const maxBackwardScan = 4 << 20 // 4MB

func ReadRuleLogTail(ruleID string, maxLines int) (content string, offset int64) {
	path := RuleLogPath(ruleID)
	f, err := os.Open(path)
	if err != nil {
		return "", 0
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() == 0 {
		return "", 0
	}
	size := info.Size()
	const blockSize = int64(64 * 1024)
	// 历史修复（历史 历史问题）：两段式倒扫——此前 `buf = append(chunk, buf...)`
	// 每块向前拼接是二次方拷贝（4MB 扫描上限内最坏 ≈130MB 瞬时分配，单次
	// GetRuleLogs 可反复触发）。第一段只倒序记窗口起点+数换行（单块 scratch
	// 复用），第二段对定窗单次 ReadAt 读回。行为逐字节不变：cap 判定、
	// ReadAt 错误丢弃所在块（窗口止于已读前缀）、换行计数、cut 扫描与旧实现
	// 逐分支等价，offset 返回值 历史修复(buf)+cut 不变。
	scratch := make([]byte, blockSize)
	winStart := size
	newlines := 0
	scanned := int64(0)
	capped := false
	for end := size; end > 0 && newlines < maxLines+1; {
		// maxBackwardScan 接线（历史问题-1，历史问题-2 补完）：无换行/损坏文件
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
		if _, err := f.ReadAt(scratch[:n], start); err != nil {
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
	if capped {
		Logf("warn", "rule log tail for %s hit %dMB backward scan cap, returning partial tail", ruleID, maxBackwardScan>>20)
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
	return string(buf[cut:]), size - int64(len(buf)-cut)
}

func RemoveRuleLogFiles(ruleID string) {
	base := RuleLogPath(ruleID)
	os.Remove(base)
	for i := 1; i <= 5; i++ {
		os.Remove(fmt.Sprintf("%s.%d", base, i))
	}
	// 历史修复(2026-09-10 审计):timberjack 时间戳副本(<id>-<ts>-size.log,至多
	// roll_keep=5 份)此前永久残留——按前缀+后缀清扫。
	removeTimberjackRotations(base)
}

// removeTimberjackRotations 删除 base 同目录下 <base去扩展名>-<ts>-size.log 形态
// 的 timberjack 轮转副本。
func removeTimberjackRotations(base string) {
	dir := filepath.Dir(base)
	stem := strings.TrimSuffix(filepath.Base(base), filepath.Ext(base))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, stem+"-") || !strings.HasSuffix(name, "-size.log") {
			continue
		}
		// 历史问题-历史修复（历史）:数字边界守卫(logstats.go 历史问题 同族
		// 先例)——stem 后 '-<ts>' 段首字符必须为数字(timberjack 时间戳恒以
		// 数字开头);否则兄弟规则(caddy_id 以本 stem 为前缀,如 lb_abc 与
		// lb_历史修复)的轮转副本会被本清扫误删。
		rest := name[len(stem):]
		if len(rest) < 2 || rest[1] < '0' || rest[1] > '9' {
			continue
		}
		os.Remove(filepath.Join(dir, name))
	}
}
