package services

import "strings"

// AccessLogFormatRule 一条合法的 access_log_format 映射行。
type AccessLogFormatRule struct {
	Line   int    // 1-based 行号（原始格式串内，非法行报告/归一重建用）
	Path   string // -> 左侧字段路径（已 TrimSpace）
	Action string // -> 右侧动作（已 TrimSpace）："delete" 或 rename 目标名
}

// AccessLogFormatParse DSL 解析结果：合法行 + 非法行号（1-based）。
type AccessLogFormatParse struct {
	Rules   []AccessLogFormatRule
	Invalid []int
}

// ParseAccessLogFormat access_log_format DSL 单源解析器——
// 渲染层（buildAccessLogEncoder）、写侧校验（validateAccessLogFormat）与
// 归一（normalizeAccessLogRedaction）此前各写一份行拆分，口径漂移且非法行
// 被静默跳过。口径：空行忽略（合法）；其余行必须满足 `路径 -> 动作` 且
// 两侧非空，否则记入 Invalid（写侧据此 400 点名行号；渲染层只消费 Rules，
// 对带外写入的存量非法行保持容忍跳过）。
func ParseAccessLogFormat(format string) AccessLogFormatParse {
	var out AccessLogFormatParse
	for i, line := range strings.Split(format, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		parts := strings.SplitN(trimmed, "->", 2)
		if len(parts) != 2 {
			out.Invalid = append(out.Invalid, i+1)
			continue
		}
		path := strings.TrimSpace(parts[0])
		action := strings.TrimSpace(parts[1])
		if path == "" || action == "" {
			out.Invalid = append(out.Invalid, i+1)
			continue
		}
		out.Rules = append(out.Rules, AccessLogFormatRule{Line: i + 1, Path: path, Action: action})
	}
	return out
}
