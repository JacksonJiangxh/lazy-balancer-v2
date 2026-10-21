package services

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestExecCaddyValidate_classifiesSuccessRejectAndUnavailable(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "caddy")
	writeScript := func(body string) {
		t.Helper()
		if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("success", func(t *testing.T) {
		writeScript("#!/bin/sh\nexit 0\n")
		t.Setenv("PATH", dir)
		if err := execCaddyValidate([]byte(`{"apps":{}}`)); err != nil {
			t.Fatalf("validate success: %v", err)
		}
	})

	t.Run("reject", func(t *testing.T) {
		writeScript("#!/bin/sh\necho 'provision failed' >&2\nexit 1\n")
		t.Setenv("PATH", dir)
		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if err == nil || errors.Is(err, ErrCLIValidatorUnavailable) || !strings.Contains(err.Error(), "拒绝配置") || !strings.Contains(err.Error(), "provision failed") {
			t.Fatalf("validate reject error=%v, want rejected with stderr", err)
		}
	})

	t.Run("unavailable", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		err := execCaddyValidate([]byte(`{"apps":{}}`))
		if !errors.Is(err, ErrCLIValidatorUnavailable) {
			t.Fatalf("missing caddy error=%v, want ErrCLIValidatorUnavailable", err)
		}
	})
}

// 历史问题（历史）：错误详情必须先按字节上限截断、再回退到合法 UTF-8
// 边界——先归一再按固定字节位硬切会把切口落在多字节字符中间（JSON 响应变成
// U+FFFD 乱码残片）。同时收集侧有界：异常巨量输出不得无界驻留内存。
func TestCaddyValidateDetail_truncatesBytesBeforeUTF8Normalization(t *testing.T) {
	// Given：切口恰落在多字节字符中间（1023 字节 ASCII + "中" 三字节）
	output := append(bytes.Repeat([]byte("a"), caddyErrorBodyMaxBytes-1), []byte("中")...)

	// When
	detail := boundedValidateDetail(output)

	// Then：带合法 UTF-8，且尾部半截 rune 被回退而非保留
	if !utf8.Valid(detail) {
		t.Fatalf("detail 含非法 UTF-8 字节: %q", detail)
	}
	if len(detail) > caddyErrorBodyMaxBytes {
		t.Fatalf("detail 长度 %d 超过上限 %d", len(detail), caddyErrorBodyMaxBytes)
	}
	if string(detail) != string(bytes.Repeat([]byte("a"), caddyErrorBodyMaxBytes-1)) {
		t.Fatalf("detail 尾部残留=%q, want 仅 ASCII 前缀（半个 rune 必须回退）", detail[len(detail)-8:])
	}
}

func TestCaddyValidateOutputCap_boundsCollectedOutput(t *testing.T) {
	// Given：上限 8 字节的收集器
	buf := &cappedOutputBuffer{limit: 8}

	// When：写入 16 字节（模拟异常巨量输出的分块）
	n, err := buf.Write([]byte("0123456789abcdef"))

	// Then：对子进程如实报告全额消费，缓冲区只保留上限内容
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != 16 {
		t.Fatalf("Write 返回 %d, want 16（短写会让子进程误判）", n)
	}
	if got := buf.buf.String(); got != "01234567" {
		t.Fatalf("收集内容=%q, want 前 8 字节", got)
	}
}
