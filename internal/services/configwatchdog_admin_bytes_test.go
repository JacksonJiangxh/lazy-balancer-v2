package services

// 历史问题-2（历史 审计）：看门狗读取 Caddy 运行配置的解码上限须与 caddy.go
// 家族口径对齐（32MB，历史问题 同源：caddy.go:210/565/780）。原 4MB 上限下
// >4MB 配置解码失败→漂移检测永久静默而 apply 仍工作至 32MB——大部署静默
// 单点失效。本测试钉：>4MB（<32MB）的运行配置仍可提取规则路由 @id。

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunningRuleRouteIDs_configAbove4MBStillDecoded(t *testing.T) {
	// 5MB 填充键：>4MB 旧上限、<32MB 家族口径。
	body := fmt.Sprintf(`{"_pad":%q,"apps":{"http":{"servers":{"s":{"routes":[{"@id":"lb_probe"},{"@id":"other"}]}}}}}`,
		strings.Repeat("p", 5<<20))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("write fake admin config: %v", err)
		}
	}))
	defer srv.Close()

	ids, err := runningRuleRouteIDs(srv.URL)
	if err != nil {
		t.Fatalf("runningRuleRouteIDs on >4MB config: %v", err)
	}
	if len(ids) != 1 || !ids["lb_probe"] {
		t.Fatalf("ids=%v, want exactly {lb_probe}", ids)
	}
}

// S历史问题（历史）：看门狗读取与 readAdminConfigBody 同源——>32MB 必须
// 返回超限哨兵（而非裸 LimitReader 的解码失败），调用方据此把「超限」与瞬时
// 读失败分开留痕。
func TestRunningRuleRouteIDs_oversizeClassified(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := io.Copy(w, &spaceFillReader{remaining: caddyAdminConfigMaxBytes + 1}); err != nil {
			t.Errorf("stream oversized config: %v", err)
		}
	}))
	defer srv.Close()

	_, err := runningRuleRouteIDs(srv.URL)
	if !errors.Is(err, errCaddyAdminConfigTooLarge) {
		t.Fatalf("err=%v, want errCaddyAdminConfigTooLarge（超限必须与解码失败区分）", err)
	}
}

// 回归形状：非 2xx 显式报错（不得把错误体当配置，也不得静默返回空路由集）。
func TestRunningRuleRouteIDs_nonOKStatusFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = io.WriteString(w, `{"error":"admin unavailable"}`)
	}))
	defer srv.Close()

	_, err := runningRuleRouteIDs(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("err=%v, want admin status in error", err)
	}
}

// 解析容忍度回归（S历史问题 修复的伴随约束）：读取统一到 readAdminConfigBody 后，
// 解析必须保持旧实现的容忍面——Decoder 只消费第一个顶层值，尾部多余字节不得把
// 「运行配置可读」降级为「读取失败」（否则启动守卫/看门狗探针按无正向证据放行，
// 外来路由告警与 历史问题 守卫静默失效）。
func TestRunningRuleRouteIDs_toleratesTrailingBytesAfterJSONValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// 多一个闭合符：旧 json.Decoder 忽略尾随内容（handlers 侧既有假 admin
		// fixture 即此形态）。
		_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"web":{"routes":[{"@id":"lb_probe"}]}}}}}}}`)
	}))
	defer srv.Close()

	ids, err := runningRuleRouteIDs(srv.URL)
	if err != nil {
		t.Fatalf("trailing bytes must not fail the probe: %v", err)
	}
	if !ids["lb_probe"] {
		t.Fatalf("ids=%v, want lb_probe", ids)
	}
}
