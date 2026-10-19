package main

// 起无有效 Host 不再回退监听地址（0.0.0.0 不可用），统一按 400 拒绝。

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// assertMalformedHostRejected 断言畸形/缺失 Host 的请求得到 400 且无 Location。
func assertMalformedHostRejected(t *testing.T, rawRequest string) {
	t.Helper()
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		redirectHTTP(bufio.NewReader(server), server)
		close(done)
	}()
	if _, err := client.Write([]byte(rawRequest)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400 (no valid Host must not reflect the bind address)", response.StatusCode)
	}
	if location := response.Header.Get("Location"); location != "" {
		t.Fatalf("Location=%q, want absent (must not reflect malformed/missing Host)", location)
	}
	_ = io.Closer(client).Close()
	<-done
}

func TestRedirectHTTP_hostWithBareCRRejected(t *testing.T) {
	assertMalformedHostRejected(t, "GET / HTTP/1.1\r\nHost: evil\rX-Injected: 1\r\n\r\n")
}

func TestRedirectHTTP_hostWithEmbeddedSpaceRejected(t *testing.T) {
	assertMalformedHostRejected(t, "GET / HTTP/1.1\r\nHost: evil .example.com\r\n\r\n")
}

// Location，跳转不可用；现按 400 拒绝。
func TestRedirectHTTP_missingHostRejected(t *testing.T) {
	assertMalformedHostRejected(t, "GET / HTTP/1.0\r\n\r\n")
}

// 回归形状：有效 Host 照常 302 到 https。
func TestRedirectHTTP_validHostStillRedirects(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		redirectHTTP(bufio.NewReader(server), server)
		close(done)
	}()
	if _, err := client.Write([]byte("GET /a?b=1 HTTP/1.1\r\nHost: public.example\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(client), &http.Request{Method: http.MethodGet})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if got := response.Header.Get("Location"); got != "https://public.example/a?b=1" {
		t.Fatalf("Location=%q", got)
	}
	if !strings.HasPrefix(response.Status, "302") {
		t.Fatalf("status=%q, want 302", response.Status)
	}
	_ = io.Closer(client).Close()
	<-done
}
