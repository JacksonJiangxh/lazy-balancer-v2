package caddychain

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// serveTunnel 升级请求（websocket 等）的隧道直通路径：不竞速，按链序建连
// 并转发握手，101 后双向拼接字节流；dial 失败换下一上游。
func (h *ChainProxy) serveTunnel(w http.ResponseWriter, r *http.Request) error {
	dialTimeout := time.Duration(h.DialTimeoutMS) * time.Millisecond
	ctx := r.Context()
	for idx, up := range h.Upstreams {
		conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", up.Dial)
		if err != nil {
			h.log().Debug("chain_proxy: 隧道建连失败",
				zap.Int("lane", idx), zap.String("upstream", up.Dial), zap.Error(err))
			continue
		}
		if up.Scheme == "https" {
			cfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec 与 transport 口径一致
			if sni := sniOf(up); sni != "" {
				cfg.ServerName = sni
			} else {
				cfg.ServerName = hostnameOf(up.Dial)
			}
			conn = tls.Client(conn, cfg)
		}
		if err := writeTunnelRequest(conn, r, up); err != nil {
			conn.Close()
			h.log().Debug("chain_proxy: 隧道请求写出失败",
				zap.Int("lane", idx), zap.String("upstream", up.Dial), zap.Error(err))
			continue
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, r)
		if err != nil {
			conn.Close()
			h.log().Debug("chain_proxy: 隧道响应读取失败",
				zap.Int("lane", idx), zap.String("upstream", up.Dial), zap.Error(err))
			continue
		}
		if resp.StatusCode == http.StatusSwitchingProtocols {
			return h.spliceTunnel(w, br, conn, resp, idx, up)
		}
		// 非 101：按普通响应透传（握手被上游拒绝等），链终止。
		conn.Close()
		resp.Body.Close()
		removeHopByHopHeaders(resp.Header)
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body) //nolint:errcheck
		return nil
	}
	h.log().Warn("chain_proxy: 隧道全部上游建连失败", zap.Int("lanes", len(h.Upstreams)))
	chainWriteError(w, http.StatusBadGateway, "chain_proxy: all upstreams failed (tunnel)")
	return nil
}

// writeTunnelRequest 手写原始 HTTP 请求（保留 Upgrade/Connection 等
// 逐跳头——隧道语义必需；StripRequestHeaders 已在 ServeHTTP 入口剥离）。
func writeTunnelRequest(conn net.Conn, r *http.Request, up ChainUpstream) error {
	host := up.Host
	if host == "" {
		host = up.Dial
	}
	var b bytes.Buffer
	requestURI := r.URL.RequestURI()
	if requestURI == "" {
		requestURI = "/"
	}
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", r.Method, requestURI)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	for k, vals := range r.Header {
		if k == "Host" {
			continue // Host 行已按回源目标写入
		}
		for _, v := range vals {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteString("\r\n")
		}
	}
	b.WriteString("\r\n")
	_, err := conn.Write(b.Bytes())
	return err
}

// spliceTunnel 完成 101 切换：回写 101 响应给客户端并双向拼接字节流。
func (h *ChainProxy) spliceTunnel(w http.ResponseWriter, br *bufio.Reader, upstreamConn net.Conn, resp *http.Response, idx int, up ChainUpstream) error {
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		chainWriteError(w, http.StatusBadGateway, "chain_proxy: client does not support hijacking")
		return nil
	}
	clientConn, clientRW, err := hj.Hijack()
	if err != nil {
		upstreamConn.Close()
		chainWriteError(w, http.StatusBadGateway, "chain_proxy: hijack failed")
		return nil
	}
	// 原样回写 101 状态行 + 头（http.Response.Write 会注入 Content-Length，
	// 101 语义不接受，手动拼接）。
	var rb bytes.Buffer
	fmt.Fprintf(&rb, "HTTP/1.1 %s\r\n", resp.Status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			rb.WriteString(k)
			rb.WriteString(": ")
			rb.WriteString(v)
			rb.WriteString("\r\n")
		}
	}
	rb.WriteString("\r\n")
	if _, err := clientConn.Write(rb.Bytes()); err != nil {
		clientConn.Close()
		upstreamConn.Close()
		return nil
	}
	h.log().Debug("chain_proxy: 隧道建立",
		zap.Int("lane", idx), zap.String("upstream", up.Dial))
	// 双向拼接：上游→客户端从 br 读（ReadResponse 可能预读后续帧）；
	// 客户端→上游从 Hijack 返回的 bufio 读（可能预存客户端数据）。
	go func() {
		io.Copy(upstreamConn, clientRW) //nolint:errcheck
		upstreamConn.Close()
	}()
	io.Copy(clientConn, br) //nolint:errcheck
	clientConn.Close()
	upstreamConn.Close()
	return nil
}
