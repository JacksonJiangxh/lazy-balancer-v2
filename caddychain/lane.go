package caddychain

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// hopHeaders RFC 7230 逐跳头（与 net/http/httputil 的 removeHopHeaders 同清单）。
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// removeHopByHopHeaders 剥离逐跳头及 Connection 头列出的专用头。
func removeHopByHopHeaders(h http.Header) {
	for _, f := range hopHeaders {
		h.Del(f)
	}
	for _, connVal := range h.Values("Connection") {
		for _, token := range strings.Split(connVal, ",") {
			token = strings.TrimSpace(token)
			if token != "" {
				h.Del(token)
			}
		}
	}
}

// bufferBody 物化请求体用于车道间重放：读取至多 limit 字节。返回
// (data, overflow, err)：overflow=true 表示超过重放上限——data 为已读前缀
// （连同越界的那一个字节，无丢失），车道 0 需以 MultiReader 续传原始流。
func bufferBody(r *http.Request, limit int) ([]byte, bool, error) {
	if r.Body == nil || r.ContentLength == 0 {
		return nil, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if err != nil {
		return nil, false, err
	}
	return data, int64(len(data)) > int64(limit), nil
}

// buildLaneRequest 按车道上游独立构造请求（参考项目 resolveActionForOrigin
// 语义：每一路按自己的源站重建 URL/Host，不复用首路）。
func (h *ChainProxy) buildLaneRequest(ctx context.Context, tpl *http.Request, up ChainUpstream, body io.Reader, bodyLen int64) *http.Request {
	out := tpl.Clone(ctx)
	out.RequestURI = "" // 服务端请求 RequestURI 在客户端请求中非法
	scheme := up.Scheme
	if scheme == "" {
		scheme = "http"
	}
	out.URL = &url.URL{
		Scheme:   scheme,
		Host:     up.Dial,
		Path:     tpl.URL.Path,
		RawPath:  tpl.URL.RawPath,
		RawQuery: tpl.URL.RawQuery,
	}
	host := up.Host
	if host == "" {
		host = up.Dial
	}
	out.Host = host
	removeHopByHopHeaders(out.Header)
	setForwardHeaders(out.Header, tpl)
	if body != nil {
		out.Body = io.NopCloser(body)
		if bodyLen >= 0 {
			out.ContentLength = bodyLen
			out.TransferEncoding = nil // 体已物化，长度已知，无需 chunked
		}
	} else {
		out.Body = nil
		out.ContentLength = 0
		out.TransferEncoding = nil
	}
	return out
}

// setForwardHeaders 追加标准转发头（X-Forwarded-For 追加客户端 IP，
// X-Forwarded-Proto/Host 按入口请求设置），与 reverse_proxy 默认行为同向。
func setForwardHeaders(hdr http.Header, tpl *http.Request) {
	if clientIP, _, err := net.SplitHostPort(tpl.RemoteAddr); err == nil && clientIP != "" {
		if prior := hdr.Get("X-Forwarded-For"); prior != "" {
			hdr.Set("X-Forwarded-For", prior+", "+clientIP)
		} else {
			hdr.Set("X-Forwarded-For", clientIP)
		}
	}
	proto := "http"
	if tpl.TLS != nil {
		proto = "https"
	}
	hdr.Set("X-Forwarded-Proto", proto)
	if tpl.Host != "" {
		hdr.Set("X-Forwarded-Host", tpl.Host)
	}
}

// roundTrip executes one lane's exchange. 返回 (resp, headerTimedOut, err)。
// 成功时 resp.Body 仍开放（调用方负责关闭）；响应头等待由 laneTimeout 定时器
// 截断（到期 cancel laneCtx 并置 headerTimedOut）——响应头已到达则定时器即刻
// 停止，body 流不受超时约束。err 时 laneCtx 已被取消（连接释放）。
func (h *ChainProxy) roundTrip(laneCtx context.Context, laneCancel context.CancelFunc, idx int, tpl *http.Request, up ChainUpstream, body io.Reader, bodyLen int64) (*http.Response, bool, error) {
	req := h.buildLaneRequest(laneCtx, tpl, up, body, bodyLen)
	var hdrTimedOut atomic.Bool
	var timer *time.Timer
	timeout := time.Duration(h.RequestTimeoutMS) * time.Millisecond
	if timeout > 0 {
		timer = time.AfterFunc(timeout, func() {
			hdrTimedOut.Store(true)
			laneCancel()
		})
	}
	start := time.Now()
	resp, err := h.transportFor(up).RoundTrip(req)
	elapsed := time.Since(start)
	if timer != nil {
		timer.Stop()
	}
	if err != nil {
		laneCancel()
		if hdrTimedOut.Load() {
			h.log().Debug("chain_proxy: lane 超时截断",
				zap.Int("lane", idx), zap.String("upstream", up.Dial), zap.Duration("elapsed", elapsed))
			return nil, true, err
		}
		h.log().Debug("chain_proxy: lane 交换错误",
			zap.Int("lane", idx), zap.String("upstream", up.Dial), zap.Duration("elapsed", elapsed), zap.Error(err))
		return nil, false, err
	}
	h.log().Debug("chain_proxy: lane 收到响应头",
		zap.Int("lane", idx), zap.String("upstream", up.Dial),
		zap.Int("status", resp.StatusCode), zap.Duration("elapsed", elapsed))
	return resp, false, nil
}

// laneResult 车道落定结果。resp 非 nil 时 Body 开放，由编排方关闭。
type laneResult struct {
	idx      int
	resp     *http.Response
	err      error
	timedOut bool
}

// serveRace 竞速编排主循环（多上游、请求体已物化的路径）。
func (h *ChainProxy) serveRace(w http.ResponseWriter, r *http.Request, body []byte) error {
	ctx := r.Context()
	n := len(h.Upstreams)
	results := make(chan laneResult, n)
	cancels := make([]context.CancelFunc, n)
	bodyReader := func() io.Reader {
		if body == nil {
			return nil
		}
		return bytes.NewReader(body)
	}
	bodyLen := int64(len(body))
	launch := func(idx int) {
		laneCtx, cancel := context.WithCancel(ctx)
		cancels[idx] = cancel
		up := h.Upstreams[idx]
		go func() {
			resp, timedOut, err := h.roundTrip(laneCtx, cancel, idx, r, up, bodyReader(), bodyLen)
			results <- laneResult{idx: idx, resp: resp, err: err, timedOut: timedOut}
		}()
	}

	launch(0)
	launchNext := 1
	settledCount := 0
	var winner *laneResult
	var firstBad *laneResult
	timeoutCount := 0
	interval := time.Duration(h.RaceIntervalMS) * time.Millisecond

	var timer *time.Timer
	var timerC <-chan time.Time
	arm := func() {
		if winner != nil || launchNext >= n || interval <= 0 {
			return
		}
		if timer == nil {
			timer = time.NewTimer(interval)
			timerC = timer.C
		} else {
			timer.Reset(interval)
		}
	}
	arm()

	for winner == nil && settledCount < n {
		select {
		case res := <-results:
			settledCount++
			if res.resp != nil && res.resp.StatusCode < 400 {
				winner = &res
				break
			}
			if res.resp != nil {
				// bad 响应（status>=400）：记录首个到达者——仅用于收尾判定与
				// 响应体回收（全挂时返回干净 404 不透传），其余即刻释放连接。
				if firstBad == nil {
					firstBad = &res
				} else {
					res.resp.Body.Close()
				}
			} else if res.timedOut {
				timeoutCount++
			}
			// 失败即切：还有未发车道则立即发出。
			if launchNext < n {
				launch(launchNext)
				launchNext++
				arm()
			}
		case <-timerC:
			if winner == nil && launchNext < n {
				launch(launchNext)
				launchNext++
				arm()
			}
		}
	}
	if timer != nil {
		if !timer.Stop() {
			select {
			case <-timerC:
			default:
			}
		}
	}

	if winner != nil {
		// 取消其余车道（含 winner 之外的全部在途/已落定车道）；winner 的
		// context 在 body 流结束后由 writeUpstreamResponse 取消。
		for idx, cancel := range cancels {
			if cancel != nil && idx != winner.idx {
				cancel()
			}
		}
		if firstBad != nil {
			firstBad.resp.Body.Close()
		}
		// 在途车道落定后释放其响应体（竞速取消本身不算故障，仅关连接）。
		go drainLaneResults(results, n-settledCount)
		return h.writeUpstreamResponse(w, winner.resp, cancels[winner.idx])
	}
	if firstBad != nil {
		// 全挂：不再透传最先到达的 bad 响应（否则对象存储 XML/后端错误页会
		// 被原样展示给客户端）；回收响应体并统一返回干净 404。
		for _, cancel := range cancels {
			if cancel != nil {
				cancel()
			}
		}
		firstBad.resp.Body.Close()
		go drainLaneResults(results, n-settledCount)
		chainWriteError(w, http.StatusNotFound, "404 Not Found")
		return nil
	}
	// 全部车道错误：取消全部，502；全部为兜底超时则 504。
	for _, cancel := range cancels {
		if cancel != nil {
			cancel()
		}
	}
	status := http.StatusBadGateway
	msg := "chain_proxy: all upstreams failed"
	if timeoutCount > 0 && timeoutCount == settledCount {
		status = http.StatusGatewayTimeout
		msg = "chain_proxy: all upstreams timed out"
	}
	h.log().Warn("chain_proxy: 全部上游失败",
		zap.Int("lanes", n), zap.Int("timeout_lanes", timeoutCount), zap.Int("status", status))
	chainWriteError(w, status, msg)
	return nil
}

// drainLaneResults 等待剩余车道落定并释放其响应体（连接回收）。
func drainLaneResults(results <-chan laneResult, remaining int) {
	for i := 0; i < remaining; i++ {
		res := <-results
		if res.resp != nil {
			res.resp.Body.Close()
		}
	}
}

// serveSingleLane 退化直通路径：请求体超重放上限（前缀 + 原始流续传）或链上
// 仅一个上游。语义与竞速车道 0 一致，但不竞速不重放；上游 404 与全挂同口径，
// 返回干净 404（不透传后端错误报文）。
func (h *ChainProxy) serveSingleLane(w http.ResponseWriter, r *http.Request, prefix []byte, overflow bool) error {
	var body io.Reader
	if overflow {
		// prefix 含越界字节（见 bufferBody），无丢失续传。
		body = io.MultiReader(bytes.NewReader(prefix), r.Body)
	} else if prefix != nil {
		body = bytes.NewReader(prefix)
	} else {
		body = r.Body
	}
	laneCtx, cancel := context.WithCancel(r.Context())
	up := h.Upstreams[0]
	resp, timedOut, err := h.roundTrip(laneCtx, cancel, 0, r, up, body, r.ContentLength)
	if err != nil {
		status := http.StatusBadGateway
		msg := "chain_proxy: upstream failed"
		if timedOut {
			status = http.StatusGatewayTimeout
			msg = "chain_proxy: upstream timed out"
		}
		chainWriteError(w, status, msg)
		return nil
	}
	if resp.StatusCode == http.StatusNotFound {
		// 上游 404：与全挂口径一致——不回传后端错误报文（对象存储 XML 等），
		// 返回干净 404；其余状态码（5xx/4xx 等语义错误）保持透传不误标。
		resp.Body.Close()
		cancel()
		chainWriteError(w, http.StatusNotFound, "404 Not Found")
		return nil
	}
	return h.writeUpstreamResponse(w, resp, cancel)
}

// writeUpstreamResponse 流式写出上游响应（竞速胜者 / 单车道非 404 直通）。
// done 在流结束后取消车道 context（连接回收）；nil 则跳过。
func (h *ChainProxy) writeUpstreamResponse(w http.ResponseWriter, resp *http.Response, done context.CancelFunc) error {
	defer resp.Body.Close()
	if done != nil {
		defer done()
	}
	removeHopByHopHeaders(resp.Header)
	for k, vals := range resp.Header {
		for _, v := range vals {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	// 逐块写出并冲刷（32KB 块；SSE 类流式响应自然受益）。
	buf := make([]byte, 32*1024)
	flusher, _ := w.(http.Flusher)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			if _, werr := w.Write(buf[:n]); werr != nil {
				return nil // 客户端断开，静默收尾
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			break
		}
	}
	return nil
}

// chainWriteError 写出纯文本错误响应。
func chainWriteError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	fmt.Fprintln(w, msg)
}
