// Spike 辅助：极简权威 DNS，把任意 A 查询解析到 127.0.0.1（供 pebble VA 使用）。
// 仅测试用途；AAAA 返回空答案以避免 IPv6 干扰。
package harness

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// MockDNS 是一个把全部 A 记录指向 targetIPv4 的 UDP/TCP DNS 服务器。
type MockDNS struct {
	Addr     string
	target   string
	udp      *dns.Server
	tcp      *dns.Server
	queries  []string
	stopChan chan struct{}
}

// StartMockDNS 在 addr（如 127.0.0.1:8053）启动 mock DNS。
func StartMockDNS(addr, targetIPv4 string) (*MockDNS, error) {
	m := &MockDNS{Addr: addr, target: targetIPv4}

	handler := func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		for _, q := range req.Question {
			switch q.Qtype {
			case dns.TypeA:
				rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN A %s", q.Name, m.target))
				if err == nil {
					resp.Answer = append(resp.Answer, rr)
				}
			case dns.TypeAAAA:
				// 空答案：NOERROR/NODATA，强制使用 IPv4
			case dns.TypeSOA, dns.TypeNS:
				rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN NS spike.local.", q.Name))
				if err == nil {
					resp.Answer = append(resp.Answer, rr)
				}
			default:
				resp.Rcode = dns.RcodeSuccess
			}
		}
		_ = w.WriteMsg(resp)
	}

	m.udp = &dns.Server{Addr: addr, Net: "udp", Handler: dns.HandlerFunc(handler)}
	m.tcp = &dns.Server{Addr: addr, Net: "tcp", Handler: dns.HandlerFunc(handler)}

	udpReady := make(chan struct{})
	m.udp.NotifyStartedFunc = func() { close(udpReady) }
	go func() { _ = m.udp.ListenAndServe() }()
	<-udpReady
	go func() { _ = m.tcp.ListenAndServe() }()

	// 连通性自检
	c, err := net.DialTimeout("udp", addr, time.Second)
	if err != nil {
		return nil, err
	}
	_ = c.Close()

	return m, nil
}

// Stop 关闭 DNS 服务。
func (m *MockDNS) Stop() {
	if m == nil {
		return
	}
	if m.udp != nil {
		_ = m.udp.Shutdown()
	}
	if m.tcp != nil {
		_ = m.tcp.Shutdown()
	}
}