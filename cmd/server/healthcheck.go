package main

import (
	"crypto/tls"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

// 容器 HEALTHCHECK 走二进制自带子命令：不派生 shell/wget/ssl_client，
// 探针本身只有一个进程。此前的 `sh -c wget https://...` 在 PID 1 不回收
// 孤儿的镜像里会持续累积僵尸（生产实证：十余小时堆到 2252 个 ssl_client，
// 打满 cgroup pids 配额，连 `cat` 都无法 fork）。
//
// 语义与旧探针保持一致：HTTPS 先行（面板管理 TLS 是常态），失败回落明文；
// 两者都只认 200。回环地址 + 自签证书 → 忽略证书校验只用于本机存活判定，
// 不承担证书正确性验证。
//
// 探测端口读 PANEL_PORT（与 internal/config 同名 env 同源同默认值）：
// host 模式下 8000 被宿主服务占用时用户以 PANEL_PORT 换口，面板真实监听
// 新口，探针必须跟随——否则打旧口永远失败，容器长期误显 unhealthy
// （面板功能完全正常，纯状态误报）。此前的硬编码 8000 形态下换口部署
// 必须在 compose 里覆盖 healthcheck 才能恢复判定，属双重维护面。

var (
	// 单次尝试上限：两段（HTTPS→HTTP）合计必须小于 Docker HEALTHCHECK 的
	// --timeout=5s，否则探针会先被运行时杀掉（137），日志里只剩「超时」。
	healthcheckTimeout = 2 * time.Second
)

// defaultHealthcheckPort 是探测端口默认值，与 internal/config 的 defaultPort
// （面板 HTTP 端口默认值）同口径：PANEL_PORT 未设/非法/越界时探 8000。
// 不直接 import internal/config（main 包引入 services/config 链会拖入 DB 装配
// 依赖，探针路径已钉测「不触碰启动依赖」），以常量+注释对齐替代单源。
const defaultHealthcheckPort = 8000

// healthcheckPanelPort 从 PANEL_PORT 解析探测端口：未设→默认；非数字/越界
// （1-65535）→ 告警后回落默认（与 envPort 同口径，非法值不静默生效——探错
// 端口和探旧端口一样是误报源，必须留痕）。
func healthcheckPanelPort() int {
	value := os.Getenv("PANEL_PORT")
	if value == "" {
		return defaultHealthcheckPort
	}
	port, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || port < 1 || port > 65535 {
		println("healthcheck: invalid PANEL_PORT=" + value + "; falling back to " + strconv.Itoa(defaultHealthcheckPort))
		return defaultHealthcheckPort
	}
	return port
}

// healthcheckURLs 返回两段探测地址（HTTPS 先行 → 明文回落）。变量化以便
// 测试注入替身；runHealthcheck 每次调用时求值，保证探针读到当次 env。
var healthcheckURLs = func() []string {
	port := healthcheckPanelPort()
	return []string{
		"https://127.0.0.1:" + strconv.Itoa(port) + "/health",
		"http://127.0.0.1:" + strconv.Itoa(port) + "/health",
	}
}

// healthcheckRequested 判断是否以健康检查模式启动。只认首个参数，避免与
// 既有 -config/-init 标志解析相互影响。
func healthcheckRequested(args []string) bool {
	return len(args) > 1 && args[1] == "--healthcheck"
}

// runHealthcheck 执行一次存活探测并返回进程退出码：0=健康，1=不健康。
func runHealthcheck() int {
	client := &http.Client{
		Timeout: healthcheckTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // 回环自签
		},
		// 不跟随跳转：面板在管理 TLS 模式下可能把明文请求 302 到登录页，
		// 跟随会把「登录页 200」误判为健康。健康判定只认第一跳 200。
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for _, url := range healthcheckURLs() {
		if probeHealth(client, url) {
			return 0
		}
	}
	return 1
}

func probeHealth(client *http.Client, url string) bool {
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
