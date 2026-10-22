package handlers

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// exitProcess 进程退出测试钩（归位：唯一生产消费方是
// restartProcess 的延迟退出回退，钩随语义属主落户 system.go；前历史
// 落位于 admintls.go）。生产=os.Exit，测试替换为 channel 信号。
var exitProcess = os.Exit

// restartProcess 触发进程重启：优先走 services 统一重启信号——与集群
// 同步的 Admin TLS 热切换同一触发器（main 注入优雅停机信号，HTTP 优雅关停后
// 退出，进程级设置随之生效）；未注入（独立/测试环境）时回退旧行为：延迟
// 500ms 待响应写出后经 exitProcess（测试可替换变量）退出。
func restartProcess() {
	if services.RequestRestart() {
		return
	}
	go func() {
		time.Sleep(500 * time.Millisecond)
		exitProcess(0)
	}()
}

// RestartService exits the process after responding; the container's
// restart policy brings the service back up (used to apply process-level
// settings such as the Caddy log timezone).
func (h *Handlers) RestartService(c *gin.Context) {
	recordAudit(c, "重启", "系统", "用户触发服务重启")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "服务正在重启"})
	restartProcess()
}

func (h *Handlers) GetSystemInfo(c *gin.Context) {
	brandingCfg := loadBrandingConfig(h.cfg.DataDir)
	version := h.cfg.Version
	if brandingCfg.Version != "" {
		version = brandingCfg.Version
	}
	info := models.SystemInfo{
		NodeMode:      "master",
		IPAddress:     getOutboundIP(),
		Hostname:      getHostname(),
		OSInfo:        getOSInfo(),
		Kernel:        getKernel(),
		Architecture:  getArchitecture(),
		NetworkIPs:    getNetworkIPs(),
		CaddyVersion:  getCaddyVersion(),
		RunningStatus: "running",
		Uptime:        getUptime(),
		Version:       version,
	}
	// 角色查询失败/库未装配时不得静默呈现 master——
	// 排障窗口里「显示主节点」会把方向引偏（同域写门 requireMasterNode 对同一
	// 故障响亮 500）。三态化：unknown 并留 warn。
	switch {
	case db.DB == nil:
		services.Logf("warn", "system info: 数据库未装配，节点角色未知（node_mode=unknown）")
		info.NodeMode = "unknown"
	default:
		if isMaster, err := services.RoleOf(c.Request.Context(), db.DB); err != nil {
			services.Logf("warn", "system info: 节点角色查询失败，按 unknown 呈现: %v", err)
			info.NodeMode = "unknown"
		} else if !isMaster {
			info.NodeMode = "slave"
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

func (h *Handlers) GetSystemMetrics(c *gin.Context) {
	metrics, err := getSystemMetrics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetRealtimeTraffic(c *gin.Context) {
	traffic, err := getRealtimeTraffic()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: traffic})
}

func (h *Handlers) GetConnectionStats(c *gin.Context) {
	stats, err := getConnectionStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: stats})
}

func (h *Handlers) GetAppLogs(c *gin.Context) {
	// 运行日志路径经 logPaths 统一口径——LOG_FILE 空串
	// 时兜底默认运行日志(与 GetLogStats 同源),消除空串路径读出的恒空 200。
	_, logPath := logPaths(h.cfg)
	const maxBytes = 128 * 1024
	const maxLines = 500

	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": ""}})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "日志文件不可读: " + err.Error()})
		return
	}
	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}
	f, err := os.Open(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "打开日志文件失败: " + err.Error()})
		return
	}
	defer f.Close()
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志失败: " + err.Error()})
		return
	}
	// Stat 与读取之间日志增长/文件被替换为 FIFO 时，
	// 无界 io.ReadAll 会读入远超 maxBytes 的数据。与任务日志/证书任务日志
	// 尾读同口径加上限（窗口本身 ≤128KB）。
	data, err := io.ReadAll(io.LimitReader(f, maxBytes))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志失败: " + err.Error()})
		return
	}
	// 窗口起点可能落在某行中段——切在多字节
	// UTF-8 rune 中间时首行残段带无效字节,JSON 编码后以 U+FFFD 污染输出。
	// 统一口径抽享 tailLogWindow（GetCaddyLogs 同 helper）。
	data = tailLogWindow(data, startOffset)
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": strings.Join(lines, "\n")}})
}
