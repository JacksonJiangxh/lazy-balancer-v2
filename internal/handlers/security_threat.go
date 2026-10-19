package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// 威胁情报库（v2.3.2 名单化重构）：内置只读三源的管理面——状态展示、
// 更新开关、手动更新、更新状态/日志。名单内容经 security_ip_lists 的
// system=1 内置行承载（IP 地址列表 tab 查看/导出），策略引用生效。
// 不提供任何源的新建/编辑/删除（用户不可删改）。

type threatSourceDTO struct {
	ID            int    `json:"id"`
	Name          string `json:"name"`
	DisplayName   string `json:"display_name"`
	URL           string `json:"url"`
	Format        string `json:"format"`
	UpdateEnabled bool   `json:"update_enabled"`
	EntryCount    int    `json:"entry_count"`
	Version       string `json:"version"`
	UpdateStatus  string `json:"update_status"`
	Message       string `json:"message"`
	LastChecked   string `json:"last_checked"`
	NextUpdate    string `json:"next_update"`
	// ListID 是该源对应的内置 IP 名单 id（前端「查看」跳转 IP 地址列表 tab）。
	ListID int `json:"list_id"`
}

func (h *Handlers) GetThreatLib(c *gin.Context) {
	sourceNames := make([]string, 0, len(db.ThreatSystemLists))
	args := make([]interface{}, 0, len(db.ThreatSystemLists))
	for _, sl := range db.ThreatSystemLists {
		sourceNames = append(sourceNames, "?")
		args = append(args, sl.Source)
	}
	where := "0"
	if len(sourceNames) > 0 {
		where = "t.name IN (" + strings.Join(sourceNames, ",") + ")"
	}
	rows, err := db.DB.Query(fmt.Sprintf(`SELECT t.id, t.name, t.display_name, t.url, t.format, t.update_enabled,
		t.entry_count, t.version, t.update_status, t.message, COALESCE(t.last_checked,''), COALESCE(t.next_update,'')
		FROM security_threat_sources t
		WHERE %s ORDER BY t.id`, where), args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
		return
	}
	defer rows.Close()
	sources := []threatSourceDTO{}
	totalEntries := 0
	for rows.Next() {
		var s threatSourceDTO
		if err := rows.Scan(&s.ID, &s.Name, &s.DisplayName, &s.URL, &s.Format, &s.UpdateEnabled,
			&s.EntryCount, &s.Version, &s.UpdateStatus, &s.Message, &s.LastChecked, &s.NextUpdate); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
			return
		}
		sources = append(sources, s)
		totalEntries += s.EntryCount
	}
	// SEC-C-N1（历史 历史问题·家族漏收敛）：迭代错误（rows.Err）不得以
	// 「部分/空列表 + 200」返回——与 历史问题/历史问题 在总览/事件列表建立的
	// 「残缺列表不得以 200」口径对齐（Scan 失败分支同响应形）。
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁情报库失败: " + err.Error()})
		return
	}
	// 与 GetCrawlerLib 同一批量形态：内置名单最多 200 行，一次预载代替逐源
	// 点查；缺行保留 list_id=0，查询/扫描/迭代故障均显式 500。
	listRows, err := db.DB.Query(`SELECT name, id FROM security_ip_lists WHERE system=1`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取内置名单失败: " + err.Error()})
		return
	}
	listIDs := map[string]int{}
	for listRows.Next() {
		var name string
		var id int
		if err := listRows.Scan(&name, &id); err != nil {
			listRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取内置名单失败: " + err.Error()})
			return
		}
		listIDs[name] = id
	}
	if err := listRows.Err(); err != nil {
		listRows.Close()
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取内置名单失败: " + err.Error()})
		return
	}
	listRows.Close()
	for i := range sources {
		sources[i].ListID = listIDs[db.ThreatListNameBySource(sources[i].Name)]
	}
	days, hhmm := services.ThreatSchedule()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"sources":       sources,
		"total_entries": totalEntries,
		"auto_update":   services.ThreatAutoUpdateEnabled(),
		"schedule_days": days,
		"schedule_time": hhmm,
	}})
}

// UpdateThreatAutoUpdate 任务级总开关（规则库卡片父行开关；镜像
// UpdateCRSAutoUpdate/UpdateIP2RegionAutoUpdate 形态）。逐源 update_enabled
// 决定任务更新哪些源（弹框内开关），与总闸解耦。
func (h *Handlers) UpdateThreatAutoUpdate(c *gin.Context) {
	if !guardConfiguredJSONBody(c) {
		return
	}
	var body struct {
		AutoUpdate *bool `json:"auto_update"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.AutoUpdate == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	// 历史问题-7：与 UpdateCRSAutoUpdate 同口径主节点门（历史问题 B-#4）——从节点
	// 状态行在集群同步段内，本地写会被下次快照覆盖。
	if !requireMasterNode(c) {
		return
	}
	if err := services.SetThreatAutoUpdate(*body.AutoUpdate); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
		return
	}
	recordAudit(c, "更新", "威胁情报库", "自动更新总开关")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// UpdateThreatSchedule 任务级排程保存（弹框「定时更新」区；镜像
// UpdateCRSSchedule 形态——保存即重排 next_update：WHERE update_enabled=1
// 一律重排（2026-09-25 裁定，含失败源））。
func (h *Handlers) UpdateThreatSchedule(c *gin.Context) {
	days, hhmm, ok := h.updateLibSchedule(c, services.SetThreatSchedule)
	if !ok {
		return
	}
	recordAudit(c, "更新", "威胁情报库", fmt.Sprintf("定时更新设置：每周%s %s", scheduleDaysLabel(days), hhmm))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// UpdateThreatSourceFlags 仅允许改 update_enabled——名单化后「应用」=
// 策略引用名单（无独立 apply 开关）。请求体携带的其余字段一律忽略
// （内置源不可变造）。
func (h *Handlers) UpdateThreatSourceFlags(c *gin.Context) {
	if !guardConfiguredJSONBody(c) {
		return
	}
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的源 ID"})
		return
	}
	var body struct {
		UpdateEnabled *bool `json:"update_enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求无效"})
		return
	}
	if body.UpdateEnabled == nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无可更新字段"})
		return
	}
	// 历史问题-7：与 UpdateCRSAutoUpdate 同口径主节点门（历史问题 B-#4）。
	if !requireMasterNode(c) {
		return
	}
	var name string
	if err := db.DB.QueryRow(`SELECT name FROM security_threat_sources WHERE id=?`, id).Scan(&name); err != nil {
		// 历史问题：DB 故障不得误报 404——缺行=404，其余=500（与
		// security_overview 的 ErrNoRows→404 同族契约）。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "威胁库源不存在"})
		} else {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取威胁库源失败: " + err.Error()})
		}
		return
	}
	if _, err := db.DB.Exec(`UPDATE security_threat_sources SET update_enabled=?, updated_at=datetime('now') WHERE id=?`, *body.UpdateEnabled, id); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新失败: " + err.Error()})
		return
	}
	if *body.UpdateEnabled {
		services.ArmThreatFirstSlots()
	}
	recordAudit(c, "更新", "威胁情报库", fmt.Sprintf("%s 更新开关", name))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已更新"})
}

// StartThreatLibUpdate 手动触发更新（主节点；镜像 StartCRSUpdate 的受理/
// 重复任务 409 语义）。
func (h *Handlers) StartThreatLibUpdate(c *gin.Context) {
	if !requireMasterNode(c) {
		return
	}
	// V2（历史用户裁定）：手动触发统一经任务引擎（同 StartCRSUpdate）。
	te := services.TaskEngine()
	if te == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "任务引擎未初始化"})
		return
	}
	if te.IsTaskInFlight("threat") {
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "任务运行中，请稍后重试"})
		return
	}
	op := auditOperator(c)
	// 历史问题/A85历史问题-2：响应前同步预占位，拒绝时不得伪报 running。
	if err := services.TriggerTaskAsync(te, "threat", services.TriggerAuditContext{
		Operator: op, Family: "威胁情报库", Name: "威胁情报库更新",
	}); err != nil {
		respondTaskTriggerAdmissionError(c, err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"status": "running", "trigger": "manual"}})
}

// GetThreatLibUpdateStatus 任务级状态（弹框轮询；镜像 GetCRSUpdateStatus 形态）。
func (h *Handlers) GetThreatLibUpdateStatus(c *gin.Context) {
	mgr := services.GetThreatUpdateManager()
	if mgr == nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁库更新服务未初始化"})
		return
	}
	snap := mgr.StatusSnapshot()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: snap})
}

// GetThreatLibUpdateLogs 更新日志（含上一代轮转文件，镜像 GetCRSUpdateLogs）。
func (h *Handlers) GetThreatLibUpdateLogs(c *gin.Context) {
	// 单一日志数据源：同 GetCRSUpdateLogs。
	logPath := taskengine.TaskLogPath("threat")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": readUpdateLogWithRotation(logPath)}})
}
