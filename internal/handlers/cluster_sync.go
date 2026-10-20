package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) GetClusterSnapshot(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	sinceVersion, _ := strconv.Atoi(c.Query("since_version"))
	snapshot, changed, err := h.clusterService.Snapshot(c.Request.Context(), sinceVersion, c.Query("fingerprint"), authenticatedClusterToken(c))
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "生成集群快照失败", err)
		return
	}
	if !changed {
		// 304「配置无变化」只在从节点侧留痕；主节点每个同步周期都会被
		// 轮询命中，记录只会制造噪音，无需在此审计。
		c.Status(http.StatusNotModified)
		return
	}
	if nodeIDValue, exists := c.Get("cluster_node_id"); exists {
		if nodeID, ok := nodeIDValue.(int); ok {
			// 历史问题(历史):节点名查询失败/为空(节点已删除等)回退
			// 「节点 #<id>」,不再落尾部空名的「节点 」。
			var nodeName string
			nodeLabel := fmt.Sprintf("节点 #%d", nodeID)
			if err := db.DB.QueryRow("SELECT COALESCE(name,'') FROM nodes WHERE id=?", nodeID).Scan(&nodeName); err == nil && nodeName != "" {
				nodeLabel = fmt.Sprintf("节点 %s", nodeName)
			}
			services.RecordAuditLog("system", "同步下发", "集群节点", services.FormatAuditDetail(nodeLabel, fmt.Sprintf("下发版本：%d", snapshot.Version)), c.ClientIP())
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "快照生成成功", Data: snapshot})
}

// authenticatedClusterToken 读取集群令牌。历史问题(历史):两处调用方
// 均挂 clusterTokenAuth 之后,该中间件成功时恒 Set("cluster_token")——
// 头部回退分支不可达且 TrimPrefix 语义与中间件 bearerToken 分叉,收敛为
// 只读 ctx 值(空串=未认证,唯一生产行为)。
func authenticatedClusterToken(c *gin.Context) string {
	return c.GetString("cluster_token")
}

func (h *Handlers) PullClusterSnapshot(c *gin.Context) {
	// 主节点无同步对象：入口直接拒绝，不调 Pull——否则「主节点不能从其他
	// 节点同步」会经 recordSyncError 写入 last_sync_error 且无自动清除路径，
	// 节点页面持续显示假错误（历史问题 历史修复）。前端按钮只对从节点渲染，此为后端防御。
	// 门控查询失败时按主节点语义拒绝（历史问题 发现2）：放行会让主节点走 Pull
	// 命中 errSyncMasterNoPull 返回 500 + 误导审计「同步失败」，实际
	// 只是瞬时 DB 读错。400 文案与真主节点一致，前端无歧义。
	if role, err := services.RoleOf(c.Request.Context(), db.DB); err != nil || role {
		clusterError(c, http.StatusBadRequest, "主节点无需手动同步", err)
		return
	}
	// 历史问题（历史 历史问题，历史修复 同族收敛）：与 SetClusterMode/Promote/
	// ForgetClusterPins 同口径——装配缺失时 503，不得 nil 指针 panic 落成
	// Gin recovery 的 500 空体。
	if h.syncService == nil {
		clusterError(c, http.StatusServiceUnavailable, "同步服务未初始化", nil)
		return
	}
	// 手动同步会写 global_config/lb_rules 等导入全量替代表，导入会话
	// 的排空阶段不覆盖 Daemon/手动 Pull（coordinator 明确 Daemon 不在范围）——
	// 窗口内提交要么被导入覆盖，要么阻塞在 SQLite 写锁上至 busy_timeout 后 500。
	// 与节点写族同口径 409 历史修复；后台 daemon 仍按「主节点为准」保留。
	if configImportBusy() {
		c.JSON(http.StatusConflict, models.APIResponse{Code: http.StatusConflict, Message: "配置导入进行中，暂不能手动同步，请稍后重试"})
		return
	}
	result, err := h.syncService.Pull(c.Request.Context())
	if err != nil {
		recordAudit(c, "同步失败", "集群同步", err.Error())
		clusterError(c, http.StatusInternalServerError, "同步失败: "+err.Error(), err)
		return
	}
	if result.Changed {
		recordAudit(c, "手动同步", "集群同步", services.FormatAuditDetail("应用版本："+strconv.Itoa(result.AppliedVersion), services.AuditResultPart("success")))
	} else {
		recordAudit(c, "手动同步", "集群同步", services.FormatAuditDetail("配置无变化", services.AuditResultPart("success")))
	}
	h.syncService.Resume()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "手动同步完成", Data: result})
}

// ForgetClusterPins 是从节点管理员的 PinMismatch 补救端点（M13②）：主节点更换
// 管理面板证书后从节点同步持续指纹不匹配，运维确认新证书合法后清空全部 TOFU
// 指纹钉（内存缓存+磁盘 pin 文件），下一同步 tick 按新证书重新钉扎。仅 admin
// 路由组可达（readOnlyGuard 的 /cluster/* 白名单保证从节点可用），操作留审计。
func (h *Handlers) ForgetClusterPins(c *gin.Context) {
	// 复审裁定 4：本端点语义=清除「本机作为从节点」对主节点证书的钉扎；主节点
	// 的 pin 目录存的是各从节点钉（服务控制 TOFU 消费），误调会整体重置从节点
	// 钉扎——主节点直接拒绝。
	if h.syncService == nil {
		clusterError(c, http.StatusServiceUnavailable, "同步服务未初始化", nil)
		return
	}
	// 主节点守卫不得随装配缺失 历史修复——h.clusterService 为 nil
	// 时此前直接放行清除本机全部 TOFU 钉（主节点误清从节点钉的风险路径）。
	// 与 PullClusterSnapshot「装配缺失 → 503」及本文件其余 历史修复 口径
	// 一致：无法确认角色即拒绝。
	if h.clusterService == nil {
		clusterError(c, http.StatusServiceUnavailable, "集群服务未初始化，已拒绝清除（fail-closed）", nil)
		return
	}
	{
		// 历史问题(历史):门控 历史修复——查询失败按主节点语义拒绝
		// (与 PullClusterSnapshot 的 历史问题 发现2 口径一致),防瞬时 DB 读错绕过
		// 守卫误清从节点钉扎。
		isMaster, err := h.clusterService.IsMaster(c.Request.Context())
		if err != nil {
			clusterError(c, http.StatusInternalServerError, "无法确认节点角色，已拒绝清除（fail-closed）", err)
			return
		}
		if isMaster {
			recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail("主节点调用被拒绝：主节点 pin 目录存各从节点钉", services.AuditResultPart("failure")))
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "主节点无需清除指纹（本端点仅从节点使用）"})
			return
		}
	}
	removed, err := h.syncService.ForgetPins()
	if err != nil {
		recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail(err.Error(), services.AuditResultPart("failure")))
		clusterError(c, http.StatusInternalServerError, "清除主节点证书指纹失败: "+err.Error(), err)
		return
	}
	recordAudit(c, "清除", "证书指纹", services.FormatAuditDetail(
		fmt.Sprintf("已清除 %d 个主节点证书指纹，下次同步将重新验证并钉扎", removed),
		services.AuditResultPart("success"),
	))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已清除全部主节点证书指纹，下次同步将按当前证书重新钉扎"})
}

// ForgetClusterNodePin 是主节点侧「单节点 TOFU 指纹钉」重置端点（历史问题，与从节点
// 侧 ForgetClusterPins 对称）：从节点更换管理面板证书后，主节点对其服务控制持续
// PinMismatch；本端点按节点（access_url 优先，回退 protocol://ip:port）定位并
// 删除对应 pin 文件（内存缓存一并失效），下次服务控制按从节点当前证书重新钉扎。
// 仅主节点管理员可达（requireMaster + admin 路由组），操作留审计。
func (h *Handlers) ForgetClusterNodePin(c *gin.Context) {
	if rejectNodeWriteDuringImport(c) {
		return
	}
	if !h.requireMaster(c) {
		return
	}
	nodeID, err := strconv.Atoi(c.Param("id"))
	if err != nil || nodeID <= 0 {
		clusterError(c, http.StatusBadRequest, "节点编号无效", err)
		return
	}
	host, err := h.clusterService.ForgetNodePin(c.Request.Context(), nodeID)
	if err != nil {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, services.ErrNotMasterNode):
			// 历史修复 历史问题：降级竞态 403 与 requireMaster 门同源带头（保留失败审计）。
			c.Header("X-LB-Error-Code", masterRequiredErrorCode)
			status = http.StatusForbidden
		case errors.Is(err, services.ErrNodeNotFound):
			status = http.StatusNotFound
		case errors.Is(err, services.ErrNoClusterPin):
			// 幂等：无钉可删（http 地址/从未服务控制过）按成功语义回应，
			// 不阻断运维排障流程。
			recordAudit(c, "清除", "证书指纹", services.FormatAuditDetail(
				fmt.Sprintf("节点 %d", nodeID), "该节点没有已钉扎的证书指纹，无需清除"))
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "该节点没有已钉扎的证书指纹，无需清除"})
			return
		}
		recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail(fmt.Sprintf("节点 %d", nodeID), err.Error()))
		clusterError(c, status, "清除节点证书指纹失败", err)
		return
	}
	if h.syncService != nil {
		h.syncService.ForgetNodePinCache(host)
	}
	recordAudit(c, "清除", "证书指纹", services.FormatAuditDetail(
		fmt.Sprintf("节点 %d（%s）", nodeID, host), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已清除该节点的证书指纹，下次服务控制将按其当前证书重新钉扎"})
}

// GetClusterWafFiles serves the full CRS/IP2Region file bundle on demand to
// slaves whose 历史修复 hash reference differs from their local files.
// 历史问题-01：响应体按引用指纹缓存（一次 base64/JSON 编码），不再每请求
// 全树打包 + 重新序列化；限流由 clusterMachineRateLimit 在路由层预占。
func (h *Handlers) GetClusterWafFiles(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	body := services.BuildWafFileBundleResponse()
	if body == nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "主节点无安全数据"})
		return
	}
	c.Data(http.StatusOK, "application/json; charset=utf-8", body)
}
