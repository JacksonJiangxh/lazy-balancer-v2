package services

import (
	"fmt"
	"sync"
	"time"
)

// 后台数据类重载的失败面（证书/CRS/IP2Region/威胁库/自动封禁）。
//
// 背景：caddy_apply_error 只由 handlers 的写路径（recordCaddyApplyResult）落盘，
// 后台数据类重载（证书部署 / CRS / IP2Region / 威胁库 / 自动封禁名单收敛）走
// services 内的注入回调，失败只在应用日志留一行——面板横幅恒不可见，运行配置
// 与库数据可长期分叉而无人察觉。
//
// 形态：按来源记录最近一次失败，成功只清除该来源（一个来源成功不得掩盖另一
// 来源仍在失败）；快照取最近失败的一条供状态接口与前端横幅消费。零新表：
// 进程内状态，重启后由首轮成功/失败重建（与 LKG 等运行态列同口径）。

// BackgroundApplyFailure 是单个来源的后台重载失败快照。
type BackgroundApplyFailure struct {
	Source  string `json:"source"`
	Message string `json:"message"`
	At      string `json:"at"` // 配置时区墙串
}

type backgroundApplyState struct {
	mu       sync.Mutex
	failures map[string]BackgroundApplyFailure
}

var backgroundApplyStore = backgroundApplyState{failures: map[string]BackgroundApplyFailure{}}

// BackgroundApplySource 后台重载来源标识（状态接口/横幅展示用）。
type BackgroundApplySource string

const (
	BackgroundApplyCertDeploy BackgroundApplySource = "证书部署"
	BackgroundApplyCRS        BackgroundApplySource = "CRS"
	BackgroundApplyIP2Region  BackgroundApplySource = "IP2Region"
	BackgroundApplyThreat     BackgroundApplySource = "威胁情报库"
	BackgroundApplyAutoban    BackgroundApplySource = "自动封禁"
)

// TrackBackgroundReload 返回包装后的后台重载回调：失败登记到失败面并按原样
// 返回，成功清除该来源的失败记录。回调本身错误语义不变（调用方仍据错误决定
// 终态/重试），本包装只负责可观测性。
func TrackBackgroundReload(source BackgroundApplySource, reload func() error) func() error {
	if reload == nil {
		return nil
	}
	return func() error {
		err := reload()
		recordBackgroundApplyResult(source, err)
		return err
	}
}

func recordBackgroundApplyResult(source BackgroundApplySource, err error) {
	backgroundApplyStore.mu.Lock()
	defer backgroundApplyStore.mu.Unlock()
	if err == nil {
		delete(backgroundApplyStore.failures, string(source))
		return
	}
	backgroundApplyStore.failures[string(source)] = BackgroundApplyFailure{
		Source:  string(source),
		Message: err.Error(),
		At:      time.Now().In(CurrentLocation()).Format("2006-01-02 15:04:05"),
	}
}

// RecordBackgroundApplyFailure 供不走 TrackBackgroundReload 的调用点手工登记
// （例如投影热路径外的直接应用）。
func RecordBackgroundApplyFailure(source BackgroundApplySource, err error) {
	recordBackgroundApplyResult(source, err)
}

// ClearBackgroundApplyFailure 清除某来源的失败记录（成功路径/手工恢复）。
func ClearBackgroundApplyFailure(source BackgroundApplySource) {
	recordBackgroundApplyResult(source, nil)
}

// BackgroundApplyFailureSnapshot 返回最近一次后台重载失败（无失败为 nil）。
// 多来源并存时按时间取最新一条；来源名与消息均随状态接口下发。
func BackgroundApplyFailureSnapshot() *BackgroundApplyFailure {
	backgroundApplyStore.mu.Lock()
	defer backgroundApplyStore.mu.Unlock()
	var latest *BackgroundApplyFailure
	for _, failure := range backgroundApplyStore.failures {
		current := failure
		if latest == nil || current.At > latest.At {
			latest = &current
		}
	}
	return latest
}

// BackgroundApplyFailureBanner 单行横幅文案（无失败为空串）。
func BackgroundApplyFailureBanner() string {
	failure := BackgroundApplyFailureSnapshot()
	if failure == nil {
		return ""
	}
	return fmt.Sprintf("后台重载失败（%s，%s）：%s", failure.Source, failure.At, failure.Message)
}
