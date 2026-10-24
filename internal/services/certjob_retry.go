package services

// 证书任务重试冷却的服务端单源策略（列表下发 / 服务端门禁 / 任务监控动态行
// 三处共用）：
//   - disabled：不可重试（永久条件，不是限流）；
//   - issued / waiting_ca：无通用冷却，但 waiting_ca 还要并入 CA 限流退避窗口
//     （ca_available_after，1–3h，远晚于通用冷却）；
//   - queued 15 分钟、failed 5 分钟、其余执行态 2 分钟（服务端门禁按 updated_at
//     起算是否到期）。
//
// 三处消费方必须共用本文件：前端以 retry_cooldown_seconds 为唯一判据，只下发
// 通用冷却会让 waiting_ca 任务显示 0（「现在可重试」）而服务端按 CA 冷却回
// 429，形成「可点重试却必被拒」的分叉。

import (
	"database/sql"
	"time"
)

// CertJobRetryCooldown 是重试冷却的通用策略源（按状态）。
// 列表下发值与服务端门禁不直接共用本函数：列表还要并入 CA 限流退避
// （见 CertJobRetryCooldownAt），服务端则先过本函数的通用冷却、再单独过
// CertJobCAcooldownActive（force 可越过）。
func CertJobRetryCooldown(status string) (time.Duration, bool) {
	switch status {
	case "disabled":
		return 0, false
	case "issued", "waiting_ca":
		return 0, true
	case "queued":
		return 15 * time.Minute, true
	case "failed":
		return 5 * time.Minute, true
	default:
		return 2 * time.Minute, true
	}
}

// CertJobCAcooldownActive 报告任务是否仍处于 CA 限流退避窗口（waiting_ca 且
// ca_available_after 未到期）。「任务重试」与「手动触发签发」两个入口必须共用
// 本判据：同状态同语义却一个要求 force、另一个直接重排，会让规则列表的
// 「重新签发」静默越过冷却、清空 ca_available_after 并继续消耗 CA 配额。
func CertJobCAcooldownActive(status string, caAvailableAfter sql.NullTime, now time.Time) bool {
	return status == "waiting_ca" && caAvailableAfter.Valid && now.Before(caAvailableAfter.Time)
}

// CertJobRetryCooldownAt 返回「此刻该任务还剩多少冷却」：通用冷却之外并入
// CA 限流退避窗口。列表类下发（证书任务列表与任务监控证书行）必须走本函数
// （或 CertJobRetryCooldownSecondsAt）——只下发通用冷却会让 waiting_ca 任务
// 显示 0，而服务端按 CA 冷却回 429。
func CertJobRetryCooldownAt(status string, caAvailableAfter sql.NullTime, now time.Time) (time.Duration, bool) {
	cooldown, retryable := CertJobRetryCooldown(status)
	if !retryable {
		return cooldown, false
	}
	if CertJobCAcooldownActive(status, caAvailableAfter, now) {
		return caAvailableAfter.Time.Sub(now), true
	}
	return cooldown, true
}

// CertJobRetryCooldownSeconds 把冷却时长规范化为下发口径（秒，向上取整）：
// 剩余不足 1 秒时下发 1 而非 0——0 在下发侧语义是「现在即可重试」，会把仍在
// 冷却中的任务引导成一次必然 429 的重试。
func CertJobRetryCooldownSeconds(cooldown time.Duration) int64 {
	if cooldown <= 0 {
		return 0
	}
	return int64((cooldown + time.Second - 1) / time.Second)
}

// CertJobRetryCooldownSecondsAt 是「此刻剩余冷却（秒）」的下发单源：
// 不可重试/无剩余/CA 窗口缺失或已到期 → 0（0=无冷却，前端按此判定可点）。
func CertJobRetryCooldownSecondsAt(status string, caAvailableAfter sql.NullTime, now time.Time) int64 {
	cooldown, retryable := CertJobRetryCooldownAt(status, caAvailableAfter, now)
	if !retryable {
		return 0
	}
	return CertJobRetryCooldownSeconds(cooldown)
}
