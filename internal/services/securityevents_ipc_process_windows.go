//go:build windows

package services

// securityEventsSpoolProcessAlive 在 Windows 开发机上保守返回 true：
// 进程存活探测仅在 Linux 容器生产环境生效；探测不了时按存活处理，
// 不冒进封存他人仍在写的 spool 文件（与 pid<=0 的既有口径一致）。
func securityEventsSpoolProcessAlive(pid int) bool { return true }
