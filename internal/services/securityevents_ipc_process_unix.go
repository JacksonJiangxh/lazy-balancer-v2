//go:build !windows

package services

import (
	"errors"
	"syscall"
)

// securityEventsSpoolProcessAlive 判断 pid 是否仍存在（EPERM=存在但无权限）。
func securityEventsSpoolProcessAlive(pid int) bool {
	if pid <= 0 {
		return true // 未知 pid 按存活处理，不冒进封存
	}
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
