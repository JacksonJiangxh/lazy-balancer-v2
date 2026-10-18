package services

import (
	"errors"
	"os"
	"path/filepath"
)

// writeFileAtomicSynced 是「持久化原子落盘」的单源实现（D1-历史问题 residual
// 收口）：同目录唯一临时文件 → chmod → 写入 → fsync → close → rename →
// 父目录 fsync。掉电/内核崩溃下读者只会看到完整旧文件或完整新文件，且新内容
// 已持久（rename 前 fsync 数据，rename 后 fsync 目录项）。任一失败清理临时
// 文件并返回错误；mode 为最终文件权限（不受进程 umask 影响）。
//
// 对照：certstore 的 writeSyncedFile/syncParentDir 是更底层的原语（证书对
// 部署需要分别控制两个临时文件与失败回滚），本函数是其上的文件级组合。
func writeFileAtomicSynced(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	fail := func(cause error) error {
		return errors.Join(cause, tmp.Close(), os.Remove(tmpName))
	}
	if err := tmp.Chmod(mode); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return syncParentDir(path)
}
