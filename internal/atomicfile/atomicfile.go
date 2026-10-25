// Package atomicfile 提供「持久化原子落盘」的唯一原语：同目录临时文件 →
// 设置权限 → 写入 → fsync → rename → 父目录 fsync。掉电/内核崩溃下读者只会
// 看到完整旧文件或完整新文件，且新内容已持久（rename 前 fsync 数据，rename 后
// fsync 目录项）。任一失败都清理临时文件并返回错误。
//
// 放在无仓内依赖的叶子包，供互不成环的包共用（acme 的账户密钥/元数据、
// services 的簿记文件）：同仓出现第二种「无 fsync/无目录同步」的落盘形态时，
// 崩溃窗口下会留下截断文件或丢失刚写入的目录项，而调用方只能按「文件不存在」
// 误判。
package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
)

// WriteAtomic 原子且持久地写入 path（覆盖既有内容）。mode 为最终文件权限
// （显式 chmod，不受进程 umask 影响）。目录必须已存在。
func WriteAtomic(path string, data []byte, mode os.FileMode) error {
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
	return SyncParent(path)
}

// SyncParent 对 path 所在目录做 fsync：rename 只改目录项，目录本身的持久化
// 需要单独同步，否则掉电后新文件名可能不存在。
func SyncParent(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return errors.Join(err, dir.Close())
	}
	return dir.Close()
}
