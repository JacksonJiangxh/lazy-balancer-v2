package services

import (
	"os"

	"lazy-balancer-v2/internal/atomicfile"
)

// writeFileAtomicSynced 是 services 包内「持久化原子落盘」的入口，实现单源在
// internal/atomicfile（与 acme 的账户密钥/元数据落盘共用同一份 fsync + 父目录
// 同步原语，避免同仓第二种无 fsync 的落盘形态）。
//
// 对照：certstore 的 writeSyncedFile/syncParentDir 是更底层的原语（证书对
// 部署需要分别控制两个临时文件与失败回滚），本函数是其上的文件级组合。
func writeFileAtomicSynced(path string, data []byte, mode os.FileMode) error {
	return atomicfile.WriteAtomic(path, data, mode)
}
