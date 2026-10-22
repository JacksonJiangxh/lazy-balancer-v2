package services

import "strings"

// cert_jobs 的「可服务证书材料」判定必须单源：渲染候选、启动物化、文件对账、
// 导入后产物清理、删除任务后的文件回收都依赖同一语义。曾有三套实现
// （渲染=非 disabled + PEM 非空；启动/对账/导入清理=issued/downloaded + PEM 非空），
// 渲染面更宽——导入清理会把「queued/waiting_ca/failed 但保留旧 PEM」规则的证书
// 文件删掉，而渲染仍从该行取材料服务流量，形成磁盘/数据库分叉。
//
// 单一语义（=渲染可消费面）：
//   - status != 'disabled'（disabled 是退役终态，任何消费方都不使用其材料）
//   - cert_pem / key_pem 均非空
//
// 域名适用性（certJobRuleApplicable）与「证书是否仍在有效期」不属于本谓词：
// 前者由各消费方按规则当前域名单独判定，后者只能解析证书后判定（SQL 表达不了）。

// CertJobMaterialPredicateSQL 返回「持有可服务证书材料」的 SQL 谓词。alias 为
// 列前缀（如 "j"），空串=裸列名。所有涉及材料可用性的 SQL 必须复用本函数，
// 不得另写条件组合。
func CertJobMaterialPredicateSQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	return "COALESCE(" + prefix + "cert_pem,'') <> '' AND COALESCE(" + prefix + "key_pem,'') <> '' AND COALESCE(" + prefix + "status,'') <> 'disabled'"
}

// CertJobMaterialUsable 是 CertJobMaterialPredicateSQL 的 Go 侧等价判定，供
// 内存中的行（已是查询结果）复用同一语义。
func CertJobMaterialUsable(status, certPEM, keyPEM string) bool {
	return strings.TrimSpace(certPEM) != "" && strings.TrimSpace(keyPEM) != "" && status != "disabled"
}
