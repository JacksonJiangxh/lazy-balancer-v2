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
//
// 判空必须是 trim 后的判空：只比较 ” 会把 ' ' 这类空白材料当作「有材料」，
// 而 Go 侧 CertJobMaterialUsable（TrimSpace）判为无材料——同一行在 SQL 扫描
// 链路（渲染/物化/补扫）与 Go 判定链路（补偿/失败降级）结论相反，补扫会把
// 空白材料写盘。trim 字符集与 Go 侧 ASCII 空白对齐（空格/制表/换行/回车/
// 垂直制表/换页）；非 ASCII 空白的带外写入仍属两侧差异，PEM 实际不会出现。
func CertJobMaterialPredicateSQL(alias string) string {
	prefix := ""
	if alias != "" {
		prefix = alias + "."
	}
	const sqlWhitespace = "' '||char(9)||char(10)||char(11)||char(12)||char(13)"
	nonBlank := func(column string) string {
		return "TRIM(" + prefix + column + ", " + sqlWhitespace + ") <> ''"
	}
	return nonBlank("cert_pem") + " AND " + nonBlank("key_pem") + " AND COALESCE(" + prefix + "status,'') <> 'disabled'"
}

// CertJobMissingMaterialPredicateSQL 是 CertJobMaterialPredicateSQL 的逻辑取反。
// 取反必须经 COALESCE 归一到布尔：SQL 三值逻辑下 NOT(NULL) 仍是 NULL，材料列
// 为 NULL（任务行创建时的默认形态——签发中断从未写入，正是「材料丢失」最常见
// 的形态）会被 `NOT (predicate)` 静默排除，而不是被当作「无材料」回收。
// 正向与取反共用同一表达式，不得另写条件组合。
func CertJobMissingMaterialPredicateSQL(alias string) string {
	return "NOT COALESCE(" + CertJobMaterialPredicateSQL(alias) + ", 0)"
}

// CertJobMaterialUsable 是 CertJobMaterialPredicateSQL 的 Go 侧等价判定，供
// 内存中的行（已是查询结果）复用同一语义（含 trim 口径，见上）。
func CertJobMaterialUsable(status, certPEM, keyPEM string) bool {
	return strings.TrimSpace(certPEM) != "" && strings.TrimSpace(keyPEM) != "" && status != "disabled"
}
