package db

import (
	"fmt"
	"log"
)

// ThreatSourceSeed 是内置威胁源下载端的唯一事实源；数据库种子、备份导入
// 与 lbbak 文件名白名单共用，防止合法 name 携带伪造 URL/format。
type ThreatSourceSeed struct {
	Name        string
	DisplayName string
	URL         string
	Format      string
}

var threatSourceSeeds = []ThreatSourceSeed{
	{Name: "ustc", DisplayName: "中科大恶意 IP（USTC）", URL: "https://blackip.ustc.edu.cn/list.php?txt", Format: "plain"},
	{Name: "firehol_l1", DisplayName: "FireHOL Level 1", URL: "https://iplists.firehol.org/files/firehol_level1.netset", Format: "plain"},
	{Name: "et_compromised", DisplayName: "Emerging Threats Compromised", URL: "https://rules.emergingthreats.net/blockrules/compromised-ips.txt", Format: "plain"},
}

// CanonicalThreatSource 按内置 name 返回官方下载端定义。
func CanonicalThreatSource(name string) (ThreatSourceSeed, bool) {
	for _, seed := range threatSourceSeeds {
		if seed.Name == name {
			return seed, true
		}
	}
	return ThreatSourceSeed{}, false
}

// ThreatSystemList 威胁情报库内置只读名单条目（v2.3.2 名单化重构）。
// Source=威胁源名（security_threat_sources.name，更新任务定位键），
// Name=security_ip_lists.name（用户可见，稳定不变——策略 refs 按 id 引用，
// 行永不删除，id 跨更新稳定）。
type ThreatSystemList struct {
	Source      string
	Name        string
	Description string
}

// ThreatSystemLists 三源内置名单种子（与 security_threat_sources 种子同源）。
// 专业化命名（2026-09-24 用户裁定）：去「威胁情报库-」前缀——选择器分组已
// 承载归属语义；存量库旧名经 migrateThreatSystemListNames 迁移（保 id）。
var ThreatSystemLists = []ThreatSystemList{
	{"ustc", "中科大恶意 IP 名单（USTC）", "中国科学技术大学恶意 IP 库（blackip.ustc.edu.cn）——威胁情报库更新任务维护，只读"},
	{"firehol_l1", "FireHOL Level 1 综合黑名单", "FireHOL Level 1 聚合黑名单（iplists.firehol.org）——威胁情报库更新任务维护，只读"},
	{"et_compromised", "Emerging Threats 失陷主机名单", "Emerging Threats Compromised IPs（失陷主机）——威胁情报库更新任务维护，只读"},
}

// threatSystemListLegacyNames 新名 → 旧名（迁移定位键；仅 v2.3.2 名单化初期的
// 「威胁情报库-*」旧名一档）。
var threatSystemListLegacyNames = map[string]string{
	"中科大恶意 IP 名单（USTC）":       "威胁情报库-中科大黑 IP",
	"FireHOL Level 1 综合黑名单":   "威胁情报库-FireHOL level1",
	"Emerging Threats 失陷主机名单": "威胁情报库-ET Compromised",
}

// migrateThreatSystemListNames 存量 system=1 内置名单按旧名改名为新名（保 id——
// 策略 refs 按 id 引用）。幂等；种子 INSERT 按新名查重，旧名行不改名会双重存在。
// CORE-U3（历史）识别同名冲突；历史起新名被占用（如用户手工建的
// 同名 system=0 名单）时，把冲突用户行改名为「规范名（用户 <id>）」（保 id/
// 数据），再让 system 行接管规范名。避免同名双行导致选择器歧义，且旧 system
// 名单不会因跳过改名而永久失更。
func migrateThreatSystemListNames() error {
	for _, sl := range ThreatSystemLists {
		legacy, ok := threatSystemListLegacyNames[sl.Name]
		if !ok {
			continue
		}
		var legacyRows int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE system=1 AND name=?`, legacy).Scan(&legacyRows); err != nil {
			return fmt.Errorf("failed to check legacy threat system list %s: %w", legacy, err)
		}
		if legacyRows == 0 {
			continue // 幂等零命中
		}
		var conflicts int
		if err := DB.QueryRow(`SELECT COUNT(*) FROM security_ip_lists WHERE name=?`, sl.Name).Scan(&conflicts); err != nil {
			return fmt.Errorf("failed to check threat system list name conflict %s: %w", sl.Name, err)
		}
		if conflicts > 0 {
			// 新名被用户名单占用时不能跳过：旧 system 名单会永久失更。
			// 把占用的用户行改名为带 id 的唯一名称（保 id/数据），再让
			// system 行接管规范名（历史 历史问题-1）。
			rows, rerr := DB.Query(`SELECT id FROM security_ip_lists WHERE name=? AND system=0`, sl.Name)
			if rerr != nil {
				return fmt.Errorf("query conflicting threat system list rows: %w", rerr)
			}
			var ids []int64
			for rows.Next() {
				var id int64
				if err := rows.Scan(&id); err != nil {
					rows.Close()
					return fmt.Errorf("scan conflicting threat system list row: %w", err)
				}
				ids = append(ids, id)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return fmt.Errorf("iterate conflicting threat system list rows: %w", err)
			}
			rows.Close()
			for _, id := range ids {
				renamed := fmt.Sprintf("%s（用户 %d）", sl.Name, id)
				if _, err := DB.Exec(`UPDATE security_ip_lists SET name=?, updated_at=datetime('now') WHERE id=?`, renamed, id); err != nil {
					return fmt.Errorf("rename conflicting user list %d: %w", id, err)
				}
			}
			log.Printf("WARN: 内置威胁名单新名 %q 被用户名单占用，已改名用户行（ids=%v）后接管规范名", sl.Name, ids)
		}
		if _, err := DB.Exec(`UPDATE security_ip_lists SET name=?, description=?, updated_at=datetime('now') WHERE system=1 AND name=?`, sl.Name, sl.Description, legacy); err != nil {
			return fmt.Errorf("failed to rename threat system list %s: %w", legacy, err)
		}
	}
	return nil
}

// ThreatListNameBySource 源名 → 名单名（未登记返回空串）。
func ThreatListNameBySource(source string) string {
	for _, sl := range ThreatSystemLists {
		if sl.Source == source {
			return sl.Name
		}
	}
	return ""
}
