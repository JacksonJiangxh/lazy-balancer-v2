package db

import (
	"crypto/tls"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
)

// 甲路线（证书密文库 cert_secrets + DEK）的启用谓词环境变量——与
// services.CertVaultDEKSource 同一单一口径（P1-4：env 名固定，无间接层）。
// db 包不依赖 services（循环依赖），迁移内部直接读 env 判定甲路线是否启用，
// 与 main.go 的 DEK 决策（services.CertVaultDEKSource）逐字同源。
const (
	certVaultDEKEnv         = "LB_CERT_DEK_B64"
	certVaultKMSEndpointEnv = "LB_CERT_KMS_ENDPOINT"
)

// migrationTlsFileBackupTable 是 file 模式证书行明文清空的迁移备份表，双用途：
//   - 乙路线（DEK 未配置）：清空前把旧明文 PEM 备份到此表（old_tls_cert/
//     old_tls_key 存旧值），供回滚；
//   - 甲路线（DEK 已配置）：记录 file 行清单（old_tls_cert/key 留空），供渲染侧
//     过滤 cert_secrets 中 file 模式规则的条目，避免双加载器冲突。
const migrationTlsFileBackupTable = "migration_tls_file_backup"

// ensureTlsFileBackupTable 建迁移备份表（幂等 DDL，每启动一次取写锁，WAL 下
// 不写帧，属 schema 收敛 DDL 既定口径）。
func ensureTlsFileBackupTable() error {
	if _, err := DB.Exec(`CREATE TABLE IF NOT EXISTS ` + migrationTlsFileBackupTable + ` (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		rule_id TEXT NOT NULL,
		old_tls_cert TEXT NOT NULL DEFAULT '',
		old_tls_key TEXT NOT NULL DEFAULT '',
		migrated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("failed to create %s: %w", migrationTlsFileBackupTable, err)
	}
	if _, err := DB.Exec(`CREATE INDEX IF NOT EXISTS idx_` + migrationTlsFileBackupTable + `_rule
		ON ` + migrationTlsFileBackupTable + `(rule_id)`); err != nil {
		return fmt.Errorf("failed to index %s: %w", migrationTlsFileBackupTable, err)
	}
	return nil
}

// certVaultDEKConfigured 报告甲路线（证书密文库）是否启用——与
// services.CertVaultDEKSource 同一启用谓词：KMS 端点或 DEK env 任一非空即启用。
// 只判非空，不读值，避免密钥材料入日志/返回值。
func certVaultDEKConfigured() bool {
	return os.Getenv(certVaultKMSEndpointEnv) != "" || os.Getenv(certVaultDEKEnv) != ""
}

// tlsFileRow 是一条待校验的 file 模式证书行（tls_source='file' AND enable_tls=1）。
type tlsFileRow struct {
	caddyID  string
	certPath string
	keyPath  string
	certPEM  string
	keyPEM   string
}

// loadTlsFileRows 读取全部 file 模式启用 TLS 的行（含路径与明文现状）。
func loadTlsFileRows() ([]tlsFileRow, error) {
	rows, err := DB.Query(`SELECT caddy_id, COALESCE(tls_cert_path,''), COALESCE(tls_key_path,''),
		COALESCE(tls_cert,''), COALESCE(tls_key,'')
		FROM lb_rules WHERE enable_tls=1 AND tls_source='file'`)
	if err != nil {
		return nil, fmt.Errorf("failed to query file-mode tls rows: %w", err)
	}
	defer rows.Close()
	var out []tlsFileRow
	for rows.Next() {
		var r tlsFileRow
		if err := rows.Scan(&r.caddyID, &r.certPath, &r.keyPath, &r.certPEM, &r.keyPEM); err != nil {
			return nil, fmt.Errorf("failed to scan file-mode tls row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate file-mode tls rows: %w", err)
	}
	return out, nil
}

// validateTlsFileRowPaths 启动期 best-effort 校验：路径非空 → 文件存在且 PEM 可解析
// （tls.X509KeyPair 同时校验 PEM 解析与证书/私钥配对，与证书文件扫描器同口径）。
// 路径为空或校验失败均返回 false——该行标记「待管理员处理」，不清空明文。
func validateTlsFileRowPaths(r tlsFileRow) bool {
	if r.certPath == "" || r.keyPath == "" {
		return false
	}
	certPEM, err := os.ReadFile(r.certPath)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(r.keyPath)
	if err != nil {
		return false
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return false
	}
	return true
}

// migrateTlsFilePlaintextClear 是 file 模式证书行启动迁移（JJC-20261125-001 子任务 6）：
//
// 背景：后端正把 tls_source='file' 改为「数据库只存路径不存内容」。现存旧数据中
// file 行的 tls_cert/tls_key 存有明文 PEM，tls_cert_path/tls_key_path 部分为空。
// 本迁移在启动期完成自愈，且与甲路线（cert_secrets + DEK）明确互斥。
//
// 步骤一·路径回填校验（best-effort，不阻断启动）：
//   - 路径非空 → 校验文件存在且 PEM 可解析；失败标记该行「待管理员处理」（WARN 日志）；
//   - 路径为空 → 标记「待管理员处理」（WARN 日志）。
//
// 步骤二·条件清空（可回滚，仅 DEK 未配置）：
//   - 校验通过的行：先把旧明文备份到 migration_tls_file_backup，再清空 tls_cert/tls_key；
//   - 校验失败的行：不清空（明文保留）。
//
// 甲路线互斥：DEK 已配置 → 整体跳过清空（明文保留，vault 继续服务），WARN 显式留痕；
// 同时把 file 行清单记入备份表（old_tls_cert/key 留空），供渲染侧过滤 cert_secrets
// 中 file 模式规则的条目，避免双加载器冲突。
//
// 幂等：备份按 (rule_id, old_tls_cert, old_tls_key) 去重；清空谓词要求明文非空；
// 收敛库（明文已空/已备份）探测零命中，不开写事务。失败仅告警，不阻断启动。
func migrateTlsFilePlaintextClear() error {
	if err := ensureTlsFileBackupTable(); err != nil {
		return err
	}
	fileRows, err := loadTlsFileRows()
	if err != nil {
		return err
	}
	if len(fileRows) == 0 {
		return nil
	}

	// 步骤一：路径回填校验（best-effort，不阻断启动）。
	var eligible, pendingAdmin []tlsFileRow
	for _, r := range fileRows {
		if validateTlsFileRowPaths(r) {
			eligible = append(eligible, r)
			continue
		}
		pendingAdmin = append(pendingAdmin, r)
		reason := "路径为空"
		if r.certPath != "" && r.keyPath != "" {
			reason = "证书/私钥文件缺失或 PEM 不可解析"
		}
		log.Printf("WARN: file 模式证书行 %s 待管理员处理：%s（tls_cert_path=%q tls_key_path=%q，明文保留未清空）",
			r.caddyID, reason, r.certPath, r.keyPath)
	}

	if certVaultDEKConfigured() {
		// 甲路线互斥：整体跳过清空，明文保留，vault 继续服务。
		log.Printf("WARN: 甲路线启用（DEK 已配置），file 行明文保留未清空，请在关闭甲路线后重跑迁移完成清空")
		// 记录 file 行清单供渲染侧过滤 cert_secrets file 条目（避免双加载器冲突）。
		return recordTlsFileInventory(fileRows)
	}

	// 步骤二：条件清空（DEK 未配置）。仅清空校验通过且明文非空的行。
	var toClear []tlsFileRow
	for _, r := range eligible {
		if r.certPEM != "" || r.keyPEM != "" {
			toClear = append(toClear, r)
		}
	}
	if len(toClear) == 0 {
		return nil // 收敛态：无明文可清，零写。
	}

	var cleared int64
	if err := withWriteTx("tls file plaintext clear", func(tx *sql.Tx) error {
		for _, r := range toClear {
			// 备份去重：同一 (rule_id, old_cert, old_key) 不重复备份。
			var one int
			probeErr := tx.QueryRow(`SELECT 1 FROM `+migrationTlsFileBackupTable+`
				WHERE rule_id=? AND old_tls_cert=? AND old_tls_key=? LIMIT 1`,
				r.caddyID, r.certPEM, r.keyPEM).Scan(&one)
			if probeErr != nil && !errors.Is(probeErr, sql.ErrNoRows) {
				return fmt.Errorf("failed to probe tls file backup for %s: %w", r.caddyID, probeErr)
			}
			if errors.Is(probeErr, sql.ErrNoRows) {
				if _, err := tx.Exec(`INSERT INTO `+migrationTlsFileBackupTable+`
					(rule_id, old_tls_cert, old_tls_key) VALUES (?,?,?)`,
					r.caddyID, r.certPEM, r.keyPEM); err != nil {
					return fmt.Errorf("failed to backup tls file plaintext for %s: %w", r.caddyID, err)
				}
			}
			res, err := tx.Exec(`UPDATE lb_rules SET tls_cert='', tls_key=''
				WHERE caddy_id=? AND (COALESCE(tls_cert,'')<>'' OR COALESCE(tls_key,'')<>'')`, r.caddyID)
			if err != nil {
				return fmt.Errorf("failed to clear tls file plaintext for %s: %w", r.caddyID, err)
			}
			if n, err := res.RowsAffected(); err == nil {
				cleared += n
			}
		}
		if cleared > 0 {
			// 清空改变 lb_rules 数据（明文→空），bump cluster_version 触发从端
			// 下轮拉取收敛（主端库/导出 canonical/从端落库三面同值不变量）。
			if _, err := tx.Exec(`UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1`); err != nil {
				return fmt.Errorf("failed to bump cluster_version after tls file plaintext clear: %w", err)
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if cleared > 0 {
		detail := fmt.Sprintf("启动迁移：file 模式证书行明文清空 %d 条（旧明文已备份至 %s，可回滚；路径列保留）", cleared, migrationTlsFileBackupTable)
		log.Print(detail)
		recordSystemAudit("启动迁移", "证书配置", detail)
	}
	return nil
}

// recordTlsFileInventory 把 file 行清单记入备份表（old_tls_cert/key 留空），供渲染侧
// 过滤 cert_secrets 中 file 模式规则的条目（甲路线下避免双加载器冲突）。
// 幂等：已记录的 rule_id 不重复插入；收敛库（全部已记录）探测零命中，零写。
func recordTlsFileInventory(fileRows []tlsFileRow) error {
	if len(fileRows) == 0 {
		return nil
	}
	var pending int
	if err := DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE enable_tls=1 AND tls_source='file'
		AND caddy_id NOT IN (SELECT rule_id FROM `+migrationTlsFileBackupTable+`)`).Scan(&pending); err != nil {
		return fmt.Errorf("failed to probe tls file inventory: %w", err)
	}
	if pending == 0 {
		return nil
	}
	if _, err := DB.Exec(`INSERT INTO `+migrationTlsFileBackupTable+` (rule_id, old_tls_cert, old_tls_key)
		SELECT caddy_id, '', '' FROM lb_rules WHERE enable_tls=1 AND tls_source='file'
		AND caddy_id NOT IN (SELECT rule_id FROM `+migrationTlsFileBackupTable+`)`); err != nil {
		return fmt.Errorf("failed to record tls file inventory: %w", err)
	}
	log.Printf("WARN: 甲路线启用：file 行清单已记入 %s（供渲染侧过滤 cert_secrets file 条目，避免双加载器冲突）", migrationTlsFileBackupTable)
	return nil
}
