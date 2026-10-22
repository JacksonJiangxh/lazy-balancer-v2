package services

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"lazy-balancer-v2/internal/db"
)

var certDir = "/app/certs"

// SetCertDirForTest 重定向证书物化目录，仅供测试隔离使用（返回还原函数）。
func SetCertDirForTest(dir string) func() {
	old := certDir
	certDir = dir
	return func() { certDir = old }
}

// certWriteMu 保护证书文件操作的层级互斥：读锁（RLock）覆盖按规则并行的
// 写/删/快照/物化，写锁（Lock）只留给「跨规则快照回滚」（RestoreCertFiles
// 全有全无，必须排斥一切并发文件操作）。全局互斥时代 /load 渲染 N 条
// ACME 规则在同一锁内串行 N 组 fsync（机械盘合计数百 ms～秒级），跨规则
// 部署/删除彼此阻塞，per-rule DeployLock 因此无实际收益。
var certWriteMu sync.RWMutex

// certRuleFileLocks 按 ruleID 串行化同一规则的 cert/key 文件操作
// （内容比对→tmp→rename 序列不得与同规则并发写交错产生撕裂组合）。
// 键空间=规则数，无需回收（与 certJobLogWriteLocks 同口径）。
var certRuleFileLocks sync.Map

// lockCertRuleFile 返回单规则的 per-rule 文件锁。调用方必须先持
// certWriteMu.RLock（锁序：certWriteMu → per-rule，单向不逆）。
func lockCertRuleFile(ruleID string) *sync.Mutex {
	lock, _ := certRuleFileLocks.LoadOrStore(ruleID, &sync.Mutex{})
	return lock.(*sync.Mutex)
}

// lockCertRuleFiles 按序取多条规则的 per-rule 锁（排序+去重防死锁/自锁），
// 返回统一解锁函数。调用方必须先持 certWriteMu.RLock。
func lockCertRuleFiles(ruleIDs []string) func() {
	unique := make([]string, 0, len(ruleIDs))
	seen := make(map[string]struct{}, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if _, ok := seen[ruleID]; ok {
			continue
		}
		seen[ruleID] = struct{}{}
		unique = append(unique, ruleID)
	}
	sort.Strings(unique)
	locks := make([]*sync.Mutex, 0, len(unique))
	for _, ruleID := range unique {
		lock := lockCertRuleFile(ruleID)
		lock.Lock()
		locks = append(locks, lock)
	}
	return func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Unlock()
		}
	}
}

var certificateDeployLocks sync.Map
var certificateDeployLocksMu sync.Mutex

type certificateDeployLock struct {
	mu   sync.Mutex
	refs int
}

// DeployLock serializes the complete deployment and rollback transaction for
// one rule while allowing unrelated rules to deploy concurrently.
func DeployLock(ruleID string) func() {
	certificateDeployLocksMu.Lock()
	value, _ := certificateDeployLocks.LoadOrStore(ruleID, &certificateDeployLock{})
	lock := value.(*certificateDeployLock)
	lock.refs++
	certificateDeployLocksMu.Unlock()

	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		certificateDeployLocksMu.Lock()
		lock.refs--
		if lock.refs == 0 {
			certificateDeployLocks.Delete(ruleID)
		}
		certificateDeployLocksMu.Unlock()
	}
}

type CertFileSnapshot struct {
	Data   []byte
	Mode   os.FileMode
	Exists bool
}

type CertPairSnapshot struct {
	Cert CertFileSnapshot
	Key  CertFileSnapshot
}

type CertFilesSnapshot map[string]CertPairSnapshot

type CertMaterial struct {
	RuleID  string
	CertPEM string
	KeyPEM  string
}

// safeRuleID rejects anything outside the generated caddy_id alphabet so a
// malicious or corrupted rule ID can never escape the cert directory.
func safeRuleID(ruleID string) bool {
	if ruleID == "" || len(ruleID) > 64 {
		return false
	}
	for _, r := range ruleID {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}

// ValidCertRuleID 报告 ruleID 是否满足证书文件路径字母表（非空、≤64、仅
// [a-z0-9_-]），与 safeRuleID 完全同源。导出供导入口等跨包调用方复用同一
// 字母表（v2 导入允许含 '.' 的 caddy_id，证书物化路径却拒绝——
// 必须在导入校验阶段 fail-fast 点名，而不是在证书阶段整体回滚）。
func ValidCertRuleID(ruleID string) bool {
	return safeRuleID(ruleID)
}

func CertFilePaths(ruleID string) (certPath, keyPath string) {
	if !safeRuleID(ruleID) {
		return "", ""
	}
	return filepath.Join(certDir, ruleID+".crt"), filepath.Join(certDir, ruleID+".key")
}

func WriteCertFiles(ruleID, certPEM, keyPEM string) error {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	ruleLock := lockCertRuleFile(ruleID)
	ruleLock.Lock()
	defer ruleLock.Unlock()
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("创建证书目录: %w", err)
	}
	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return fmt.Errorf("非法的规则编号: %q", ruleID)
	}
	return writeCertPair(certPath, keyPath, certPEM, keyPEM)
}

func writeCertPair(certPath, keyPath, certPEM, keyPEM string) error {
	previousCert, err := os.ReadFile(certPath)
	certExisted := err == nil
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("读取原证书: %w", err)
	}
	// 内容一致且权限正确才零写
	// ——旧内容本已读出,比对几乎免费;跳过可免每次 apply 的 tmp+fsync+
	// rename 写放大。权限被外部改错时仍重写(既有契约:重复物化修复权限,
	// TestMaterializeCertPairs_restores_permissions 钉住)。
	if previousKey, kerr := os.ReadFile(keyPath); kerr == nil &&
		string(previousCert) == certPEM && string(previousKey) == keyPEM {
		if certInfo, serr := os.Stat(certPath); serr == nil && certInfo.Mode().Perm() == 0644 {
			if keyInfo, kerr2 := os.Stat(keyPath); kerr2 == nil && keyInfo.Mode().Perm() == 0600 {
				return nil
			}
		}
	}
	previousMode := os.FileMode(0644)
	if certExisted {
		info, statErr := os.Stat(certPath)
		if statErr != nil {
			return fmt.Errorf("读取原证书权限: %w", statErr)
		}
		previousMode = info.Mode().Perm()
	}

	certTmp, keyTmp := certPath+".tmp", keyPath+".tmp"
	if err := writeSyncedFile(certTmp, []byte(certPEM), 0644); err != nil {
		return fmt.Errorf("写入证书: %w", err)
	}
	if err := writeSyncedFile(keyTmp, []byte(keyPEM), 0600); err != nil {
		return errors.Join(fmt.Errorf("写入私钥: %w", err), removeTemporaryCertFile(certTmp))
	}
	if err := os.Rename(certTmp, certPath); err != nil {
		return errors.Join(fmt.Errorf("部署证书: %w", err), removeTemporaryCertFile(certTmp), removeTemporaryCertFile(keyTmp))
	}
	if err := os.Rename(keyTmp, keyPath); err != nil {
		deployErr := fmt.Errorf("部署私钥: %w", err)
		cleanupErr := removeTemporaryCertFile(keyTmp)
		if certExisted {
			if restoreErr := writeSyncedFile(certPath, previousCert, previousMode); restoreErr != nil {
				return errors.Join(deployErr, cleanupErr, fmt.Errorf("恢复原证书: %w", restoreErr))
			}
		} else if removeErr := os.Remove(certPath); removeErr != nil && !os.IsNotExist(removeErr) {
			return errors.Join(deployErr, cleanupErr, fmt.Errorf("删除新证书: %w", removeErr))
		}
		return errors.Join(deployErr, cleanupErr)
	}
	if err := syncParentDir(certPath); err != nil {
		return fmt.Errorf("同步证书目录: %w", err)
	}
	return nil
}

func writeSyncedFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		return errors.Join(err, file.Close())
	}
	if err := file.Sync(); err != nil {
		return errors.Join(err, file.Close())
	}
	return file.Close()
}

func syncParentDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		return errors.Join(err, dir.Close())
	}
	return dir.Close()
}

func removeTemporaryCertFile(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("清理临时文件 %s: %w", path, err)
	}
	return nil
}

func RemoveCertFiles(ruleID string) error {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	ruleLock := lockCertRuleFile(ruleID)
	ruleLock.Lock()
	defer ruleLock.Unlock()

	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return fmt.Errorf("非法的规则编号: %q", ruleID)
	}
	var certErr, keyErr error
	if err := os.Remove(certPath); err != nil && !os.IsNotExist(err) {
		certErr = fmt.Errorf("删除证书: %w", err)
	}
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		keyErr = fmt.Errorf("删除私钥: %w", err)
	}
	return errors.Join(certErr, keyErr)
}

func SnapshotCertFiles(ruleIDs []string) (CertFilesSnapshot, error) {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	unlock := lockCertRuleFiles(ruleIDs)
	defer unlock()
	return snapshotCertFilesLocked(ruleIDs)
}

func snapshotCertFilesLocked(ruleIDs []string) (CertFilesSnapshot, error) {
	snapshot := make(CertFilesSnapshot, len(ruleIDs))
	for _, ruleID := range ruleIDs {
		if _, exists := snapshot[ruleID]; exists {
			continue
		}
		certPath, keyPath := CertFilePaths(ruleID)
		if certPath == "" {
			return nil, fmt.Errorf("非法的规则编号: %q", ruleID)
		}
		cert, err := snapshotCertFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("快照证书 %s: %w", ruleID, err)
		}
		key, err := snapshotCertFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("快照私钥 %s: %w", ruleID, err)
		}
		snapshot[ruleID] = CertPairSnapshot{Cert: cert, Key: key}
	}
	return snapshot, nil
}

// RestoreCertFiles 恢复整份快照（任一失败→全部回滚）。跨规则回滚必须全局
// 互斥：写锁排斥一切并发文件操作（其余路径均持 RLock + per-rule 锁）。
func RestoreCertFiles(snapshot CertFilesSnapshot) error {
	certWriteMu.Lock()
	defer certWriteMu.Unlock()
	return restoreCertFilesLocked(snapshot)
}

func restoreCertFilesLocked(snapshot CertFilesSnapshot) error {
	ruleIDs := make([]string, 0, len(snapshot))
	for ruleID := range snapshot {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	current, err := snapshotCertFilesLocked(ruleIDs)
	if err != nil {
		return fmt.Errorf("快照恢复前证书文件: %w", err)
	}

	for _, ruleID := range ruleIDs {
		pair := snapshot[ruleID]
		certPath, keyPath := CertFilePaths(ruleID)
		certErr := restoreCertFile(certPath, pair.Cert)
		var keyErr error
		if certErr == nil {
			keyErr = restoreCertFile(keyPath, pair.Key)
		}
		if certErr != nil || keyErr != nil {
			rollbackErr := restoreCertFilesBestEffortLocked(current)
			restoreErr := fmt.Errorf("恢复证书对 %s: %w", ruleID, errors.Join(certErr, keyErr))
			if rollbackErr != nil {
				restoreErr = errors.Join(restoreErr, fmt.Errorf("回滚全部证书文件: %w", rollbackErr))
			}
			return restoreErr
		}
	}
	return nil
}

func restoreCertFilesBestEffortLocked(snapshot CertFilesSnapshot) error {
	var restoreErrors []error
	for ruleID, pair := range snapshot {
		certPath, keyPath := CertFilePaths(ruleID)
		restoreErrors = append(restoreErrors,
			restoreCertFile(certPath, pair.Cert),
			restoreCertFile(keyPath, pair.Key),
		)
	}
	return errors.Join(restoreErrors...)
}

func MaterializeCertPairs(materials []CertMaterial) (CertFilesSnapshot, error) {
	certWriteMu.RLock()
	defer certWriteMu.RUnlock()
	materialRuleIDs := make([]string, 0, len(materials))
	for _, material := range materials {
		materialRuleIDs = append(materialRuleIDs, material.RuleID)
	}
	unlock := lockCertRuleFiles(materialRuleIDs)
	defer unlock()

	lastMaterialByRule := make(map[string]int, len(materials))
	for i, material := range materials {
		if _, err := tls.X509KeyPair([]byte(material.CertPEM), []byte(material.KeyPEM)); err != nil {
			return nil, fmt.Errorf("证书与私钥不匹配 %s: %w", material.RuleID, err)
		}
		if certPath, _ := CertFilePaths(material.RuleID); certPath == "" {
			return nil, fmt.Errorf("非法的规则编号: %q", material.RuleID)
		}
		lastMaterialByRule[material.RuleID] = i
	}

	changedMaterials := make([]CertMaterial, 0, len(lastMaterialByRule))
	snapshot := make(CertFilesSnapshot, len(lastMaterialByRule))
	for i, material := range materials {
		if lastMaterialByRule[material.RuleID] != i {
			continue
		}
		certPath, keyPath := CertFilePaths(material.RuleID)
		cert, err := snapshotCertFile(certPath)
		if err != nil {
			return nil, fmt.Errorf("快照证书 %s: %w", material.RuleID, err)
		}
		key, err := snapshotCertFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("快照私钥 %s: %w", material.RuleID, err)
		}
		if cert.Exists && cert.Mode == 0644 && key.Exists && key.Mode == 0600 && bytes.Equal(cert.Data, []byte(material.CertPEM)) && bytes.Equal(key.Data, []byte(material.KeyPEM)) {
			continue
		}
		snapshot[material.RuleID] = CertPairSnapshot{Cert: cert, Key: key}
		changedMaterials = append(changedMaterials, material)
	}
	if len(changedMaterials) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return nil, fmt.Errorf("创建证书目录: %w", err)
	}
	for _, material := range changedMaterials {
		certPath, keyPath := CertFilePaths(material.RuleID)
		if err := writeCertPair(certPath, keyPath, material.CertPEM, material.KeyPEM); err != nil {
			return nil, errors.Join(fmt.Errorf("物化证书 %s: %w", material.RuleID, err), restoreCertFilesLocked(snapshot))
		}
	}
	return snapshot, nil
}

func snapshotCertFile(path string) (CertFileSnapshot, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return CertFileSnapshot{}, nil
	}
	if err != nil {
		return CertFileSnapshot{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return CertFileSnapshot{}, err
	}
	return CertFileSnapshot{Data: data, Mode: info.Mode().Perm(), Exists: true}, nil
}

func restoreCertFile(path string, snapshot CertFileSnapshot) error {
	if !snapshot.Exists {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	temporaryPath := path + ".restore"
	if err := writeSyncedFile(temporaryPath, snapshot.Data, snapshot.Mode); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		removeErr := os.Remove(temporaryPath)
		return errors.Join(err, removeErr)
	}
	return syncParentDir(path)
}

func MaterializeAllCertsFromDB() {
	if err := os.MkdirAll(certDir, 0755); err != nil {
		Logf("error", "certstore: create cert dir failed: %v", err)
		return
	}
	manualRecovered := 0
	acmeRecovered := 0

	rows, err := db.DB.Query(`SELECT caddy_id, tls_cert, tls_key FROM lb_rules WHERE enable_tls=1 AND tls_source='manual' AND COALESCE(tls_cert,'')!='' AND COALESCE(tls_key,'')!=''`)
	if err != nil {
		Logf("error", "certstore: query manual certs failed: %v", err)
		RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), "类型：手动证书", AuditResultPart("query_failed")), "")
	} else {
		for rows.Next() {
			var ruleID, certPEM, keyPEM string
			if err := rows.Scan(&ruleID, &certPEM, &keyPEM); err != nil {
				Logf("error", "certstore: scan manual cert failed: %v", err)
				continue
			}
			changed, materializeErr := materializeCertPair(ruleID, certPEM, keyPEM)
			if materializeErr != nil {
				Logf("error", "certstore: write manual cert %s failed: %v", ruleID, materializeErr)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(ruleID), "类型：手动证书", AuditResultPart("io_error")), "")
			} else if changed {
				manualRecovered++
			}
		}
		if err := rows.Err(); err != nil {
			Logf("error", "certstore: iterate manual certs failed: %v", err)
		}
		rows.Close()
	}

	// 多行规则(同 rule_id 多 cert_jobs 行)必须按
	// certJobRuleApplicable 同语义过滤——否则灾备物化内容取决于扫描顺序,
	// 可能重建旧域证书。取每 rule_id 最新行且校验域名适用。
	rows2, err := db.DB.Query(`SELECT j.rule_id, j.cert_pem, j.key_pem, COALESCE(j.domain,''), COALESCE(r.domain,'') FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE ` + CertJobMaterialPredicateSQL("j") + `
		  AND r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns'
		ORDER BY j.rule_id, j.updated_at DESC, j.id DESC`)
	if err != nil {
		Logf("error", "certstore: query ACME certs failed: %v", err)
		RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), "类型：ACME证书", AuditResultPart("query_failed")), "")
	} else {
		seenRules := make(map[string]bool)
		for rows2.Next() {
			var ruleID, certPEM, keyPEM, jobDomain, ruleDomain string
			if err := rows2.Scan(&ruleID, &certPEM, &keyPEM, &jobDomain, &ruleDomain); err != nil {
				Logf("error", "certstore: scan ACME cert failed: %v", err)
				continue
			}
			// 同 rule_id 多行只取首个**适用**行（ORDER BY updated_at DESC, id DESC）。
			// （同族收敛，对齐 certificates.go reconcile 历史
			// 必须先判适用性再标记 seen——先 seen 后适用性会让最新
			// 旧域行短路较旧的适用行，整条规则被跳过、证书文件不物化。
			if seenRules[ruleID] {
				continue
			}
			// 域名适用性校验(与 certJobRuleApplicable 同语义)——任务签发
			// 域名与规则当前域名不一致时物化会写入不匹配证书。
			if !certJobRuleApplicable(true, ruleDomain, jobDomain) {
				continue
			}
			seenRules[ruleID] = true
			changed, materializeErr := materializeCertPair(ruleID, certPEM, keyPEM)
			if materializeErr != nil {
				Logf("error", "certstore: write ACME cert %s failed: %v", ruleID, materializeErr)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(ruleID), "类型：ACME证书", AuditResultPart("io_error")), "")
			} else if changed {
				acmeRecovered++
			}
		}
		if err := rows2.Err(); err != nil {
			Logf("error", "certstore: iterate ACME certs failed: %v", err)
		}
		rows2.Close()
	}
	if manualRecovered > 0 || acmeRecovered > 0 {
		RecordAuditLog("system", "恢复", "证书文件", FormatAuditDetail(AuditSourcePart("startup_materialization"), fmt.Sprintf("手动证书 %d 个", manualRecovered), fmt.Sprintf("ACME证书 %d 个", acmeRecovered)), "")
	}
	TaskLogf("startup:config-load", "certs", "证书物化完成：手动证书 %d 个、ACME 证书 %d 个落盘", manualRecovered, acmeRecovered)
}

// materializeCertPair 把库内证书对物化到磁盘，返回是否真正发生了写入。
// 内容与权限已一致时零写（返回 changed=false）——调用方的恢复计数
// 与审计/任务日志必须只统计 changed，否则每次启动都报「恢复 N 个」，稀释真正
// 的恢复事件（运维无法区分「真恢复」与「本来就在」）。
func materializeCertPair(ruleID, certPEM, keyPEM string) (bool, error) {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return false, fmt.Errorf("证书与私钥不匹配: %w", err)
	}
	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return false, fmt.Errorf("非法的规则编号: %q", ruleID)
	}
	diskCert, certErr := os.ReadFile(certPath)
	diskKey, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil && bytes.Equal(diskCert, []byte(certPEM)) && bytes.Equal(diskKey, []byte(keyPEM)) {
		// 跳过前检查权限(与 writeCertPair/MaterializeCertPairs 同
		// 契约)——私钥被 chmod 0644 后启动路径此前不修复,直到下次 apply。
		if certInfo, serr := os.Stat(certPath); serr == nil && certInfo.Mode().Perm() == 0644 {
			if keyInfo, kerr := os.Stat(keyPath); kerr == nil && keyInfo.Mode().Perm() == 0600 {
				// 删除对磁盘字节的重复 X509KeyPair 解析——
				// :467 的 bytes.Equal 已证明磁盘字节与 :458 刚验证通过的库内
				// 字节完全相同，二次解析不可能产生不同结果。
				return false, nil
			}
		}
	}
	if err := WriteCertFiles(ruleID, certPEM, keyPEM); err != nil {
		return false, err
	}
	return true, nil
}
