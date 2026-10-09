package services

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"lazy-balancer-v2/internal/db"
)

var certDir = "/app/certs"

// CertDir 返回引用型证书允许的根目录（tls_source="file" 白名单边界）。
func CertDir() string { return certDir }

// ReferencedCertificate 引用型证书（tls_source="file"）的校验结果：
// 归一后的路径 + 已读取的 PEM 内容（仅供调用方校验与预检，不落库）。
type ReferencedCertificate struct {
	CertPath string
	KeyPath  string
	CertPEM  string
	KeyPEM   string
}

// ResolveReferencedCertPath 校验并归一引用型证书文件路径（2026-10-09）：
//   - 绝对路径、位于 certDir 内（前缀 + 分隔符边界，防 /app/certs-evil 绕过）；
//   - 拒绝空串、目录、含 NUL 的路径；
//   - 文件须存在且为常规文件；
//   - 解析符号链接后再次校验边界（防目录内软链指向容器任意文件）。
//
// 返回归一路径用于展示与落库（保持用户输入语义），安全性由真实路径校验保证。
func ResolveReferencedCertPath(rawPath string) (string, error) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "", fmt.Errorf("证书文件路径不能为空")
	}
	if strings.ContainsRune(trimmed, 0) {
		return "", fmt.Errorf("证书文件路径含非法字符")
	}
	cleaned := filepath.Clean(trimmed)
	if !filepath.IsAbs(cleaned) {
		return "", fmt.Errorf("证书文件路径必须是绝对路径")
	}
	base := filepath.Clean(certDir)
	if !pathWithinBase(cleaned, base) {
		return "", fmt.Errorf("证书文件路径必须位于 %s 目录内", base)
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("证书文件不存在: %s", cleaned)
		}
		return "", fmt.Errorf("读取证书文件失败: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("证书文件路径不能是目录: %s", cleaned)
	}
	// 符号链接逃逸：目录与文件均解析为真实路径后复核边界（目录本身为软链时
	// 以解析后的真实目录为基准，避免误判）。
	realPath, err := filepath.EvalSymlinks(cleaned)
	if err != nil {
		return "", fmt.Errorf("解析证书文件路径失败: %w", err)
	}
	if realBase, baseErr := filepath.EvalSymlinks(base); baseErr == nil {
		base = realBase
	}
	if !pathWithinBase(realPath, base) {
		return "", fmt.Errorf("证书文件路径（解析符号链接后）必须位于 %s 目录内", base)
	}
	return cleaned, nil
}

// pathWithinBase 判定 path 是否位于 base 内（严格边界：base 本身不计入）。
func pathWithinBase(path, base string) bool {
	if path == base {
		return false
	}
	return strings.HasPrefix(path, base+string(os.PathSeparator))
}

// LoadReferencedCertificate 校验引用型证书的证书/私钥两个路径并读取内容，
// 同时校验二者能配成合法密钥对（与物化路径同口径，提前失败以免 Caddy 加载期报错）。
func LoadReferencedCertificate(certPath, keyPath string) (ReferencedCertificate, error) {
	resolvedCert, err := ResolveReferencedCertPath(certPath)
	if err != nil {
		return ReferencedCertificate{}, fmt.Errorf("证书文件：%w", err)
	}
	resolvedKey, err := ResolveReferencedCertPath(keyPath)
	if err != nil {
		return ReferencedCertificate{}, fmt.Errorf("私钥文件：%w", err)
	}
	certPEM, err := os.ReadFile(resolvedCert)
	if err != nil {
		return ReferencedCertificate{}, fmt.Errorf("读取证书文件失败: %w", err)
	}
	keyPEM, err := os.ReadFile(resolvedKey)
	if err != nil {
		return ReferencedCertificate{}, fmt.Errorf("读取私钥文件失败: %w", err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return ReferencedCertificate{}, fmt.Errorf("证书与私钥不匹配: %w", err)
	}
	return ReferencedCertificate{
		CertPath: resolvedCert,
		KeyPath:  resolvedKey,
		CertPEM:  string(certPEM),
		KeyPEM:   string(keyPEM),
	}, nil
}

// ReferencedCertFileDigest 返回引用型证书文件对的内容指纹（含文件不存在标记）。
// 供「外部更新证书文件 → 自动重载」的变更检测使用：与上次快照比对，不同即视为
// 证书已更新。
func ReferencedCertFileDigest(certPath, keyPath string) string {
	certData, certErr := os.ReadFile(certPath)
	keyData, keyErr := os.ReadFile(keyPath)
	if certErr != nil || keyErr != nil {
		return fmt.Sprintf("missing:%v:%v", certErr != nil, keyErr != nil)
	}
	sum := sha256.Sum256(append(append([]byte{}, certData...), keyData...))
	return hex.EncodeToString(sum[:])
}

// SetCertDirForTest 重定向证书物化目录，仅供测试隔离使用（返回还原函数）。
func SetCertDirForTest(dir string) func() {
	old := certDir
	certDir = dir
	return func() { certDir = old }
}

// 序列化证书对文件操作，避免并发写入、恢复或删除产生撕裂的 cert/key 组合。
var certWriteMu sync.Mutex

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

func CertFilePaths(ruleID string) (certPath, keyPath string) {
	if !safeRuleID(ruleID) {
		return "", ""
	}
	return filepath.Join(certDir, ruleID+".crt"), filepath.Join(certDir, ruleID+".key")
}

func WriteCertFiles(ruleID, certPEM, keyPEM string) error {
	certWriteMu.Lock()
	defer certWriteMu.Unlock()
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
	// CL9-N14(第 9 轮审计,含权限修复契约修正):内容一致且权限正确才零写
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
	certWriteMu.Lock()
	defer certWriteMu.Unlock()

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
	certWriteMu.Lock()
	defer certWriteMu.Unlock()
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
	certWriteMu.Lock()
	defer certWriteMu.Unlock()

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
			if err := materializeCertPair(ruleID, certPEM, keyPEM); err != nil {
				Logf("error", "certstore: write manual cert %s failed: %v", ruleID, err)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(ruleID), "类型：手动证书", AuditResultPart("io_error")), "")
			} else {
				manualRecovered++
			}
		}
		if err := rows.Err(); err != nil {
			Logf("error", "certstore: iterate manual certs failed: %v", err)
		}
		rows.Close()
	}

	// CL23-2(第 23 轮审计):多行规则(同 rule_id 多 cert_jobs 行)必须按
	// certJobRuleApplicable 同语义过滤——否则灾备物化内容取决于扫描顺序,
	// 可能重建旧域证书。取每 rule_id 最新行且校验域名适用。
	rows2, err := db.DB.Query(`SELECT j.rule_id, j.cert_pem, j.key_pem, COALESCE(j.domain,''), COALESCE(r.domain,'') FROM cert_jobs j
		JOIN lb_rules r ON r.caddy_id=j.rule_id
		WHERE j.status IN ('downloaded','issued') AND COALESCE(j.cert_pem,'')!='' AND COALESCE(j.key_pem,'')!=''
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
			// 同 rule_id 多行只取首行(ORDER BY updated_at DESC=最新),旧行跳过——
			// 防旧域/旧材料覆盖新物化(CL23-2)。
			if seenRules[ruleID] {
				continue
			}
			seenRules[ruleID] = true
			// CL23-2:域名适用性校验(与 certJobRuleApplicable 同语义)——任务签发
			// 域名与规则当前域名不一致时物化会写入不匹配证书。
			if !certJobRuleApplicable(true, ruleDomain, jobDomain) {
				continue
			}
			if err := materializeCertPair(ruleID, certPEM, keyPEM); err != nil {
				Logf("error", "certstore: write ACME cert %s failed: %v", ruleID, err)
				RecordAuditLog("system", "恢复失败", "证书文件", FormatAuditDetail(AuditRulePart(ruleID), "类型：ACME证书", AuditResultPart("io_error")), "")
			} else {
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

func materializeCertPair(ruleID, certPEM, keyPEM string) error {
	if _, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM)); err != nil {
		return fmt.Errorf("证书与私钥不匹配: %w", err)
	}
	certPath, keyPath := CertFilePaths(ruleID)
	if certPath == "" {
		return fmt.Errorf("非法的规则编号: %q", ruleID)
	}
	diskCert, certErr := os.ReadFile(certPath)
	diskKey, keyErr := os.ReadFile(keyPath)
	if certErr == nil && keyErr == nil && bytes.Equal(diskCert, []byte(certPEM)) && bytes.Equal(diskKey, []byte(keyPEM)) {
		// CL10-N5:跳过前检查权限(与 writeCertPair/MaterializeCertPairs 同
		// 契约)——私钥被 chmod 0644 后启动路径此前不修复,直到下次 apply。
		if certInfo, serr := os.Stat(certPath); serr == nil && certInfo.Mode().Perm() == 0644 {
			if keyInfo, kerr := os.Stat(keyPath); kerr == nil && keyInfo.Mode().Perm() == 0600 {
				if _, err := tls.X509KeyPair(diskCert, diskKey); err == nil {
					return nil
				}
			}
		}
	}
	return WriteCertFiles(ruleID, certPEM, keyPEM)
}
