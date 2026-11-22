package services

// 主节点证书文件扫描器（用户最终裁定流程 · JJC-20261122-003 续作）：
// 主节点定期扫描 certDir（/app/certs）下 *.crt + 同名 *.key 配对，校验合法性
// 后以指纹比对 cert_secrets，只在内容真正变化时密文入库并推进 cert_version；
// 从节点经快照密文轴导入 + cert_version 差判定自动 force 热重载 Caddy，
// 全程不需要重启容器。
//
// 挂载点：cluster-sync daemon 的主分支 Run 体（masterSyncServingLifecycleRun），
// 因此天然只在主节点运行、随引擎换代 ctx 取消而退出。甲路线关闭时整个扫描
// 函数 no-op（零回归），DEK 未配置时同样不启动。

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/caddydbcert"
	"lazy-balancer-v2/internal/db"
)

const (
	// CertFileScanIntervalEnv 扫描周期环境变量（秒）。未设置/非法/非正数一律
	// 回落到默认 60s——不因一个拼写错误的运维变量把主节点变成高频数据库写入机。
	CertFileScanIntervalEnv = "LB_CERT_FILE_SCAN_INTERVAL"
	defaultCertFileScanSec  = 60
	// certFileScanWarnWindow 同一把 key 的告警节流窗口：文件被外部反复写坏时
	// 每轮都刷 warn 会淹没任务日志，窗口内只记一次。
	certFileScanWarnWindow = 5 * time.Minute
)

// certFileScanInterval 是扫描周期的单源默认值（测试可压缩时钟直接改写）。
var certFileScanInterval = defaultCertFileScanSec * time.Second

// certFileScanErrors 累计扫描错误数（跨轮，供诊断；单轮明细见 certScanRound）。
var certFileScanErrors atomic.Uint64

var (
	certFileScanWarnMu sync.Mutex
	certFileScanWarnAt = make(map[string]time.Time)
)

// certFileScanWarn 节流告警：同一 key 在窗口内只输出一次。
func certFileScanWarn(key, format string, args ...any) {
	now := time.Now()
	certFileScanWarnMu.Lock()
	if last, ok := certFileScanWarnAt[key]; ok && now.Sub(last) < certFileScanWarnWindow {
		certFileScanWarnMu.Unlock()
		return
	}
	certFileScanWarnAt[key] = now
	// 有界化：被反复改名的坏文件不会让 key 空间无界增长。
	if len(certFileScanWarnAt) > 512 {
		for k, t := range certFileScanWarnAt {
			if now.Sub(t) > certFileScanWarnWindow {
				delete(certFileScanWarnAt, k)
			}
		}
	}
	certFileScanWarnMu.Unlock()
	Logf("warn", format, args...)
}

// effectiveCertFileScanInterval 解析环境变量，非法值告警后回落默认。
func effectiveCertFileScanInterval() time.Duration {
	raw := os.Getenv(CertFileScanIntervalEnv)
	if raw == "" {
		return certFileScanInterval
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || seconds <= 0 {
		Logf("warn", "证书文件扫描周期 %s=%q 非法（须为正整数秒），回落默认 %ds", CertFileScanIntervalEnv, raw, defaultCertFileScanSec)
		return certFileScanInterval
	}
	return time.Duration(seconds) * time.Second
}

// startCertFileScanLoop 在主节点 daemon Run 体内拉起扫描循环。仅在甲路线启用
// 且 DEK 来源存在时启动；ctx 取消（引擎停机/角色翻转）即真实退出。
func startCertFileScanLoop(ctx context.Context) {
	if !DBCertLoaderEnabled() {
		return
	}
	if CertVaultDEKSource() == "" {
		certFileScanWarn("dek-missing", "证书文件扫描未启动：甲路线已启用但 DEK 未配置（%s / %s 均为空）", DefaultCertDEKEnv, kmsEndpointEnv)
		return
	}
	interval := effectiveCertFileScanInterval()
	Logf("info", "证书文件扫描启动：每 %d 秒扫描 %s 下的证书对入库（密文）", int(interval.Seconds()), CertDir())
	go func() {
		scanCertFilesToVault(ctx) // 启动即首轮，避免刚升级的存量文件要等一个周期
		//scope-exempt: daemon-run-body-loop —— 主节点证书文件周期扫描（daemon Run 体自管理阻塞循环，ctx 取消即退）
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				scanCertFilesToVault(ctx)
			}
		}
	}()
}

// certScanRound 一轮扫描的可观测结果（测试直接断言；生产按差异落日志）。
type certScanRound struct {
	Pairs     int // 通过合法性校验并进入比对/入库的证书对数
	Upserted  int // 本轮真正写入（新增或内容变化）的证书数
	Unchanged int // 指纹一致、跳过 Upsert 的证书数（cert_version 不抖动的关键）
	Failed    int // 单个文件失败数（不中断整批）
}

type vaultRowBrief struct {
	domain  string
	fp      string
	deleted int
}

// scanCertFilesToVault 执行一轮证书文件 → 密文库扫描。
//
// 关键不变量：指纹相同绝不再调 Upsert。cert_secrets 的触发器在密文实质变更时
// 每写一次 cert_version +1；若每轮重复 Upsert，从端每轮都检测到 before<after
// 而永久 force reload（用户明确要求避免）。比对口径：
//   - 已存在同 rule_id 的行：沿用其 domain 计算指纹（与启动回填完全同口径，
//     避免为同一规则再造一行不同 domain 的重复证书）；
//   - 全新规则：domain 取证书 SAN 首项，无 SAN 时回落文件名 ruleID（与回填
//     COALESCE(NULLIF(domain,''), rule_id) 的兜底口径一致）。
func scanCertFilesToVault(ctx context.Context) certScanRound {
	var round certScanRound
	if !DBCertLoaderEnabled() || db.DB == nil {
		return round // 甲路线关闭：完全 no-op
	}
	if CertVaultDEKSource() == "" {
		return round // DEK 未配置：不入库（Upsert 也会 ErrNoKey，这里提前收口）
	}
	if ctx.Err() != nil {
		return round
	}
	dir := CertDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			certFileScanWarn("readdir", "证书文件扫描失败（下一轮重试）：%v", err)
			certFileScanErrors.Add(1)
		}
		return round
	}
	provider := certKeyProvider(os.Getenv(kmsEndpointEnv))
	wrapped := os.Getenv("LB_CERT_WRAPPED_DEK")
	for _, entry := range entries {
		if ctx.Err() != nil {
			return round
		}
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".crt") {
			continue
		}
		ruleID := strings.TrimSuffix(name, ".crt")
		if !ValidCertRuleID(ruleID) {
			// 引用型证书/其它带外文件名不属本扫描口径（它们走 JJC-001 快照轴）。
			continue
		}
		certPath := filepath.Join(dir, name)
		keyPath := filepath.Join(dir, ruleID+".key")
		certPEM, certErr := os.ReadFile(certPath)
		keyPEM, keyErr := os.ReadFile(keyPath)
		if certErr != nil || keyErr != nil {
			certFileScanWarn("read:"+ruleID, "证书文件扫描跳过 %s：读取失败（cert=%v key=%v）", ruleID, certErr, keyErr)
			round.Failed++
			certFileScanErrors.Add(1)
			continue
		}
		if _, pairErr := tls.X509KeyPair(certPEM, keyPEM); pairErr != nil {
			certFileScanWarn("pair:"+ruleID, "证书文件扫描跳过 %s：证书与私钥不匹配：%v", ruleID, pairErr)
			round.Failed++
			certFileScanErrors.Add(1)
			continue
		}
		round.Pairs++
		existing, queryErr := vaultRowsForRule(ctx, ruleID)
		if queryErr != nil {
			certFileScanWarn("query:"+ruleID, "证书文件扫描跳过 %s：读取证书库失败：%v", ruleID, queryErr)
			round.Failed++
			certFileScanErrors.Add(1)
			continue
		}
		certStr, keyStr := string(certPEM), string(keyPEM)
		if len(existing) == 0 {
			domain := certPrimaryDomain(certPEM, ruleID)
			if _, err := caddydbcert.Upsert(ctx, db.DB, provider, wrapped, domain, ruleID, certStr, keyStr, false, []string{ruleID}); err != nil {
				certFileScanWarn("upsert:"+ruleID, "证书文件扫描入库失败 %s：%v", ruleID, err)
				round.Failed++
				certFileScanErrors.Add(1)
				continue
			}
			round.Upserted++
			continue
		}
		// 同 rule_id 可能有多行（不同 domain 的历史回填）：逐行按各自 domain
		// 计算指纹，已一致且未删除的行跳过；变化的写入并把陈旧副本收敛。
		for _, row := range existing {
			fp := caddydbcert.Fingerprint(certStr, keyStr, row.domain)
			if row.fp == fp && row.deleted == 0 {
				round.Unchanged++
				continue
			}
			if _, err := caddydbcert.Upsert(ctx, db.DB, provider, wrapped, row.domain, ruleID, certStr, keyStr, false, []string{ruleID}); err != nil {
				certFileScanWarn("upsert:"+ruleID, "证书文件扫描入库失败 %s/%s：%v", row.domain, ruleID, err)
				round.Failed++
				certFileScanErrors.Add(1)
				continue
			}
			round.Upserted++
		}
	}
	if round.Upserted > 0 {
		Logf("info", "证书文件扫描：本轮入库 %d 项（跳过未变 %d 项，失败 %d 项）", round.Upserted, round.Unchanged, round.Failed)
	}
	return round
}

// vaultRowsForRule 读取某规则在密文库中的全部行（domain/fingerprint/deleted）。
func vaultRowsForRule(ctx context.Context, ruleID string) ([]vaultRowBrief, error) {
	rows, err := db.DB.QueryContext(ctx, `SELECT domain, fingerprint, deleted FROM cert_secrets WHERE rule_id=?`, ruleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []vaultRowBrief
	for rows.Next() {
		var row vaultRowBrief
		if err := rows.Scan(&row.domain, &row.fp, &row.deleted); err != nil {
			return nil, err
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// certPrimaryDomain 从证书 SAN 中取主域名；无 SAN 时回落到文件名 ruleID，
// 与 BackfillFromPlaintext 的 COALESCE(NULLIF(domain,''), rule_id) 同口径。
func certPrimaryDomain(certPEM []byte, fallback string) string {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return fallback
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || len(cert.DNSNames) == 0 {
		return fallback
	}
	// 优先具体域名而非通配 SAN——与规则 domain 列取值口径一致。
	for _, name := range cert.DNSNames {
		if name != "" && !strings.HasPrefix(name, "*.") {
			return name
		}
	}
	if name := cert.DNSNames[0]; name != "" {
		return name
	}
	return fallback
}
