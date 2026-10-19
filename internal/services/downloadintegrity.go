package services

// 下载校验（TOFU）：经 GitHub 加速代理（github_proxy_url 白名单，历史硬编码
// ghfast.top 已废弃）下载无上游官方校验和可钉，首次成功下载后把 size+SHA256
// 记录到数据卷（.download-integrity.json）；后续同一来源（URL 含版本 tag）下载
// 若 size 或摘要变化，说明代理返回内容与上次不一致，以 error 日志 + 审计记录
// 告警并返回错误阻断安装、保留旧基线（格式校验仍由调用方执行）。内容变化必须
// 经人工清理基线（删除记录文件中该来源条目）后重试，不自动重定基线。

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// downloadIntegrityPath 是完整性记录文件路径；定义为变量以便测试注入。
var downloadIntegrityPath = "/app/data/.download-integrity.json"

// downloadIntegrityMu 串行化记录文件的 load-modify-persist：CRS 与 ip2region
// 两个更新调度器可能同时到期下载（同小时并发），共享同一记录文件时丢失更新
// 或撕裂 tmp 文件（历史问题 F4）。所有读改写路径都必须在持锁下进行。
// S历史问题：锁内只做文件 load-modify-persist 与状态判定——日志/审计落库（审计库
// I/O）一律解锁后执行，照抄看门狗 历史问题 的 pendingIO 模式：审计库被外部写锁
// 占住时（busy_timeout 30s），持锁落审计会让两族更新调度器互相阻塞。
var downloadIntegrityMu sync.Mutex

// downloadIntegrityAudit 是「锁内判定、锁外落库」的审计记录载荷。
type downloadIntegrityAudit struct {
	action   string
	resource string
	detail   string
}

// recordDownloadIntegrityAudits 落库锁内收集的审计记录（调用方必须已解锁）。
func recordDownloadIntegrityAudits(audits []downloadIntegrityAudit) {
	for _, audit := range audits {
		RecordAuditLog("system", audit.action, audit.resource, audit.detail, "")
	}
}

type downloadIntegrityRecord struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// errDownloadIntegrityMismatch 标记「下载内容与 TOFU 基线不一致」的阻断性
// 失败，供调用方与 I/O 类失败区分：mismatch 必须中止安装（审计 M11，契约#4），
// I/O 失败仅记日志不阻断（历史问题 F6 既有语义）。
var errDownloadIntegrityMismatch = errors.New("下载完整性校验失败：内容与基线不一致")

// recordDownloadIntegrity 校验并记录一次成功下载的完整性快照：首次下载写入
// 基线；同一来源再次下载且 size/digest 与基线不符时 Logf("error") + 审计并
// 返回 errDownloadIntegrityMismatch 包装错误（阻断安装、保留旧基线）。必须在
// 下载文件的格式验证成功之后调用——验证前的坏工件基线会让下次同源好下载
// 误报（历史问题 F6）。
func recordDownloadIntegrity(source, destPath, resource string) error {
	info, err := os.Stat(destPath)
	if err != nil {
		return err
	}
	digest, err := sha256File(destPath)
	if err != nil {
		return err
	}
	downloadIntegrityMu.Lock()
	records, audits, err := loadDownloadIntegrityRecords()
	if err != nil {
		downloadIntegrityMu.Unlock()
		recordDownloadIntegrityAudits(audits)
		return err
	}
	prev, existed := records[source]
	// 审计 M11（契约#4）：mismatch 阻断安装并保留旧基线——ghfast.top 类镜像
	// 代理投毒时「仅告警+自动重定基线」无拦截力；内容变化必须经人工清理基线
	// （删除记录文件中该来源条目）后重试。
	if existed && (prev.Size != info.Size() || prev.SHA256 != digest) {
		// S历史问题：锁内只构造文案与错误，日志/审计在解锁后落库。
		mismatchErr := fmt.Errorf("来源 %s 下载内容与上次完整性记录不一致（size %d→%d，sha256 %s→%s），已阻断安装；如确认上游更新合法，删除 %s 中该来源条目后重试: %w",
			source, prev.Size, info.Size(), prev.SHA256, digest, downloadIntegrityPath, errDownloadIntegrityMismatch)
		audits = append(audits, downloadIntegrityAudit{
			action:   "校验阻断",
			resource: resource,
			detail:   FormatAuditDetail(fmt.Sprintf("来源 %s 的下载内容与上次记录不一致（size %d→%d，sha256 %s→%s），已阻断安装并保留旧基线", source, prev.Size, info.Size(), prev.SHA256, digest)),
		})
		downloadIntegrityMu.Unlock()
		Logf("error", "download integrity mismatch for %s: size %d→%d, sha256 %s→%s（与上次记录不一致，已阻断安装并保留旧基线；如确认上游更新合法，删除 %s 中该来源条目后重试）", source, prev.Size, info.Size(), prev.SHA256, digest, downloadIntegrityPath)
		recordDownloadIntegrityAudits(audits)
		return mismatchErr
	}
	records[source] = downloadIntegrityRecord{Size: info.Size(), SHA256: digest}
	err = persistDownloadIntegrityRecords(records)
	downloadIntegrityMu.Unlock()
	recordDownloadIntegrityAudits(audits)
	return err
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// loadDownloadIntegrityRecords 读取记录文件（调用方须持有 downloadIntegrityMu）。
// 损坏文件的隔离审计以返回值交给调用方在解锁后落库（S历史问题）。
func loadDownloadIntegrityRecords() (map[string]downloadIntegrityRecord, []downloadIntegrityAudit, error) {
	data, err := os.ReadFile(downloadIntegrityPath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]downloadIntegrityRecord{}, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	var records map[string]downloadIntegrityRecord
	if err := json.Unmarshal(data, &records); err != nil {
		// 损坏记录文件会静默禁用 TOFU 完整性检查且不自愈（历史问题 F5）：隔离文件
		// （rename 为 .corrupt-<ts>）保留取证现场，error 日志 + 审计记录告警，
		// 并从头重建基线。
		quarantined := downloadIntegrityPath + ".corrupt-" + time.Now().UTC().Format("20060102-150405")
		if err := os.Rename(downloadIntegrityPath, quarantined); err != nil {
			// 隔离失败时如实记录：文件仍在原位，后续 persist（tmp+rename）会覆盖
			// 重建，但取证副本缺失（历史问题 F）。
			Logf("error", "download integrity: records file %s is corrupt, quarantine rename to %s failed: %v（原文件保留，直接重建基线）", downloadIntegrityPath, quarantined, err)
			return map[string]downloadIntegrityRecord{}, []downloadIntegrityAudit{{
				action:   "下载校验",
				resource: "完整性记录",
				detail:   FormatAuditDetail(fmt.Sprintf("记录文件 %s 解析失败，隔离为 %s 失败：%v", downloadIntegrityPath, quarantined, err)),
			}}, nil
		}
		Logf("error", "download integrity: records file %s is corrupt, quarantined to %s and baselines rebuilt", downloadIntegrityPath, quarantined)
		return map[string]downloadIntegrityRecord{}, []downloadIntegrityAudit{{
			action:   "下载校验",
			resource: "完整性记录",
			detail:   FormatAuditDetail(fmt.Sprintf("记录文件 %s 解析失败，已隔离为 %s 并重建基线", downloadIntegrityPath, quarantined)),
		}}, nil
	}
	if records == nil {
		records = map[string]downloadIntegrityRecord{}
	}
	return records, nil, nil
}

func persistDownloadIntegrityRecords(records map[string]downloadIntegrityRecord) error {
	data, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(downloadIntegrityPath), 0o755); err != nil {
		return err
	}
	// D1-历史问题：tmp+rename 缺 fsync 可留下 0 字节记录（基线丢失/误重建）。
	return writeFileAtomicSynced(downloadIntegrityPath, data, 0o644)
}
