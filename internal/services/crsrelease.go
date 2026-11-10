package services

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// validateCRSStaging ensures an extracted CRS release tree is complete enough
// to swap into place: the setup template plus an intact rules tree.
// 探针文件（crsRulesProbeFile）是 backup restore / seed / snapshot 消费门共用
// 的完整性契约，安装期必须同步把关——否则未来 CRS 重组 rules/ 的发布会装出
// 退化树，之后每次启动都触发清空重播循环。
func validateCRSStaging(dir string) error {
	if info, err := os.Stat(filepath.Join(dir, "crs-setup.conf.example")); err != nil || info.IsDir() {
		return fmt.Errorf("staging 缺少 crs-setup.conf.example")
	}
	if !crsRulesTreeIntact(filepath.Join(dir, "rules")) {
		return fmt.Errorf("staging rules 树不完整（无 .conf 规则文件或缺失 %s）；该探针文件是安装契约——若上游 CRS 发布结构已变更，请等待适配版本或手动回退，切勿绕过校验强行安装", crsRulesProbeFile)
	}
	return nil
}

// countSecRules counts SecRule directives across all *.conf files in dir
// (recursive, matching crsRulesTreeIntact's tree-wide .conf probe: a rule tree
// with subdirectories must not report "library available, count 0").
// Only lines whose first token is exactly "SecRule" count; comments and
// lookalike directives (SecRuleUpdateTargetById, SecRuleRemoveById, ...) do not.
func countSecRules(dir string) (int, error) {
	total := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".conf") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("读取规则文件 %s: %w", d.Name(), err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimLeft(line, " \t")
			if trimmed == "SecRule" || strings.HasPrefix(trimmed, "SecRule ") || strings.HasPrefix(trimmed, "SecRule\t") {
				total++
			}
		}
		return nil
	})
	if err != nil {
		if _, statErr := os.Stat(dir); statErr != nil {
			return 0, fmt.Errorf("读取规则目录: %w", statErr)
		}
		return 0, err
	}
	return total, nil
}

// CountSecRulesLive counts SecRule directives in the live rules directory.
func CountSecRulesLive() (int, error) {
	return countSecRules(filepath.Join(crsLiveDir, "rules"))
}

// compareCRSVersions compares two dotted version tags (optional leading "v"),
// returning -1, 0 or 1. Missing segments are treated as 0.
func compareCRSVersions(a, b string) (int, error) {
	pa, err := parseVersionParts(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseVersionParts(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa) || i < len(pb); i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1, nil
		}
		if va > vb {
			return 1, nil
		}
	}
	return 0, nil
}

// CompareCRSVersions exposes compareCRSVersions for handlers.
func CompareCRSVersions(a, b string) (int, error) {
	return compareCRSVersions(a, b)
}

func parseVersionParts(tag string) ([]int, error) {
	trimmed := strings.TrimPrefix(strings.TrimSpace(tag), "v")
	if trimmed == "" {
		return nil, fmt.Errorf("无法解析版本号 %q", tag)
	}
	parts := strings.Split(trimmed, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		value, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("无法解析版本号 %q: %w", tag, err)
		}
		out = append(out, value)
	}
	return out, nil
}

// parseGitHubLatestTag extracts tag_name from a GitHub releases/latest body.
func parseGitHubLatestTag(body []byte) (string, error) {
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("解析 GitHub 响应失败: %w", err)
	}
	if payload.TagName == "" {
		return "", errors.New("GitHub 响应缺少 tag_name")
	}
	// 与 HTML 回退路径同口径校验 tag 形状（控制字符/换行
	// 会进入版本行、日志与审计，并参与 raw.githubusercontent URL 拼接）。
	if err := validateReleaseTag(payload.TagName); err != nil {
		return "", err
	}
	return payload.TagName, nil
}

// crsExtractMaxBytes 是解压总字节上限（防 gzip 炸弹耗尽数据卷）
// tar 头声明的 hdr.Size 即解压后写入的确切字节数，跨条目累计超限即中止。
const crsExtractMaxBytes = 500 << 20

// crsExtractMaxFiles / crsExtractMaxDirs 与 untarGzTo 三门同口径：字节门只
// 累计 hdr.Size，0 字节条目与目录头不占额度——2GB 下载上限内的包可携带
// 数百万个空条目/目录头，在 staging 建海量 inode 并让失败路径 RemoveAll
// 逐条删除。正常 CRS 树 ~50 文件、数个目录，上限留两个数量级余量。
const (
	crsExtractMaxFiles = 2000
	crsExtractMaxDirs  = 2 * crsExtractMaxFiles
)

// extractCRSTarball extracts a GitHub release tar.gz into destDir, stripping
// the single top-level root directory GitHub adds to every entry.
func extractCRSTarball(tarballPath, destDir string) error {
	f, err := os.Open(tarballPath)
	if err != nil {
		return fmt.Errorf("打开 tarball: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("解压 gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var totalBytes int64
	files, dirs := 0, 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("读取 tar: %w", err)
		}
		// 先减后比：totalBytes 恒 ≤ crsExtractMaxBytes（每个被接受条目维持该
		// 不变量），减法不下溢；加法在 hdr.Size 接近 2^63-1（GNU base-256）时
		// int64 溢出为负，会绕过上限（发现1，镜像 waffiles_sync.go 口径）。
		if hdr.Size < 0 || hdr.Size > crsExtractMaxBytes-totalBytes {
			return fmt.Errorf("tarball 解压超过大小上限（%d MB）", crsExtractMaxBytes>>20)
		}
		totalBytes += hdr.Size
		// 条目数门（与字节门并行执法）：空条目/目录头不占字节额度。
		if hdr.Typeflag == tar.TypeDir {
			dirs++
			if dirs > crsExtractMaxDirs {
				return fmt.Errorf("tarball 目录条目数超过上限（%d）", crsExtractMaxDirs)
			}
		} else {
			files++
			if files > crsExtractMaxFiles {
				return fmt.Errorf("tarball 文件条目数超过上限（%d）", crsExtractMaxFiles)
			}
		}
		rel, err := stripTarRoot(hdr.Name)
		if err != nil {
			return err
		}
		if rel == "" {
			continue
		}
		target := filepath.Join(destDir, rel)
		if !strings.HasPrefix(target, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("tarball 包含非法路径 %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("创建目录 %s: %w", rel, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("创建目录 %s: %w", filepath.Dir(rel), err)
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return fmt.Errorf("写入 %s: %w", rel, err)
			}
			_, copyErr := io.Copy(out, tr)
			// 落盘耐久性与 writeFileAtomicSynced 同口径：解压树随后被
			// moveTree 换入 live，掉电/容器强杀窗口内未 fsync 的页可能留下
			// 0 字节或截断规则文件——crsRulesTreeIntact 只查探针文件存在，
			// 残缺树会被装载并静默削弱 WAF。
			syncErr := error(nil)
			if copyErr == nil {
				syncErr = out.Sync()
			}
			closeErr := out.Close()
			if copyErr != nil {
				return fmt.Errorf("写入 %s: %w", rel, copyErr)
			}
			if syncErr != nil {
				return fmt.Errorf("同步 %s: %w", rel, syncErr)
			}
			if closeErr != nil {
				return fmt.Errorf("写入 %s: %w", rel, closeErr)
			}
		}
	}
}

// stripTarRoot removes the first path component (the GitHub root directory)
// and rejects absolute paths or any remaining ".." traversal component.
func stripTarRoot(name string) (string, error) {
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("tarball 包含绝对路径 %q", name)
	}
	parts := strings.Split(filepath.ToSlash(name), "/")
	rest := parts[1:]
	for _, part := range rest {
		if part == ".." {
			return "", fmt.Errorf("tarball 包含非法路径 %q", name)
		}
	}
	if len(rest) == 0 {
		return "", nil
	}
	return filepath.Join(rest...), nil
}
