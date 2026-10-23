package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 「材料可用性」只允许一处实现（certmaterial.go）：SQL 谓词必须调用
// CertJobMaterialPredicateSQL，内存行必须调用 CertJobMaterialUsable。
//
// 历史事故正是多套实现并存——渲染面把「有材料」判宽、导入清理判窄，结果把仍在
// 对外服务的证书文件删掉。此扫描把「不许再长出内联谓词」变成机器判定：新增
// 证书域生产文件时把文件名加进清单（或让扫描覆盖更宽），漏加只会让覆盖面变小，
// 不会让本测试假红。
func TestCertJobMaterialPredicate_hasNoInlineCopies(t *testing.T) {
	servicesFiles := []string{
		"certificates.go", "certissuer.go", "certstore.go", "certinfo.go",
		"certselector.go", "caqueue.go", "certjoblog.go",
	}
	for _, name := range servicesFiles {
		assertNoInlineMaterialPredicate(t, name)
	}
	handlerFiles, err := filepath.Glob(filepath.Join("..", "handlers", "cert*.go"))
	if err != nil {
		t.Fatalf("glob handler certificate files: %v", err)
	}
	for _, path := range handlerFiles {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		assertNoInlineMaterialPredicate(t, path)
	}
}

func assertNoInlineMaterialPredicate(t *testing.T, path string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	for lineNo, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "cert_pem") || !strings.Contains(line, "key_pem") {
			continue
		}
		if strings.Contains(line, "CertJobMaterialPredicateSQL") || strings.Contains(line, "CertJobMaterialUsable") {
			continue
		}
		if strings.Contains(line, "<> ''") || strings.Contains(line, "!= ''") ||
			strings.Contains(line, "<>''") || strings.Contains(line, "!=''") {
			t.Errorf("%s:%d 内联材料谓词，必须复用 CertJobMaterialPredicateSQL/CertJobMaterialUsable: %s",
				path, lineNo+1, strings.TrimSpace(line))
		}
	}
}

// 空白 PEM 必须与单源 Go 判据同结论（无材料）：trim 口径分叉会让补偿路径把
// 「只有空格的材料」当作可部署，进入部署快速路径后永久重试。
func TestRequeueCanceledJob_whitespaceMaterialTreatedAsAbsent(t *testing.T) {
	jobID, _ := seedCertificateJob(t, "downloaded")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='   ', key_pem='key' WHERE id=?`, jobID); err != nil {
		t.Fatalf("seed whitespace material: %v", err)
	}

	// When
	requeueCanceledJob(jobID)

	// Then：按无材料处理 → 回落重新排队（而非保留部署态）
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=?", jobID).Scan(&status); err != nil {
		t.Fatalf("read job status: %v", err)
	}
	if status != "queued" {
		t.Fatalf("status=%q, want queued（空白材料按无材料处理）", status)
	}
}
