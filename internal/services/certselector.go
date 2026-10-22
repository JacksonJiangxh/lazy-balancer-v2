package services

import (
	"crypto/tls"
	"crypto/x509"
	"strings"
	"time"
)

type CertificateCandidate struct {
	ID        int64
	Domain    string
	Status    string
	CertPEM   string
	KeyPEM    string
	UpdatedAt float64
	// Leaf 是调用方预解析的证书（快照组选统一解析后传入，避免二次 X509KeyPair
	// 解析）；为空时 SelectCertificate 自行解析。
	Leaf *x509.Certificate
}

type CertificateSelection struct {
	Candidate   CertificateCandidate
	Certificate *x509.Certificate
}

// ParseCertificateLeaf 解析候选证书为 Leaf。tls.X509KeyPair 会同时校验
// 证书/私钥配对并解析私钥——是候选筛选里最贵的步骤；批量装载阶段（渲染、
// 配置巡检、证书信息查询）统一预解析一次并填入 CertificateCandidate.Leaf，
// SelectCertificate 走已解析快路径，避免同一候选在「选择 + 过期回退」等多
// 次调用间重复解析（与 cluster_snapshot 的同口径做法一致）。
// 解析失败返回 nil，语义等同未预解析：候选仍由 SelectCertificate 按不可解析
// 跳过（disabled 候选由调用方直接跳过预解析）。
func ParseCertificateLeaf(certPEM, keyPEM string) *x509.Certificate {
	pair, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return nil
	}
	if pair.Leaf != nil {
		return pair.Leaf
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil
	}
	return leaf
}

func SelectCertificate(candidates []CertificateCandidate, ruleDomains string, now time.Time) (CertificateSelection, bool) {
	canonicalDomains, err := CanonicalACMEDomains(ruleDomains)
	if err != nil {
		return CertificateSelection{}, false
	}
	domains := strings.Split(canonicalDomains, ",")
	var selected CertificateSelection
	selectedExact := false
	found := false
	for _, candidate := range candidates {
		if candidate.Status == "disabled" {
			continue
		}
		certificate := candidate.Leaf
		if certificate == nil {
			pair, err := tls.X509KeyPair([]byte(candidate.CertPEM), []byte(candidate.KeyPEM))
			if err != nil || len(pair.Certificate) == 0 {
				continue
			}
			certificate = pair.Leaf
			if certificate == nil {
				certificate, err = x509.ParseCertificate(pair.Certificate[0])
			}
			if err != nil {
				continue
			}
		}
		if now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
			continue
		}
		coversDomains := true
		for _, domain := range domains {
			if certificate.VerifyHostname(domain) != nil {
				coversDomains = false
				break
			}
		}
		if !coversDomains {
			continue
		}
		candidateCanonical, canonicalErr := CanonicalACMEDomains(candidate.Domain)
		candidateExact := canonicalErr == nil && candidateCanonical == canonicalDomains
		candidateSelection := CertificateSelection{Candidate: candidate, Certificate: certificate}
		if !found || betterCertificate(selected, candidateSelection, selectedExact, candidateExact) {
			selected = candidateSelection
			selectedExact = candidateExact
			found = true
		}
	}
	return selected, found
}

// betterCertificate 返回 candidate 是否优于 selected：NotAfter 越晚（剩余有效期
// 越长）越优先，避免把快照到期更近的证书推给从节点；相同时精确域名匹配优先于
// 覆盖匹配，再按 updated_at、id 倒序决胜。
func betterCertificate(selected, candidate CertificateSelection, selectedExact, candidateExact bool) bool {
	if !candidate.Certificate.NotAfter.Equal(selected.Certificate.NotAfter) {
		return candidate.Certificate.NotAfter.After(selected.Certificate.NotAfter)
	}
	if candidateExact != selectedExact {
		return candidateExact
	}
	if candidate.Candidate.UpdatedAt != selected.Candidate.UpdatedAt {
		return candidate.Candidate.UpdatedAt > selected.Candidate.UpdatedAt
	}
	return candidate.Candidate.ID > selected.Candidate.ID
}
