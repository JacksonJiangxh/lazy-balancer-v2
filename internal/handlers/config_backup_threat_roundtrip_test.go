package handlers

// RDB 文件化 lbbak 往返（v2.3.4）：威胁库 .iplist 源文件随「规则库数据库」
// 分区导出、导入时落盘并编译 .fast。

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// Given：bundle 含威胁 .fast + waf 目录含 .iplist 源文件。
// When：buildLbbakPayload → parseLbbak 往返。
// Then：threat/*.iplist 条目在包内、校验和一致、解析回 ThreatIplists 映射。
func TestLbbakThreatRoundtrip_exportImport(t *testing.T) {
	wafDir := t.TempDir()
	restoreWaf := services.OverrideThreatWafDirForTest(wafDir)
	defer restoreWaf()

	iplistContent := []byte("192.0.2.0/24\n198.51.100.7\n")
	if err := os.WriteFile(filepath.Join(wafDir, "threat-ustc.iplist"), iplistContent, 0644); err != nil {
		t.Fatal(err)
	}
	fastSum := sha256.Sum256([]byte("fake-fast-bytes"))

	bundle := &services.WafFileBundle{
		ThreatFiles: []models.ThreatFileEntry{{Name: "ustc", Sha256: hex.EncodeToString(fastSum[:]), Content: []byte("fake-fast-bytes")}},
	}
	payload, err := buildLbbakPayload([]byte(`{"meta":{"app":"lazy-balancer-v2"}}`), bundle)
	if err != nil {
		t.Fatalf("buildLbbakPayload: %v", err)
	}

	parsed, err := parseLbbak(payload)
	if err != nil {
		t.Fatalf("parseLbbak: %v", err)
	}
	got, ok := parsed.ThreatIplists["ustc"]
	if !ok {
		t.Fatalf("ThreatIplists 必须含 ustc; got %#v", parsed.ThreatIplists)
	}
	if !bytes.Equal(got, iplistContent) {
		t.Fatalf("iplist 内容往返不一致: %q", got)
	}
}

// Given：空 bundle（无威胁文件）。
// Then：ThreatIplists 为空映射（不 panic、不误报）。
func TestLbbakThreatRoundtrip_noThreatFiles(t *testing.T) {
	payload, err := buildLbbakPayload([]byte(`{}`), nil)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parseLbbak(payload)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.ThreatIplists) != 0 {
		t.Fatalf("无威胁文件时 ThreatIplists 必须为空, got %#v", parsed.ThreatIplists)
	}
}
