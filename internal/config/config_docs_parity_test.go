package config

// 部署文档与启动断言的一致性：JWT_SECRET 的强度门槛（长度 + 熵下限）与
// 「弱密钥只告警不阻断」的裁定必须同时出现在运维可见的部署文档里——否则
// 按文档设置短密钥能正常启动，而这条 fail-visible 信号只留在启动日志中。

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestDeploymentDocs_documentJWTSecretStrengthThreshold(t *testing.T) {
	source, err := os.ReadFile("../../docs/deployment.zh-CN.md")
	if err != nil {
		t.Fatalf("read docs/deployment.zh-CN.md: %v", err)
	}
	var row string
	for _, line := range strings.Split(string(source), "\n") {
		if strings.Contains(line, "`JWT_SECRET`") {
			row = line
			break
		}
	}
	if row == "" {
		t.Fatal("docs/deployment.zh-CN.md 缺 JWT_SECRET 环境变量行")
	}
	for _, want := range []string{
		fmt.Sprintf("≥%d 字节", minJWTSecretBytes),
		fmt.Sprintf("%d 个不同字节", minJWTSecretDistinctBytes),
		"强度不足",
		"不阻断启动",
	} {
		if !strings.Contains(row, want) {
			t.Errorf("JWT_SECRET 文档行缺少 %q: %s", want, row)
		}
	}
}
