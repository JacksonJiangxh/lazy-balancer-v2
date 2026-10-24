package services

import "testing"

// loadCertJobDeploymentState 是「部署生命周期 + 材料」四类判定的唯一读取口
// （补偿重排队 / CA provider 不可用降级 / 生命周期取消重排队 / 失败终态降级）：
// 状态与材料形态必须同源，空白 PEM 与非空 PEM 的结论必须一致（trim 口径），
// 行不存在与读故障由调用方决定语义（found=false / err）。
func TestLoadCertJobDeploymentState_reportsMaterialAndMissingRow(t *testing.T) {
	_, database := newClusterTestService(t)
	insert := func(domain, status, certPEM, keyPEM string) int {
		t.Helper()
		result, err := database.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem)
			VALUES ('lb_state',?,?,?,?)`, domain, status, certPEM, keyPEM)
		if err != nil {
			t.Fatalf("seed cert job: %v", err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatalf("read cert job id: %v", err)
		}
		return int(id)
	}
	withMaterial := insert("state.example.test", "downloaded", "CERT-PEM", "KEY-PEM")
	blankPEM := insert("blank.example.test", "downloaded", "   ", "KEY-PEM")

	status, hasMaterial, found, err := loadCertJobDeploymentState(withMaterial)
	if err != nil || !found || status != "downloaded" || !hasMaterial {
		t.Fatalf("withMaterial: status=%q hasMaterial=%v found=%v err=%v", status, hasMaterial, found, err)
	}
	if _, hasMaterial, found, err = loadCertJobDeploymentState(blankPEM); err != nil || !found || hasMaterial {
		t.Fatalf("blank PEM: hasMaterial=%v found=%v err=%v, want 无材料", hasMaterial, found, err)
	}
	if _, _, found, err = loadCertJobDeploymentState(withMaterial + 1000); err != nil || found {
		t.Fatalf("missing row: found=%v err=%v, want found=false 且无错误", found, err)
	}
}
