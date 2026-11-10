package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

func TestRegistrationStatus_DemotionDoesNotDeliverUnpersistedToken(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	registerToken, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatalf("generate register token: %v", err)
	}
	registration, err := service.RegisterNode(context.Background(), models.ClusterRegisterRequest{
		Token: registerToken, Name: "slave-race", IPAddress: "10.0.0.31", Port: 8000,
	}, "10.0.0.31", now)
	if err != nil {
		t.Fatalf("register node: %v", err)
	}
	if err := service.ApproveNode(context.Background(), registration.RegistrationID, time.Now()); err != nil {
		t.Fatalf("approve node: %v", err)
	}

	// 交错形状：HTTP 主节点门通过后、状态事务的令牌 UPDATE 前完成降级。
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	response, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret, now)
	if !errors.Is(err, ErrNotMasterNode) {
		t.Fatalf("registration status after demotion error=%v response=%#v, want ErrNotMasterNode", err, response)
	}
	if response.ClusterToken != "" {
		t.Fatalf("demoted node delivered an unpersisted cluster token: %q", response.ClusterToken)
	}
	var storedHash string
	if err := database.QueryRow(`SELECT COALESCE(cluster_token_hash,'') FROM nodes WHERE id=?`, registration.RegistrationID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != "" {
		t.Fatalf("demotion race unexpectedly persisted token hash %q", storedHash)
	}

	// 回归形状：恢复主节点后可重发同一确定性令牌，且 hash 真实落库。
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	response, err = service.RegistrationStatus(context.Background(), registration.RegistrationID, registration.RegistrationSecret, now)
	if err != nil || response.Status != "approved" || response.ClusterToken == "" {
		t.Fatalf("master registration status response=%#v err=%v", response, err)
	}
	if err := database.QueryRow(`SELECT COALESCE(cluster_token_hash,'') FROM nodes WHERE id=?`, registration.RegistrationID).Scan(&storedHash); err != nil {
		t.Fatal(err)
	}
	if storedHash != tokenHash(response.ClusterToken) {
		t.Fatalf("persisted token hash=%q, want hash of delivered token", storedHash)
	}

	// 畸形形状：角色守卫不改变无效 registration secret 的认证拒绝语义。
	if _, err := service.RegistrationStatus(context.Background(), registration.RegistrationID, "wrong-secret", now); !errors.Is(err, ErrInvalidClusterAuth) {
		t.Fatalf("invalid registration secret error=%v, want ErrInvalidClusterAuth", err)
	}
}

func TestGenerateRegisterToken_DemotionDuringGenerationDoesNotIssueToken(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	if _, _, err := service.GenerateRegisterToken(context.Background(), 1, now); err != nil {
		t.Fatal(err)
	}
	// 真实 SQLite 交错：旧令牌清理提交后、新令牌 INSERT 前发生角色降级。
	if _, err := database.Exec(`CREATE TRIGGER demote_after_register_token_gc AFTER DELETE ON cluster_register_tokens BEGIN UPDATE global_config SET is_master=0 WHERE id=1; END`); err != nil {
		t.Fatal(err)
	}
	issuedAt := now.Add(time.Minute)
	token, _, err := service.GenerateRegisterToken(context.Background(), 1, issuedAt)
	if !errors.Is(err, ErrNotMasterNode) || token != "" {
		t.Fatalf("generation across demotion token=%q err=%v, want empty token + ErrNotMasterNode", token, err)
	}
	var newTokens int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_register_tokens WHERE created_at=?`, issuedAt).Scan(&newTokens); err != nil {
		t.Fatal(err)
	}
	if newTokens != 0 {
		t.Fatalf("demoted node persisted %d new registration tokens", newTokens)
	}
}

func TestGenerateRegisterToken_SlaveDoesNotCleanupOrIssue(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	oldToken, _, err := service.GenerateRegisterToken(context.Background(), 1, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if token, _, err := service.GenerateRegisterToken(context.Background(), 1, now.Add(time.Minute)); !errors.Is(err, ErrNotMasterNode) || token != "" {
		t.Fatalf("slave generation token=%q err=%v, want empty token + ErrNotMasterNode", token, err)
	}
	var oldTokens int
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_register_tokens WHERE token_hash=?`, tokenHash(oldToken)).Scan(&oldTokens); err != nil {
		t.Fatal(err)
	}
	if oldTokens != 1 {
		t.Fatalf("slave generation changed existing token bookkeeping: rows=%d, want 1", oldTokens)
	}
}

func TestGenerateLoginTicket_DemotionRejectsIssuance(t *testing.T) {
	service, database := newClusterTestService(t)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	clusterToken := "lb_cluster_login-ticket-role-race"
	key := sha256.Sum256([]byte(clusterToken))
	if _, err := database.Exec(`INSERT INTO nodes (id,name,ip_address,port,status,is_approved,cluster_token_hash,last_seen) VALUES (31,'slave-race','10.0.0.31',8000,'online',1,?,?)`, hex.EncodeToString(key[:]), now.Format("2006-01-02 15:04:05")); err != nil {
		t.Fatal(err)
	}
	claims := models.ClusterLoginTicketClaims{UserID: 3, Username: "alice", NodeID: 31}
	if _, err := database.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	response, err := service.GenerateLoginTicket(context.Background(), claims, now)
	if !errors.Is(err, ErrNotMasterNode) || response.Ticket != "" {
		t.Fatalf("slave login ticket response=%#v err=%v, want empty ticket + ErrNotMasterNode", response, err)
	}

	// 主节点与缺失节点形状保持既有成功/404 哨兵语义。
	if _, err := database.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if response, err = service.GenerateLoginTicket(context.Background(), claims, now); err != nil || response.Ticket == "" {
		t.Fatalf("master login ticket response=%#v err=%v", response, err)
	}
	claims.NodeID = 999
	if _, err := service.GenerateLoginTicket(context.Background(), claims, now); !errors.Is(err, ErrNodeNotFound) {
		t.Fatalf("missing login target error=%v, want ErrNodeNotFound", err)
	}
}

func TestPromote_MissingTopologyRowFailsInsteadOfReportingSuccess(t *testing.T) {
	service, database := newClusterTestService(t)
	StopTaskEngine()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url='', cluster_token='' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	// 初始角色/拓扑读取成功后，行在 UPDATE 临界区被并发删除；SQLite 真实
	// changes()=0，旧实现却 Commit 并返回成功。
	if _, err := database.Exec(`CREATE TRIGGER delete_topology_during_promote BEFORE UPDATE ON global_config WHEN NEW.is_master=1 BEGIN DELETE FROM global_config WHERE id=1; END`); err != nil {
		t.Fatal(err)
	}
	if err := service.Promote(context.Background()); err == nil {
		t.Fatal("Promote reported success although the topology UPDATE affected zero rows")
	}
}

func TestBecomeSlave_MissingTopologyRowFailsInsteadOfReportingSuccess(t *testing.T) {
	service, database := newClusterTestService(t)
	StopTaskEngine()
	if _, err := database.Exec(`CREATE TRIGGER delete_topology_during_demote BEFORE UPDATE ON global_config WHEN NEW.is_master=0 BEGIN DELETE FROM global_config WHERE id=1; END`); err != nil {
		t.Fatal(err)
	}
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 41, RegistrationSecret: "secret"}); err == nil {
		t.Fatal("BecomeSlave reported success although the topology UPDATE affected zero rows")
	}
}

func TestPromote_ResetsAppliedSyncBookkeeping(t *testing.T) {
	service, database := newClusterTestService(t)
	StopTaskEngine()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, master_url='', cluster_token='', applied_waf_ref_hash='stale-ref', applied_waf_ref_version=9 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section,hash,applied_version) VALUES ('rules','stale-section',9)`); err != nil {
		t.Fatal(err)
	}
	if err := service.Promote(context.Background()); err != nil {
		t.Fatalf("promote: %v", err)
	}
	assertAppliedSyncBookkeepingCleared(t, database)
}

func TestBecomeSlave_ResetsAppliedSyncBookkeeping(t *testing.T) {
	service, database := newClusterTestService(t)
	StopTaskEngine()
	if _, err := database.Exec(`UPDATE global_config SET applied_waf_ref_hash='stale-ref', applied_waf_ref_version=9 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cluster_applied_sections (section,hash,applied_version) VALUES ('rules','stale-section',9)`); err != nil {
		t.Fatal(err)
	}
	if err := service.BecomeSlave(context.Background(), "https://master.example", models.ClusterRegistration{RegistrationID: 42, RegistrationSecret: "secret"}); err != nil {
		t.Fatalf("become slave: %v", err)
	}
	assertAppliedSyncBookkeepingCleared(t, database)
}

func assertAppliedSyncBookkeepingCleared(t *testing.T, database *sql.DB) {
	t.Helper()
	var hash string
	var version, sections int
	if err := database.QueryRow(`SELECT COALESCE(applied_waf_ref_hash,''),COALESCE(applied_waf_ref_version,0) FROM global_config WHERE id=1`).Scan(&hash, &version); err != nil {
		t.Fatal(err)
	}
	if err := database.QueryRow(`SELECT COUNT(*) FROM cluster_applied_sections`).Scan(&sections); err != nil {
		t.Fatal(err)
	}
	if hash != "" || version != 0 || sections != 0 {
		t.Fatalf("stale applied bookkeeping: hash=%q version=%d sections=%d, want all cleared", hash, version, sections)
	}
}
