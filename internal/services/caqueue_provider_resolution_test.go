package services

import "testing"

// 「跟随默认 CA」（规则 ca_provider_id=0）的语义收敛：任务行不得固化默认的快照，
// 每次入队都按当前默认解析。否则管理员切换默认并禁用旧 provider 后，该规则的
// 续期/重试按固化 id 命中「显式选择但已禁用」硬错误，自动续签链终止而 UI 仍显示
// 「跟随默认」。
func TestCAQueueManager_followDefaultRuleResolvesCurrentDefault(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'old default','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (8,'new default','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE global_config SET default_ca_provider_id=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,ca_provider_id) VALUES ('lb_follow','lb_follow','example.com','http',8443,1,1,'acme_dns',0)`); err != nil {
		t.Fatal(err)
	}
	// 旧版本固化形态：跟随默认规则的任务行被写成当时的默认 id(7)。
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (71,'lb_follow','example.com','queued',7)`); err != nil {
		t.Fatal(err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}

	// 切换默认到 8 并禁用旧 provider 7——此时没有任何规则显式引用 7。
	if _, err := database.Exec(`UPDATE global_config SET default_ca_provider_id=8 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`UPDATE ca_providers SET enabled=0 WHERE id=7`); err != nil {
		t.Fatal(err)
	}

	if _, err := manager.requeueStrandedQueuedJobs(); err != nil {
		t.Fatalf("requeue stranded queued jobs: %v", err)
	}
	defer manager.Stop()

	// Then 1：任务行归一为 0（不再固化默认派生 id）。
	var pinned int
	if err := database.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM cert_jobs WHERE id=71").Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if pinned != 0 {
		t.Fatalf("cert_jobs.ca_provider_id=%d, want 0（跟随默认不得固化默认快照）", pinned)
	}
	// Then 2：入队落到当前默认 provider(8)。
	manager.mu.Lock()
	queue := manager.queues[8]
	manager.mu.Unlock()
	if queue == nil {
		t.Fatal("job 未落到当前默认 provider 8 的队列（跟随默认规则被固化 id 绑架）")
	}
	queue.mu.Lock()
	_, enqueued := queue.active[71]
	queue.mu.Unlock()
	if !enqueued {
		t.Fatal("follow-default job 71 was not enqueued onto the current default provider")
	}
}

// 显式选择（ca_provider_id≠0）保持固化语义：解析结果写回任务行，续期沿用同一
// provider（默认切换不影响显式选择）。
func TestCAQueueManager_explicitRuleProviderStillPinned(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO ca_providers (id,name,provider,directory_url,enabled) VALUES (7,'explicit','letsencrypt','https://invalid.example/directory',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,ca_provider_id) VALUES ('lb_explicit','lb_explicit','explicit.example.com','http',8444,1,1,'acme_dns',7)`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status,ca_provider_id) VALUES (72,'lb_explicit','explicit.example.com','queued',7)`); err != nil {
		t.Fatal(err)
	}
	manager := &CAQueueManager{queues: make(map[int]*caQueue), active: true}
	if _, err := manager.requeueStrandedQueuedJobs(); err != nil {
		t.Fatalf("requeue stranded queued jobs: %v", err)
	}
	defer manager.Stop()

	var pinned int
	if err := database.QueryRow("SELECT COALESCE(ca_provider_id,0) FROM cert_jobs WHERE id=72").Scan(&pinned); err != nil {
		t.Fatal(err)
	}
	if pinned != 7 {
		t.Fatalf("cert_jobs.ca_provider_id=%d, want 7（显式选择必须固化，跟随默认归一不得改写）", pinned)
	}
	manager.mu.Lock()
	queue := manager.queues[7]
	manager.mu.Unlock()
	if queue == nil {
		t.Fatal("显式选择的任务未落到其 provider 7 的队列")
	}
}
