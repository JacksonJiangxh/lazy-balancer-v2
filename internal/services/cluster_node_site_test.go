package services

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/models"
)

func TestNodes_fallsBackToMasterSiteForUnconfiguredNodes(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET server_map_lat=35.19, server_map_lon=108.87 WHERE id=1`); err != nil {
		t.Fatalf("seed master site: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved,server_map_lat,server_map_lon) VALUES
		(2,'edge-a','slave','10.0.0.2',8000,1,0,0),
		(3,'edge-b','slave','10.0.0.3',8000,1,40.19,116.42)`); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}
	nodes, err := service.Nodes(context.Background(), time.Now())
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	byID := map[int]models.ClusterNodeView{}
	for _, node := range nodes {
		byID[node.ID] = node
	}
	if got := byID[2]; got.ServerMapLat != 35.19 || got.ServerMapLon != 108.87 || !got.SiteInherited {
		t.Fatalf("node 2=%+v, want inherited master site 35.19/108.87", got)
	}
	if got := byID[3]; got.ServerMapLat != 40.19 || got.ServerMapLon != 116.42 || got.SiteInherited {
		t.Fatalf("node 3=%+v, want own site without inherited flag", got)
	}
}

func TestSnapshot_carriesPerNodeSiteCoordinates(t *testing.T) {
	service, database := newClusterTestService(t)
	if _, err := database.Exec(`UPDATE global_config SET server_map_lat=35.19, server_map_lon=108.87 WHERE id=1`); err != nil {
		t.Fatalf("seed master site: %v", err)
	}
	if _, err := database.Exec(`INSERT INTO nodes (id,name,mode,ip_address,port,is_approved,server_map_lat,server_map_lon) VALUES
		(2,'edge-a','slave','10.0.0.2',8000,1,0,0),
		(3,'edge-b','slave','10.0.0.3',8000,1,40.19,116.42)`); err != nil {
		t.Fatalf("seed nodes: %v", err)
	}

	snapshot, err := service.clusterSnapshotBypassingCache(context.Background())
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	if got := snapshot.NodeSites[2]; got.ServerMapLat != 35.19 || got.ServerMapLon != 108.87 {
		t.Fatalf("node 2 site=%+v, want inherited master 35.19/108.87", got)
	}
	if got := snapshot.NodeSites[3]; got.ServerMapLat != 40.19 || got.ServerMapLon != 116.42 {
		t.Fatalf("node 3 site=%+v, want 40.19/116.42", got)
	}
}

func TestApplySnapshot_appliesOnlyOwnNodeSiteCoordinates(t *testing.T) {
	_, database := newClusterTestService(t)
	caddyServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.WriteHeader(http.StatusOK)
	}))
	defer caddyServer.Close()
	if _, err := database.Exec(`UPDATE global_config SET is_master=0, registration_id=3, server_map_lat=99, server_map_lon=99, cluster_version=40 WHERE id=1`); err != nil {
		t.Fatalf("seed slave identity: %v", err)
	}
	syncService := NewSyncService(database, &config.Config{CaddyAdminURL: caddyServer.URL}, NewCaddyService(caddyServer.URL))

	snapshot := models.ClusterSnapshot{
		Version: 41,
		NodeSites: map[int]models.ClusterNodeSite{
			2: {ServerMapLat: 31.23, ServerMapLon: 121.47},
			3: {ServerMapLat: 40.19, ServerMapLon: 116.42},
		},
	}
	snapshot.SectionHashes = ComputeSnapshotSectionHashes(&snapshot)
	if err := syncService.applySnapshot(context.Background(), snapshot); err != nil {
		t.Fatalf("apply: %v", err)
	}

	var lat, lon float64
	if err := database.QueryRow(`SELECT server_map_lat, server_map_lon FROM global_config WHERE id=1`).Scan(&lat, &lon); err != nil {
		t.Fatalf("read local site: %v", err)
	}
	if lat != 40.19 || lon != 116.42 {
		t.Fatalf("local site=(%v,%v), want node 3 coords (40.19,116.42)", lat, lon)
	}
}
