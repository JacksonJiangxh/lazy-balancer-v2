package caddygeoip

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTrafficLease_enableRelease(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	if trafficCollectorActive() {
		t.Fatal("collector should start disabled after explicit reset")
	}
	if err := acquireTrafficLease("screen-1", time.Minute, 1); err != nil {
		t.Fatal(err)
	}
	if !trafficCollectorActive() {
		t.Fatal("collector should be enabled after lease")
	}
	releaseTrafficLease("screen-1")
	if trafficCollectorActive() {
		t.Fatal("collector should be disabled after last lease release")
	}
}

func TestTrafficCollectorAdmin_postGetDelete(t *testing.T) {
	resetTrafficState(t)
	trafficCollectorEnabled.Store(false)

	body := bytes.NewBufferString(`{"lease_id":"tab-1","ttl_ms":30000}`)
	rec := httptest.NewRecorder()
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodPost, "/lb/traffic-collector", body)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || !trafficCollectorActive() {
		t.Fatalf("post status=%d enabled=%v", rec.Code, trafficCollectorActive())
	}

	rec = httptest.NewRecorder()
	if err := serveTrafficCollector(rec, httptest.NewRequest(http.MethodDelete, "/lb/traffic-collector?lease_id=tab-1", nil)); err != nil {
		t.Fatal(err)
	}
	if trafficCollectorActive() {
		t.Fatal("collector should be disabled after DELETE")
	}
}
