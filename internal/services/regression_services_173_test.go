package services

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDoWithSameHostTLSUpgradeRedirect_replaysSupportedStatusMatrix(t *testing.T) {
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			// Given a plaintext listener redirecting to the same hostname over HTTPS.
			received := make(chan string, 1)
			tlsMaster := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost {
					t.Errorf("method=%q, want POST preserved", r.Method)
				}
				body, _ := io.ReadAll(r.Body)
				if string(body) != "payload" || r.URL.RawQuery != "x=1" {
					t.Errorf("replayed body/query=%q/%q, want payload/x=1", body, r.URL.RawQuery)
				}
				received <- r.Header.Get("X-Cluster-Token")
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(tlsMaster.Close)
			plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tlsMaster.URL+r.URL.Path, status)
			}))
			t.Cleanup(plaintext.Close)
			client := tlsMaster.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			req, err := http.NewRequest(http.MethodPost, plaintext.URL+"/report?x=1", bytes.NewReader([]byte("payload")))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Cluster-Token", "cluster-secret")

			// When the shared helper handles the upgrade status.
			resp, err := DoWithSameHostTLSUpgradeRedirect(client, req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			// Then every supported status replays with method/body/query/credentials.
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status=%d, want replayed 200 for redirect %d", resp.StatusCode, status)
			}
			select {
			case token := <-received:
				if token != "cluster-secret" {
					t.Fatalf("token=%q, want cluster-secret", token)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("redirect target never received request")
			}
		})
	}
}

// 同契约——旧主节点启用管理 HTTPS 后明文端口整体 301，脱离通知必须对
// 「同主机名 + 升级为 https」的 Location 按原方法重放一次，否则主节点永远
// 收不到 detached 上报、节点行与令牌不撤销。
func TestNotifyMasterDetach_followsSameHostTLSUpgradeRedirect(t *testing.T) {
	// Given an old master whose plaintext port 301s to its HTTPS port (same hostname)
	received := make(chan string, 1)
	tlsMaster := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method=%q, want POST preserved across redirect", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"detached":true`) {
			t.Errorf("body=%s, want detached report", body)
		}
		received <- r.Header.Get("X-Cluster-Token")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tlsMaster.Close)
	pin := sha256.Sum256(tlsMaster.Certificate().Raw)
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, tlsMaster.URL+r.URL.Path, http.StatusMovedPermanently)
	}))
	t.Cleanup(plaintext.Close)

	// When the detach notification is sent to the plaintext address
	notifyMasterDetach(context.Background(), plaintext.URL, "cluster-secret", hex.EncodeToString(pin[:]))

	// Then the report is replayed over https with the cluster token header preserved
	select {
	case token := <-received:
		if token != "cluster-secret" {
			t.Fatalf("token=%q, want cluster-secret", token)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("redirect target never received the detach report")
	}
}

// TestSyncService_do_doesNotFollowHTTPRedirectOrForwardCredentials 同契约）。
func TestNotifyMasterDetach_doesNotFollowCrossHostRedirect(t *testing.T) {
	// Given a redirect to the same listener but under a different hostname
	received := make(chan struct{}, 1)
	tlsMaster := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(tlsMaster.Close)
	pin := sha256.Sum256(tlsMaster.Certificate().Raw)
	crossHost := strings.Replace(tlsMaster.URL, "127.0.0.1", "localhost", 1)
	plaintext := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, crossHost+r.URL.Path, http.StatusMovedPermanently)
	}))
	t.Cleanup(plaintext.Close)

	// When the detach notification is sent
	notifyMasterDetach(context.Background(), plaintext.URL, "cluster-secret", hex.EncodeToString(pin[:]))

	// Then the redirect is not followed (no request reaches the target)
	select {
	case <-received:
		t.Fatal("cross-host redirect must not be followed（凭证外泄防护）")
	case <-time.After(300 * time.Millisecond):
	}
}
