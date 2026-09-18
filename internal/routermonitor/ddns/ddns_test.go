package ddns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/blesswinsamuel/router-monitor/internal/tsdb"
)

func TestDetector_ExternalEndpoints(t *testing.T) {
	// Mock IPv4 server
	tsV4 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("198.51.100.42\n"))
	}))
	defer tsV4.Close()

	// Mock IPv6 server (simulating Cloudflare cdn-cgi/trace format)
	tsV6 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("fl=123\nip=2001:db8::cafe\nts=12345\n"))
	}))
	defer tsV6.Close()

	detector := NewDetector(DetectorConfig{
		IPv4Endpoints: []string{tsV4.URL},
		IPv6Endpoints: []string{tsV6.URL},
	})

	ctx := context.Background()
	pair, err := detector.DetectIPs(ctx, true, true)
	if err != nil {
		t.Fatalf("DetectIPs failed: %v", err)
	}

	if pair.IPv4 != "198.51.100.42" {
		t.Errorf("expected IPv4 198.51.100.42, got %s", pair.IPv4)
	}
	if pair.IPv6 != "2001:db8::cafe" {
		t.Errorf("expected IPv6 2001:db8::cafe, got %s", pair.IPv6)
	}
}

func TestDetector_Fallback(t *testing.T) {
	// First server fails
	tsFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer tsFail.Close()

	// Second server succeeds
	tsOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("203.0.113.10"))
	}))
	defer tsOK.Close()

	detector := NewDetector(DetectorConfig{
		IPv4Endpoints: []string{tsFail.URL, tsOK.URL},
	})

	pair, err := detector.DetectIPs(context.Background(), true, false)
	if err != nil {
		t.Fatalf("DetectIPs fallback failed: %v", err)
	}
	if pair.IPv4 != "203.0.113.10" {
		t.Errorf("expected 203.0.113.10, got %s", pair.IPv4)
	}
}

func TestDuckDNSProvider(t *testing.T) {
	var requestedURL string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedURL = r.URL.String()
		_, _ = w.Write([]byte("OK"))
	}))
	defer ts.Close()

	provider, err := NewDuckDNSProvider(DuckDNSConfig{
		Token:   "secret-token",
		BaseURL: ts.URL,
	})
	if err != nil {
		t.Fatalf("NewDuckDNSProvider failed: %v", err)
	}

	res, err := provider.Update(context.Background(), UpdateRequest{
		Domains: []string{"testdomain.duckdns.org"},
		IPv4:    "198.51.100.5",
		IPv6:    "2001:db8::1",
	})
	if err != nil {
		t.Fatalf("DuckDNS Update failed: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success result")
	}

	if !strings.Contains(requestedURL, "domains=testdomain") {
		t.Errorf("expected domains=testdomain in URL, got %s", requestedURL)
	}
	if !strings.Contains(requestedURL, "token=secret-token") {
		t.Errorf("expected token in URL, got %s", requestedURL)
	}
	if !strings.Contains(requestedURL, "ip=198.51.100.5") {
		t.Errorf("expected ip in URL, got %s", requestedURL)
	}
	if !strings.Contains(requestedURL, "ipv6=2001%3Adb8%3A%3A1") {
		t.Errorf("expected ipv6 in URL, got %s", requestedURL)
	}
}

func TestGenericProvider(t *testing.T) {
	var requestedPath string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path + "?" + r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("good"))
	}))
	defer ts.Close()

	provider, err := NewGenericProvider(GenericConfig{
		URLTemplate: ts.URL + "/update?host={domain}&ip={ipv4}",
	})
	if err != nil {
		t.Fatalf("NewGenericProvider failed: %v", err)
	}

	res, err := provider.Update(context.Background(), UpdateRequest{
		Domains: []string{"home.example.com"},
		IPv4:    "198.51.100.99",
	})
	if err != nil {
		t.Fatalf("Generic update failed: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success")
	}
	if !strings.Contains(requestedPath, "host=home.example.com&ip=198.51.100.99") {
		t.Errorf("unexpected path: %s", requestedPath)
	}
}

func TestCloudflareProvider(t *testing.T) {
	var patchedRecord, createdRecord bool

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header
		if r.Header.Get("Authorization") != "Bearer test-cf-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/zones" {
			_ = json.NewEncoder(w).Encode(cfZonesResponse{
				Success: true,
				Result: []cfZone{
					{ID: "zone123", Name: "example.com"},
				},
			})
			return
		}

		if r.Method == http.MethodGet && r.URL.Path == "/zones/zone123/dns_records" {
			// Existing A record with old IP
			_ = json.NewEncoder(w).Encode(cfRecordsResponse{
				Success: true,
				Result: []cfRecord{
					{
						ID:      "rec1",
						Type:    "A",
						Name:    "router.example.com",
						Content: "198.51.100.1",
						Proxied: false,
					},
				},
			})
			return
		}

		if r.Method == http.MethodPatch && r.URL.Path == "/zones/zone123/dns_records/rec1" {
			patchedRecord = true
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["content"] != "198.51.100.2" {
				t.Errorf("expected patch content 198.51.100.2, got %v", body["content"])
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
			return
		}

		if r.Method == http.MethodPost && r.URL.Path == "/zones/zone123/dns_records" {
			createdRecord = true
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["type"] != "AAAA" || body["content"] != "2001:db8::10" {
				t.Errorf("unexpected post body: %v", body)
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"success": true}`))
			return
		}

		http.NotFound(w, r)
	}))
	defer ts.Close()

	cf, err := NewCloudflareProvider(CloudflareConfig{
		APIToken: "test-cf-token",
		BaseURL:  ts.URL,
	})
	if err != nil {
		t.Fatalf("NewCloudflareProvider failed: %v", err)
	}

	res, err := cf.Update(context.Background(), UpdateRequest{
		Domains: []string{"router.example.com"},
		IPv4:    "198.51.100.2",
		IPv6:    "2001:db8::10",
	})
	if err != nil {
		t.Fatalf("Cloudflare Update failed: %v", err)
	}
	if !res.Success {
		t.Errorf("expected success")
	}
	if !patchedRecord {
		t.Errorf("expected A record to be PATCHed")
	}
	if !createdRecord {
		t.Errorf("expected AAAA record to be POSTed")
	}
}

type mockDetector struct {
	pair IPPair
}

func (m *mockDetector) DetectIPs(ctx context.Context, checkIPv4, checkIPv6 bool) (IPPair, error) {
	return m.pair, nil
}

type mockProvider struct {
	updateCount int32
}

func (p *mockProvider) Name() string { return "mock" }
func (p *mockProvider) Update(ctx context.Context, req UpdateRequest) (*UpdateResult, error) {
	atomic.AddInt32(&p.updateCount, 1)
	return &UpdateResult{
		UpdatedRecords: len(req.Domains),
		Message:        "updated",
		Success:        true,
	}, nil
}

func TestManager_DeduplicationAndForce(t *testing.T) {
	detector := &mockDetector{
		pair: IPPair{IPv4: "198.51.100.1"},
	}
	provider := &mockProvider{}

	db, err := tsdb.Open(":memory:")
	if err != nil {
		t.Fatalf("Open TSDB failed: %v", err)
	}
	defer db.Close()

	mgr := NewManager(ManagerConfig{
		Enabled:   true,
		Provider:  provider,
		Detector:  detector,
		Domains:   []string{"test.example.com"},
		Interval:  1 * time.Minute,
		CheckIPv4: true,
		Store:     db,
	})

	ctx := context.Background()

	// 1st sync: should call provider
	res, err := mgr.Sync(ctx, false)
	if err != nil {
		t.Fatalf("1st sync failed: %v", err)
	}
	if !res.Success {
		t.Errorf("expected 1st sync success")
	}
	if atomic.LoadInt32(&provider.updateCount) != 1 {
		t.Errorf("expected 1 update call, got %d", provider.updateCount)
	}

	// 2nd sync with same IP: should skip provider call
	res, err = mgr.Sync(ctx, false)
	if err != nil {
		t.Fatalf("2nd sync failed: %v", err)
	}
	if atomic.LoadInt32(&provider.updateCount) != 1 {
		t.Errorf("expected still 1 update call, got %d", provider.updateCount)
	}

	// 3rd sync: force=true: should call provider
	res, err = mgr.Sync(ctx, true)
	if err != nil {
		t.Fatalf("3rd sync (force) failed: %v", err)
	}
	if atomic.LoadInt32(&provider.updateCount) != 2 {
		t.Errorf("expected 2 update calls after force, got %d", provider.updateCount)
	}

	// 4th sync: IP changed: should call provider
	detector.pair.IPv4 = "198.51.100.2"
	res, err = mgr.Sync(ctx, false)
	if err != nil {
		t.Fatalf("4th sync (IP change) failed: %v", err)
	}
	if atomic.LoadInt32(&provider.updateCount) != 3 {
		t.Errorf("expected 3 update calls after IP change, got %d", provider.updateCount)
	}

	// Check status
	status, err := mgr.GetStatus(ctx)
	if err != nil {
		t.Fatalf("GetStatus failed: %v", err)
	}
	if status.CurrentIPv4 != "198.51.100.2" {
		t.Errorf("expected current IPv4 198.51.100.2, got %s", status.CurrentIPv4)
	}
	if status.LastSyncStatus != "success" {
		t.Errorf("expected status success, got %s", status.LastSyncStatus)
	}
	if len(status.History) < 3 {
		t.Errorf("expected at least 3 history items, got %d", len(status.History))
	}
}
