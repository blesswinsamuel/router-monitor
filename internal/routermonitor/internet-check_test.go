package routermonitor

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type mockOutageStore struct {
	mu      sync.Mutex
	outages []mockOutage
	nextID  int64
}

type mockOutage struct {
	id     int64
	status string
	reason string
	start  time.Time
	end    time.Time
}

func (m *mockOutageStore) RecordOutageStart(status, reason string, startTime time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextID++
	m.outages = append(m.outages, mockOutage{
		id:     m.nextID,
		status: status,
		reason: reason,
		start:  startTime,
	})
	return m.nextID, nil
}

func (m *mockOutageStore) RecordOutageEnd(id int64, endTime time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range m.outages {
		if m.outages[i].id == id {
			m.outages[i].end = endTime
			return nil
		}
	}
	return nil
}

func TestParseTargetConfigs(t *testing.T) {
	// 1. Empty string defaults
	cfgs, err := ParseTargetConfigs("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 5 {
		t.Fatalf("expected 5 default targets, got %d", len(cfgs))
	}

	// 2. Custom string parsing
	raw := "icmp:1.0.0.1,dns:google.com@8.8.8.8,http:http://example.com/204,tcp:127.0.0.1:8080"
	cfgs, err = ParseTargetConfigs(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfgs) != 4 {
		t.Fatalf("expected 4 targets, got %d", len(cfgs))
	}

	if cfgs[0].Type != ProbeICMP || cfgs[0].Target != "1.0.0.1" {
		t.Errorf("expected icmp 1.0.0.1, got %+v", cfgs[0])
	}
	if cfgs[1].Type != ProbeDNS || cfgs[1].Target != "google.com@8.8.8.8" || cfgs[1].Name != "DNS (google.com via 8.8.8.8)" {
		t.Errorf("expected dns google.com@8.8.8.8, got %+v", cfgs[1])
	}
	if cfgs[2].Type != ProbeHTTP || cfgs[2].Target != "http://example.com/204" {
		t.Errorf("expected http example.com, got %+v", cfgs[2])
	}
	if cfgs[3].Type != ProbeTCP || cfgs[3].Target != "127.0.0.1:8080" {
		t.Errorf("expected tcp 127.0.0.1:8080, got %+v", cfgs[3])
	}
}

func TestProbeDNS_CustomServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	res := probeDNS(ctx, "cloudflare.com@1.1.1.1:53", 2*time.Second)
	if res.IsUp && res.Latency <= 0 {
		t.Errorf("expected positive latency on successful DNS probe, got %v", res.Latency)
	}
}

func TestInternetChecker_StateTransitionsAndOutagePersistence(t *testing.T) {
	store := &mockOutageStore{}

	targets := []TargetConfig{
		{Name: "Target 1", Target: "127.0.0.1:9", Type: ProbeTCP}, // unreachable echo port
	}

	checker := NewInternetChecker(1*time.Second, targets, store)
	reg := prometheus.NewRegistry()
	checker.Register(reg)

	var receivedSamples []MetricSample
	checker.SetSampleSink(func(samples []MetricSample) {
		receivedSamples = append(receivedSamples, samples...)
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Run single check
	checker.CheckOnce(ctx)

	health := checker.GetOverallHealth()
	if health.IsUp {
		t.Errorf("expected unreachable target to result in down health, got %+v", health)
	}
	if health.Status != "down" {
		t.Errorf("expected down status, got %s", health.Status)
	}

	// Verify outage is recorded
	store.mu.Lock()
	if len(store.outages) != 1 {
		t.Fatalf("expected 1 outage recorded, got %d", len(store.outages))
	}
	if store.outages[0].status != "down" {
		t.Errorf("expected down status in outage record, got %s", store.outages[0].status)
	}
	store.mu.Unlock()

	// Verify sample sink received metrics
	if len(receivedSamples) == 0 {
		t.Errorf("expected metric samples to be emitted to sink")
	}
}
