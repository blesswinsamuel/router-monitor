package tsdb

import (
	"path/filepath"
	"testing"
	"time"
)

func TestTSDB_InsertAndQuery(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	now := time.Now().Truncate(time.Second)
	samples := []Sample{
		{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now.Add(-20 * time.Second), Value: 1000},
		{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now.Add(-15 * time.Second), Value: 2000},
		{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now.Add(-10 * time.Second), Value: 3000},
		{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now.Add(-10 * time.Second), Value: 500},
		{Metric: "internet_latency_seconds", Labels: map[string]string{"target": "1.1.1.1:53"}, Timestamp: now.Add(-10 * time.Second), Value: 0.012},
	}

	if err := db.InsertSamples(samples); err != nil {
		t.Fatalf("InsertSamples failed: %v", err)
	}

	// Query ingress traffic
	results, err := db.QueryRange("traffic_bytes_rate", map[string]string{"direction": "ingress"}, now.Add(-30*time.Second), now, 5)
	if err != nil {
		t.Fatalf("QueryRange failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 series, got %d", len(results))
	}
	if len(results[0].Points) == 0 {
		t.Fatalf("expected points, got 0")
	}

	// Verify purge
	deleted, err := db.PurgeOlderThan(1 * time.Second)
	if err != nil {
		t.Fatalf("PurgeOlderThan failed: %v", err)
	}
	if deleted != 5 {
		t.Fatalf("expected 5 deleted samples, got %d", deleted)
	}
}
