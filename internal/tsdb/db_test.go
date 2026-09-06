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

func TestTSDB_DevicePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "devices.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	t1 := time.Now().Add(-10 * time.Minute).Truncate(time.Second)
	t2 := time.Now().Truncate(time.Second)

	// 1. Initial upsert
	if err := db.UpsertDevice("aa:bb:cc:dd:ee:01", "10.100.1.10", "my-laptop", "lan", t1); err != nil {
		t.Fatalf("UpsertDevice failed: %v", err)
	}

	devs, err := db.GetPersistedDevices()
	if err != nil {
		t.Fatalf("GetPersistedDevices failed: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	if devs[0].Hostname != "my-laptop" || devs[0].HWAddr != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("unexpected device details: %+v", devs[0])
	}
	if !devs[0].FirstSeen.Equal(t1) || !devs[0].LastSeen.Equal(t1) {
		t.Fatalf("unexpected timestamps: first=%v, last=%v", devs[0].FirstSeen, devs[0].LastSeen)
	}

	// 2. Subsequent upsert with unknown hostname should retain existing known hostname
	if err := db.UpsertDevice("aa:bb:cc:dd:ee:01", "10.100.1.10", "unknown:10.100.1.10", "lan", t2); err != nil {
		t.Fatalf("UpsertDevice second call failed: %v", err)
	}

	devs, err = db.GetPersistedDevices()
	if err != nil {
		t.Fatalf("GetPersistedDevices failed: %v", err)
	}
	if len(devs) != 1 {
		t.Fatalf("expected 1 device, got %d", len(devs))
	}
	if devs[0].Hostname != "my-laptop" {
		t.Fatalf("expected hostname 'my-laptop' preserved, got %q", devs[0].Hostname)
	}
	if !devs[0].FirstSeen.Equal(t1) {
		t.Fatalf("first_seen should be preserved: got %v, want %v", devs[0].FirstSeen, t1)
	}
	if !devs[0].LastSeen.Equal(t2) {
		t.Fatalf("last_seen should be updated: got %v, want %v", devs[0].LastSeen, t2)
	}
}
