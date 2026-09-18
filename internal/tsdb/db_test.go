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

	// Query multiple metrics using QueryRanges
	multiResults, err := db.QueryRanges([]TimeSeriesQuerySpec{
		{MetricName: "traffic_bytes_rate", MatchLabels: map[string]string{"direction": "ingress"}},
		{MetricName: "traffic_bytes_rate", MatchLabels: map[string]string{"direction": "egress"}},
		{MetricName: "internet_latency_seconds"},
	}, now.Add(-30*time.Second), now, 5)
	if err != nil {
		t.Fatalf("QueryRanges failed: %v", err)
	}
	if len(multiResults) != 3 {
		t.Fatalf("expected 3 series from batch QueryRanges, got %d", len(multiResults))
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

	// 2. Subsequent upsert with empty hostname should retain existing known hostname
	if err := db.UpsertDevice("aa:bb:cc:dd:ee:01", "10.100.1.10", "", "lan", t2); err != nil {
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

func TestTSDB_OutagePersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "outages.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	t1 := time.Now().Add(-5 * time.Minute).Truncate(time.Second)
	t2 := time.Now().Truncate(time.Second)

	id, err := db.RecordOutageStart("degraded", "High packet loss: 33%", t1)
	if err != nil {
		t.Fatalf("RecordOutageStart failed: %v", err)
	}
	if id <= 0 {
		t.Fatalf("expected positive id, got %d", id)
	}

	outages, err := db.GetRecentOutages(10)
	if err != nil {
		t.Fatalf("GetRecentOutages failed: %v", err)
	}
	if len(outages) != 1 {
		t.Fatalf("expected 1 outage, got %d", len(outages))
	}
	if outages[0].Status != "degraded" || outages[0].Reason != "High packet loss: 33%" {
		t.Fatalf("unexpected outage: %+v", outages[0])
	}
	if !outages[0].EndTime.IsZero() {
		t.Fatalf("expected end time zero for active outage")
	}

	// Resolve outage
	if err := db.RecordOutageEnd(id, t2); err != nil {
		t.Fatalf("RecordOutageEnd failed: %v", err)
	}

	outages, err = db.GetRecentOutages(10)
	if err != nil {
		t.Fatalf("GetRecentOutages failed: %v", err)
	}
	if len(outages) != 1 {
		t.Fatalf("expected 1 outage, got %d", len(outages))
	}
	if outages[0].DurationSeconds <= 0 {
		t.Fatalf("expected positive duration, got %v", outages[0].DurationSeconds)
	}
	if !outages[0].EndTime.Equal(t2) {
		t.Fatalf("expected end time %v, got %v", t2, outages[0].EndTime)
	}
}

func TestTSDB_DeviceAndOverviewUsage(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "usage.db")

	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()
	db.SetSampleInterval(15 * time.Second)

	now := time.Now().Truncate(time.Second)
	samples := []Sample{
		{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now.Add(-30 * time.Second), Value: 200},
		{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now.Add(-30 * time.Second), Value: 100},
		{Metric: "wan_traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now.Add(-30 * time.Second), Value: 150},
		{Metric: "wan_traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now.Add(-30 * time.Second), Value: 80},
		{Metric: "lan_traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now.Add(-30 * time.Second), Value: 50},
		{Metric: "lan_traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now.Add(-30 * time.Second), Value: 20},
		{Metric: "device_traffic_bytes_rate", Labels: map[string]string{"ip": "10.100.1.5", "direction": "ingress"}, Timestamp: now.Add(-30 * time.Second), Value: 200},
		{Metric: "device_traffic_bytes_rate", Labels: map[string]string{"ip": "10.100.1.5", "direction": "egress"}, Timestamp: now.Add(-30 * time.Second), Value: 100},
		{Metric: "device_wan_bytes_rate", Labels: map[string]string{"ip": "10.100.1.5", "direction": "ingress"}, Timestamp: now.Add(-30 * time.Second), Value: 150},
		{Metric: "device_wan_bytes_rate", Labels: map[string]string{"ip": "10.100.1.5", "direction": "egress"}, Timestamp: now.Add(-30 * time.Second), Value: 80},
		{Metric: "device_protocol_bytes_rate", Labels: map[string]string{"ip": "10.100.1.5", "protocol": "TCP", "direction": "ingress"}, Timestamp: now.Add(-30 * time.Second), Value: 120},
		{Metric: "device_peer_bytes_rate", Labels: map[string]string{"ip": "10.100.1.5", "peer_ip": "10.100.1.1", "direction": "ingress"}, Timestamp: now.Add(-30 * time.Second), Value: 50},
	}

	if err := db.InsertSamples(samples); err != nil {
		t.Fatalf("InsertSamples failed: %v", err)
	}

	fromUnix := now.Add(-60 * time.Second).Unix()
	toUnix := now.Unix()

	ov, err := db.GetOverviewUsageByPeriod(fromUnix, toUnix)
	if err != nil {
		t.Fatalf("GetOverviewUsageByPeriod failed: %v", err)
	}
	// Value 200 * 15s = 3000 bytes
	if ov.TotalDownloadBytes != 3000 || ov.TotalUploadBytes != 1500 {
		t.Fatalf("unexpected total bytes: dl=%d, ul=%d", ov.TotalDownloadBytes, ov.TotalUploadBytes)
	}
	if ov.WanDownloadBytes != 2250 || ov.WanUploadBytes != 1200 {
		t.Fatalf("unexpected wan bytes: dl=%d, ul=%d", ov.WanDownloadBytes, ov.WanUploadBytes)
	}
	if ov.LanDownloadBytes != 750 || ov.LanUploadBytes != 300 {
		t.Fatalf("unexpected lan bytes: dl=%d, ul=%d", ov.LanDownloadBytes, ov.LanUploadBytes)
	}

	devs, err := db.GetDeviceUsageByPeriod(fromUnix, toUnix)
	if err != nil {
		t.Fatalf("GetDeviceUsageByPeriod failed: %v", err)
	}
	d5, ok := devs["10.100.1.5"]
	if !ok {
		t.Fatalf("expected usage for 10.100.1.5")
	}
	if d5.DownloadBytes != 3000 || d5.UploadBytes != 1500 {
		t.Fatalf("unexpected device total: dl=%d, ul=%d", d5.DownloadBytes, d5.UploadBytes)
	}
	if d5.WanDownloadBytes != 2250 || d5.WanUploadBytes != 1200 {
		t.Fatalf("unexpected device wan: dl=%d, ul=%d", d5.WanDownloadBytes, d5.WanUploadBytes)
	}
	if d5.Protocols == nil || d5.Protocols["TCP"] == nil || d5.Protocols["TCP"].DownloadBytes != 1800 {
		t.Fatalf("unexpected proto usage: %+v", d5.Protocols)
	}
	if d5.Peers == nil || d5.Peers["10.100.1.1"] == nil || d5.Peers["10.100.1.1"].BytesReceived != 750 {
		t.Fatalf("unexpected peer usage: %+v", d5.Peers)
	}
}

func TestDB_DDNSHistory(t *testing.T) {
	db, err := Open(":memory:")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	now := time.Now().Truncate(time.Second)
	id1, err := db.RecordDDNSEvent(now.Add(-2*time.Minute), "cloudflare", "198.51.100.1", "", "success", "Updated 2 records")
	if err != nil {
		t.Fatalf("RecordDDNSEvent failed: %v", err)
	}
	if id1 <= 0 {
		t.Errorf("expected valid id, got %d", id1)
	}

	id2, err := db.RecordDDNSEvent(now, "cloudflare", "198.51.100.2", "2001:db8::1", "failure", "API error: unauthorized")
	if err != nil {
		t.Fatalf("RecordDDNSEvent failed: %v", err)
	}
	if id2 <= id1 {
		t.Errorf("expected id2 > id1, got id1=%d, id2=%d", id1, id2)
	}

	history, err := db.GetRecentDDNSHistory(10)
	if err != nil {
		t.Fatalf("GetRecentDDNSHistory failed: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("expected 2 history events, got %d", len(history))
	}

	// Should be ordered DESC by timestamp
	if history[0].ID != id2 || history[0].Status != "failure" || history[0].IPv4 != "198.51.100.2" || history[0].IPv6 != "2001:db8::1" {
		t.Errorf("unexpected event 0: %+v", history[0])
	}
	if history[1].ID != id1 || history[1].Status != "success" || history[1].IPv4 != "198.51.100.1" || history[1].IPv6 != "" {
		t.Errorf("unexpected event 1: %+v", history[1])
	}
}

