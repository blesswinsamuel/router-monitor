package routermonitor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

func newTestArpCollector(filename string) *arpCollector {
	return &arpCollector{
		filename:          filename,
		stripDomainSuffix: "",
		hostCacheTTL:      time.Minute,
		lookupTimeout:     10 * time.Millisecond,
		hostCache:         make(map[string]hostCacheValue),
		pendingLookups:    make(map[string]struct{}),
		lookupQueue:       make(chan string, 4),
		arpDevices: prometheus.NewDesc("router_monitor_arp_devices", "ARP entries discovered from /proc/net/arp.",
			[]string{"ip_addr", "hw_addr", "hostname", "device"}, nil,
		),
	}
}

func TestEnqueueLookup_Deduplicates(t *testing.T) {
	collector := newTestArpCollector("")

	collector.enqueueLookup("192.168.1.10")
	collector.enqueueLookup("192.168.1.10")

	if len(collector.lookupQueue) != 1 {
		t.Fatalf("expected one queued lookup, got %d", len(collector.lookupQueue))
	}
	if _, ok := collector.pendingLookups["192.168.1.10"]; !ok {
		t.Fatal("expected pending lookup entry")
	}
}

func TestEnqueueLookup_DropsWhenQueueFull(t *testing.T) {
	collector := newTestArpCollector("")
	collector.lookupQueue = make(chan string, 1)
	collector.lookupQueue <- "already-full"

	collector.enqueueLookup("192.168.1.11")

	if _, ok := collector.pendingLookups["192.168.1.11"]; ok {
		t.Fatal("pending lookup should be removed when queue is full")
	}
}

func TestCollect_EmitsMetricAndQueuesLookup(t *testing.T) {
	tmpDir := t.TempDir()
	arpPath := filepath.Join(tmpDir, "arp")
	contents := "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.20 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n"
	if err := os.WriteFile(arpPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test arp file: %v", err)
	}

	collector := newTestArpCollector(arpPath)
	metrics := make(chan prometheus.Metric, 2)
	collector.Collect(metrics)

	if len(metrics) != 1 {
		t.Fatalf("expected one metric, got %d", len(metrics))
	}
	if len(collector.lookupQueue) != 1 {
		t.Fatalf("expected one queued lookup, got %d", len(collector.lookupQueue))
	}
	if _, ok := collector.pendingLookups["192.168.1.20"]; !ok {
		t.Fatal("expected pending lookup after collect")
	}
}

func TestCollect_UsesFreshCacheWithoutQueueingLookup(t *testing.T) {
	tmpDir := t.TempDir()
	arpPath := filepath.Join(tmpDir, "arp")
	contents := "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.21 0x1 0x2 aa:bb:cc:dd:ee:01 * eth0\n"
	if err := os.WriteFile(arpPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test arp file: %v", err)
	}

	collector := newTestArpCollector(arpPath)
	collector.hostCache["192.168.1.21"] = hostCacheValue{Hostname: "host1", Expiry: time.Now().Add(time.Minute)}
	metrics := make(chan prometheus.Metric, 2)
	collector.Collect(metrics)

	if len(metrics) != 1 {
		t.Fatalf("expected one metric, got %d", len(metrics))
	}
	if len(collector.lookupQueue) != 0 {
		t.Fatalf("expected no queued lookup, got %d", len(collector.lookupQueue))
	}
	if len(collector.pendingLookups) != 0 {
		t.Fatalf("expected no pending lookups, got %d", len(collector.pendingLookups))
	}
}
