package routermonitor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestCollect_EmitsMetric(t *testing.T) {
	tmpDir := t.TempDir()
	arpPath := filepath.Join(tmpDir, "arp")
	contents := "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.20 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n"
	if err := os.WriteFile(arpPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test arp file: %v", err)
	}

	collector := NewArpCollector(arpPath)
	metrics := make(chan prometheus.Metric, 2)
	collector.Collect(metrics)

	if len(metrics) != 1 {
		t.Fatalf("expected one metric, got %d", len(metrics))
	}
}

func TestGetDevices_IgnoresNullHWAddr(t *testing.T) {
	tmpDir := t.TempDir()
	arpPath := filepath.Join(tmpDir, "arp")
	contents := "IP address       HW type     Flags       HW address            Mask     Device\n192.168.1.20 0x1 0x2 aa:bb:cc:dd:ee:ff * eth0\n192.168.1.21 0x1 0x0 00:00:00:00:00:00 * eth0\n"
	if err := os.WriteFile(arpPath, []byte(contents), 0o600); err != nil {
		t.Fatalf("write test arp file: %v", err)
	}

	collector := NewArpCollector(arpPath)
	devices := collector.GetDevices()

	if len(devices) != 1 {
		t.Fatalf("expected 1 valid device, got %d", len(devices))
	}
	if devices[0].IPAddr != "192.168.1.20" {
		t.Errorf("expected IP 192.168.1.20, got %s", devices[0].IPAddr)
	}
	if devices[0].HWAddr != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected MAC aa:bb:cc:dd:ee:ff, got %s", devices[0].HWAddr)
	}
	if !devices[0].IsValid {
		t.Errorf("expected IsValid=true for flag 0x2")
	}
}
