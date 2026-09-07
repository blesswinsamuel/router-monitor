package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	routermonitorv1 "github.com/blesswinsamuel/router-monitor/gen/go/routermonitor/v1"
	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
	"github.com/blesswinsamuel/router-monitor/internal/tsdb"
)

func TestRouterMonitorService_Endpoints(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tsdb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	ebpf := routermonitor.NewEbpfCollector()
	arp := routermonitor.NewArpCollector("/dev/null", "", 30*time.Minute)
	checker := routermonitor.NewInternetChecker(10*time.Second, []routermonitor.TargetConfig{
		{Name: "Target 1", Target: "1.1.1.1:53", Type: routermonitor.ProbeTCP},
	}, db)
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

	svc := NewRouterMonitorService("eth0", "10.100.0.0/16", ebpf, arp, checker, db, sampler, nil)

	ctx := context.Background()

	// 1. Test GetOverview
	overviewRes, err := svc.GetOverview(ctx, connect.NewRequest(&routermonitorv1.GetOverviewRequest{}))
	if err != nil {
		t.Fatalf("GetOverview failed: %v", err)
	}
	if overviewRes.Msg.InterfaceName != "eth0" {
		t.Errorf("expected eth0, got %s", overviewRes.Msg.InterfaceName)
	}

	// 2. Test ListDevices
	devicesRes, err := svc.ListDevices(ctx, connect.NewRequest(&routermonitorv1.ListDevicesRequest{}))
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}
	if devicesRes.Msg.Devices == nil {
		t.Errorf("expected non-nil devices list")
	}

	// 3. Test GetInternetHealth
	healthRes, err := svc.GetInternetHealth(ctx, connect.NewRequest(&routermonitorv1.GetInternetHealthRequest{}))
	if err != nil {
		t.Fatalf("GetInternetHealth failed: %v", err)
	}
	if len(healthRes.Msg.Targets) != 1 {
		t.Errorf("expected 1 target, got %d", len(healthRes.Msg.Targets))
	}

	// 4. Test QueryTimeSeries
	tsRes, err := svc.QueryTimeSeries(ctx, connect.NewRequest(&routermonitorv1.QueryTimeSeriesRequest{
		MetricName: "traffic_bytes_rate",
	}))
	if err != nil {
		t.Fatalf("QueryTimeSeries failed: %v", err)
	}
	if tsRes.Msg.Series == nil {
		t.Errorf("expected non-nil series list")
	}
}

func TestRouterMonitorService_DeviceTrafficAndPersistence(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	arpPath := filepath.Join(tmpDir, "arp")

	db, err := tsdb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	// Seed persisted offline device
	_ = db.UpsertDevice("aa:bb:cc:dd:ee:99", "10.100.1.99", "old-offline-device", "lan", time.Now().Add(-1*time.Hour))

	// Write mock ARP table with 1 active device and 1 unreachable device (flag 0)
	arpContent := `IP address       HW type     Flags       HW address            Mask     Device
10.100.1.10      0x1         0x2         aa:bb:cc:dd:ee:10     *        lan
10.100.1.20      0x1         0x0         aa:bb:cc:dd:ee:20     *        lan
10.100.1.30      0x1         0x6         aa:bb:cc:dd:ee:30     *        lan
`
	if err := os.WriteFile(arpPath, []byte(arpContent), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ebpf := routermonitor.NewEbpfCollector()
	arp := routermonitor.NewArpCollector(arpPath, "", 30*time.Minute)
	checker := routermonitor.NewInternetChecker(10*time.Second, []routermonitor.TargetConfig{
		{Name: "Target 1", Target: "1.1.1.1:53", Type: routermonitor.ProbeTCP},
	}, db)
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

	svc := NewRouterMonitorService("lan", "10.100.0.0/16", ebpf, arp, checker, db, sampler, nil)
	ctx := context.Background()

	res, err := svc.ListDevices(ctx, connect.NewRequest(&routermonitorv1.ListDevicesRequest{}))
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}

	devices := res.Msg.Devices
	if len(devices) != 4 {
		t.Fatalf("expected 4 devices (3 from ARP + 1 offline from DB), got %d", len(devices))
	}

	statusByIP := make(map[string]string)
	for _, d := range devices {
		statusByIP[d.IpAddr] = d.Status
	}

	if statusByIP["10.100.1.10"] != "active" {
		t.Errorf("expected 10.100.1.10 to be active, got %s", statusByIP["10.100.1.10"])
	}
	if statusByIP["10.100.1.20"] != "unreachable" {
		t.Errorf("expected 10.100.1.20 to be unreachable (Flags:0), got %s", statusByIP["10.100.1.20"])
	}
	if statusByIP["10.100.1.30"] != "static" {
		t.Errorf("expected 10.100.1.30 to be static (Flags:6), got %s", statusByIP["10.100.1.30"])
	}
	if statusByIP["10.100.1.99"] != "offline" {
		t.Errorf("expected 10.100.1.99 to be offline, got %s", statusByIP["10.100.1.99"])
	}
}

type mockDHCPReader struct {
	leases []routermonitor.DHCPLease
}

func (m *mockDHCPReader) GetLeases() ([]routermonitor.DHCPLease, error) {
	return m.leases, nil
}

func (m *mockDHCPReader) GetLeasesMap() (map[string]routermonitor.DHCPLease, map[string]routermonitor.DHCPLease, error) {
	byIP := make(map[string]routermonitor.DHCPLease)
	byMAC := make(map[string]routermonitor.DHCPLease)
	for _, l := range m.leases {
		if l.IPAddr != "" {
			byIP[l.IPAddr] = l
		}
		if l.MACAddr != "" {
			byMAC[strings.ToLower(l.MACAddr)] = l
		}
	}
	return byIP, byMAC, nil
}

func TestListDevices_KnownAndUnknownWithDHCP(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")
	db, err := tsdb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	arpPath := filepath.Join(tmpDir, "arp")
	arpContent := "IP address       HW type     Flags       HW address            Mask     Device\n" +
		"10.100.1.10     0x1         0x2         aa:bb:cc:dd:ee:01     *        lan\n" +
		"10.100.99.153    0x1         0x2         ee:41:6b:c8:f9:9d     *        guest\n"
	if err := os.WriteFile(arpPath, []byte(arpContent), 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	ebpf := routermonitor.NewEbpfCollector()
	arp := routermonitor.NewArpCollector(arpPath, "", 30*time.Minute)
	checker := routermonitor.NewInternetChecker(10*time.Second, nil, db)
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

	// Pre-populate reverse DNS cache for 10.100.1.10 (known) but not for 10.100.99.153
	// We call GetDevices so ARP collector parses the file, but inject hostCache for 10.100.1.10
	_ = arp.GetDevices()

	mockDHCP := &mockDHCPReader{
		leases: []routermonitor.DHCPLease{
			{
				IPAddr:        "10.100.99.153",
				MACAddr:       "ee:41:6b:c8:f9:9d",
				Hostname:      "iphone",
				ClientID:      "01:ee:41:6b:c8:f9:9d",
				ValidLifetime: 8 * time.Hour,
				Expire:        time.Now().Add(4 * time.Hour),
				SubnetID:      99,
				State:         0,
			},
		},
	}

	// Statically upsert 10.100.1.10 in DB with a known hostname from reverse DNS
	tNow := time.Now()
	if err := db.UpsertDevice("aa:bb:cc:dd:ee:01", "10.100.1.10", "static-workstation", "lan", tNow); err != nil {
		t.Fatalf("UpsertDevice failed: %v", err)
	}

	svc := NewRouterMonitorService("lan", "10.100.0.0/16", ebpf, arp, checker, db, sampler, mockDHCP)
	res, err := svc.ListDevices(context.Background(), connect.NewRequest(&routermonitorv1.ListDevicesRequest{}))
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}

	var dKnown, dUnknown *routermonitorv1.Device
	for _, d := range res.Msg.Devices {
		if d.IpAddr == "10.100.1.10" {
			dKnown = d
		} else if d.IpAddr == "10.100.99.153" {
			dUnknown = d
		}
	}

	if dKnown == nil {
		t.Fatal("missing 10.100.1.10")
	}
	if !dKnown.IsKnown {
		t.Errorf("expected 10.100.1.10 to be known (static DNS), got IsKnown=false")
	}
	if dKnown.Hostname != "static-workstation" {
		t.Errorf("expected hostname static-workstation, got %s", dKnown.Hostname)
	}

	if dUnknown == nil {
		t.Fatal("missing 10.100.99.153")
	}
	if dUnknown.IsKnown {
		t.Errorf("expected 10.100.99.153 to be unknown (no reverse DNS), got IsKnown=true")
	}
	if dUnknown.Hostname != "iphone" {
		t.Errorf("expected hostname iphone from DHCP, got %s", dUnknown.Hostname)
	}
	if dUnknown.DhcpLease == nil {
		t.Fatal("expected DhcpLease to be populated")
	}
	if dUnknown.DhcpLease.Hostname != "iphone" {
		t.Errorf("expected dhcp_lease.hostname=iphone, got %s", dUnknown.DhcpLease.Hostname)
	}
	if dUnknown.DhcpLease.SubnetId != 99 {
		t.Errorf("expected dhcp_lease.subnet_id=99, got %d", dUnknown.DhcpLease.SubnetId)
	}
}


