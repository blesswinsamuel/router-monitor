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
	"github.com/blesswinsamuel/router-monitor/internal/networkmgr"
	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
	"github.com/blesswinsamuel/router-monitor/internal/routermonitor/ddns"
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
	arp := routermonitor.NewArpCollector("/dev/null")
	checker := routermonitor.NewInternetChecker(10*time.Second, []routermonitor.TargetConfig{
		{Name: "Target 1", Target: "1.1.1.1:53", Type: routermonitor.ProbeTCP},
	}, db)
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

	svc := NewRouterMonitorService("eth0", "10.100.0.0/16", ebpf, arp, checker, db, sampler, nil, nil, nil)

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
		Queries: []*routermonitorv1.TimeSeriesQuery{
			{MetricName: "traffic_bytes_rate"},
		},
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
	arp := routermonitor.NewArpCollector(arpPath)
	checker := routermonitor.NewInternetChecker(10*time.Second, []routermonitor.TargetConfig{
		{Name: "Target 1", Target: "1.1.1.1:53", Type: routermonitor.ProbeTCP},
	}, db)
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

	svc := NewRouterMonitorService("lan", "10.100.0.0/16", ebpf, arp, checker, db, sampler, nil, nil, nil)
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
	arp := routermonitor.NewArpCollector(arpPath)
	checker := routermonitor.NewInternetChecker(10*time.Second, nil, db)
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

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

	devicesYaml := filepath.Join(tmpDir, "devices.yaml")
	netYaml := filepath.Join(tmpDir, "network.yaml")
	_ = os.WriteFile(devicesYaml, []byte("devices:\n  - id: workstation\n    name: static-workstation\n    ip: 10.100.1.10\n    mac: aa:bb:cc:dd:ee:01\n"), 0644)
	_ = os.WriteFile(netYaml, []byte("vlan:\n"), 0644)
	netMgr, err := networkmgr.NewManager(networkmgr.Options{
		DevicesPath: devicesYaml,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	svc := NewRouterMonitorService("lan", "10.100.0.0/16", ebpf, arp, checker, db, sampler, mockDHCP, nil, netMgr)
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
	if !dKnown.IsKnown || !dKnown.IsConfigured {
		t.Errorf("expected 10.100.1.10 to be known and configured, got IsKnown=%v IsConfigured=%v", dKnown.IsKnown, dKnown.IsConfigured)
	}
	if dKnown.Hostname != "static-workstation" {
		t.Errorf("expected hostname static-workstation, got %s", dKnown.Hostname)
	}

	if dUnknown == nil {
		t.Fatal("missing 10.100.99.153")
	}
	if dUnknown.IsKnown || dUnknown.IsConfigured {
		t.Errorf("expected 10.100.99.153 to be unknown (not in devices.yaml), got IsKnown=%v IsConfigured=%v", dUnknown.IsKnown, dUnknown.IsConfigured)
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

func TestRouterMonitorService_WakeOnLan(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "test.db")

	db, err := tsdb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	ebpf := routermonitor.NewEbpfCollector()
	arp := routermonitor.NewArpCollector("/dev/null")
	checker := routermonitor.NewInternetChecker(10*time.Second, nil, db)
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

	// Persist a device to verify MAC auto-lookup by IP
	_ = db.UpsertDevice("aa:bb:cc:dd:ee:88", "10.100.1.88", "desktop-pc", "lan", time.Now())

	svc := NewRouterMonitorService("lan", "10.100.0.0/16", ebpf, arp, checker, db, sampler, nil, nil, nil)
	ctx := context.Background()

	// 1. Successful WoL with explicit MAC
	res, err := svc.WakeOnLan(ctx, connect.NewRequest(&routermonitorv1.WakeOnLanRequest{
		MacAddr: "00:11:22:33:44:55",
	}))
	if err != nil {
		t.Fatalf("WakeOnLan unexpected RPC error: %v", err)
	}
	if !res.Msg.Success {
		t.Errorf("expected success=true, got error: %s", res.Msg.ErrorMessage)
	}
	if res.Msg.MacAddr != "00:11:22:33:44:55" {
		t.Errorf("expected canonical MAC 00:11:22:33:44:55, got %s", res.Msg.MacAddr)
	}
	if !strings.Contains(res.Msg.BroadcastAddr, ":9") {
		t.Errorf("expected broadcast target port 9, got %s", res.Msg.BroadcastAddr)
	}

	// 2. WoL with auto-resolved MAC via IP
	resAuto, err := svc.WakeOnLan(ctx, connect.NewRequest(&routermonitorv1.WakeOnLanRequest{
		IpAddr: "10.100.1.88",
	}))
	if err != nil {
		t.Fatalf("WakeOnLan auto-resolve RPC error: %v", err)
	}
	if !resAuto.Msg.Success {
		t.Errorf("expected success=true for auto-resolved IP, got error: %s", resAuto.Msg.ErrorMessage)
	}
	if resAuto.Msg.MacAddr != "aa:bb:cc:dd:ee:88" {
		t.Errorf("expected MAC aa:bb:cc:dd:ee:88, got %s", resAuto.Msg.MacAddr)
	}

	// 3. Failed WoL when no MAC and unknown IP
	resFail, err := svc.WakeOnLan(ctx, connect.NewRequest(&routermonitorv1.WakeOnLanRequest{
		IpAddr: "10.100.99.99",
	}))
	if err != nil {
		t.Fatalf("WakeOnLan unexpected RPC error: %v", err)
	}
	if resFail.Msg.Success {
		t.Errorf("expected success=false for unknown device without MAC")
	}

	// 4. Failed WoL with invalid MAC
	resInvalid, err := svc.WakeOnLan(ctx, connect.NewRequest(&routermonitorv1.WakeOnLanRequest{
		MacAddr: "invalid-mac-address",
	}))
	if err != nil {
		t.Fatalf("WakeOnLan unexpected RPC error: %v", err)
	}
	if resInvalid.Msg.Success {
		t.Errorf("expected success=false for invalid MAC format")
	}
}

type testDDNSDetector struct{}

func (d *testDDNSDetector) DetectIPs(ctx context.Context, v4, v6 bool) (ddns.IPPair, error) {
	return ddns.IPPair{IPv4: "203.0.113.50", IPv6: "2001:db8::50"}, nil
}

type testDDNSProvider struct{}

func (p *testDDNSProvider) Name() string { return "testprovider" }
func (p *testDDNSProvider) Update(ctx context.Context, req ddns.UpdateRequest) (*ddns.UpdateResult, error) {
	return &ddns.UpdateResult{UpdatedRecords: len(req.Domains), Message: "All good", Success: true}, nil
}

func TestRouterMonitorService_DDNS(t *testing.T) {
	db, err := tsdb.Open(":memory:")
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// 1. Service without DDNS manager
	svcNoDDNS := NewRouterMonitorService("lan", "10.100.0.0/16", nil, nil, nil, db, nil, nil, nil, nil)
	stNoDDNS, err := svcNoDDNS.GetDDNSStatus(ctx, connect.NewRequest(&routermonitorv1.GetDDNSStatusRequest{}))
	if err != nil {
		t.Fatalf("GetDDNSStatus failed: %v", err)
	}
	if stNoDDNS.Msg.Enabled {
		t.Errorf("expected Enabled=false when manager is nil")
	}
	if stNoDDNS.Msg.LastSyncStatus != "disabled" {
		t.Errorf("expected LastSyncStatus=disabled, got %s", stNoDDNS.Msg.LastSyncStatus)
	}

	syncNoDDNS, err := svcNoDDNS.SyncDDNS(ctx, connect.NewRequest(&routermonitorv1.SyncDDNSRequest{}))
	if err != nil {
		t.Fatalf("SyncDDNS failed: %v", err)
	}
	if syncNoDDNS.Msg.Success {
		t.Errorf("expected SyncDDNS to fail when manager is nil")
	}

	// 2. Service with DDNS manager
	mgr := ddns.NewManager(ddns.ManagerConfig{
		Enabled:   true,
		Provider:  &testDDNSProvider{},
		Detector:  &testDDNSDetector{},
		Domains:   []string{"home.example.com"},
		Interval:  5 * time.Minute,
		CheckIPv4: true,
		CheckIPv6: true,
		Store:     db,
	})

	svc := NewRouterMonitorService("lan", "10.100.0.0/16", nil, nil, nil, db, nil, nil, mgr, nil)

	// Sync via RPC
	syncRes, err := svc.SyncDDNS(ctx, connect.NewRequest(&routermonitorv1.SyncDDNSRequest{Force: true}))
	if err != nil {
		t.Fatalf("SyncDDNS error: %v", err)
	}
	if !syncRes.Msg.Success {
		t.Errorf("expected SyncDDNS success, got error: %s", syncRes.Msg.Message)
	}
	if syncRes.Msg.Status == nil || syncRes.Msg.Status.CurrentIpv4 != "203.0.113.50" {
		t.Errorf("unexpected sync status: %+v", syncRes.Msg.Status)
	}

	// Fetch status
	stRes, err := svc.GetDDNSStatus(ctx, connect.NewRequest(&routermonitorv1.GetDDNSStatusRequest{}))
	if err != nil {
		t.Fatalf("GetDDNSStatus error: %v", err)
	}
	if !stRes.Msg.Enabled {
		t.Errorf("expected Enabled=true")
	}
	if stRes.Msg.Provider != "testprovider" {
		t.Errorf("expected provider testprovider, got %s", stRes.Msg.Provider)
	}
	if len(stRes.Msg.Domains) != 1 || stRes.Msg.Domains[0] != "home.example.com" {
		t.Errorf("unexpected domains: %v", stRes.Msg.Domains)
	}
	if stRes.Msg.CurrentIpv4 != "203.0.113.50" || stRes.Msg.CurrentIpv6 != "2001:db8::50" {
		t.Errorf("unexpected IPs: v4=%s v6=%s", stRes.Msg.CurrentIpv4, stRes.Msg.CurrentIpv6)
	}
	if len(stRes.Msg.History) != 1 {
		t.Errorf("expected 1 history record, got %d", len(stRes.Msg.History))
	}
}

func TestRouterMonitorService_NetworkMgr(t *testing.T) {
	tmpDir := t.TempDir()
	devicesPath := filepath.Join(tmpDir, "devices.yaml")

	nm, err := networkmgr.NewManager(networkmgr.Options{
		DevicesPath: devicesPath,
	})
	if err != nil {
		t.Fatalf("NewManager failed: %v", err)
	}

	db, err := tsdb.Open(":memory:")
	if err != nil {
		t.Fatalf("tsdb.Open failed: %v", err)
	}
	defer db.Close()

	svc := NewRouterMonitorService("lan", "10.100.0.0/16", nil, nil, nil, db, nil, nil, nil, nm)
	ctx := context.Background()

	// 1. UpsertConfigDevice
	upsertDevRes, err := svc.UpsertConfigDevice(ctx, connect.NewRequest(&routermonitorv1.UpsertConfigDeviceRequest{
		Device: &routermonitorv1.ConfigDevice{
			Id:        "test-apple-tv",
			Name:      "Living Room Apple TV",
			Mac:       "aa:bb:cc:dd:ee:ff",
			Vlan:      "trusted",
			Ip:        "10.100.1.55",
			Hostnames: []string{"apple-tv", "living-room"},
			Tags:      []string{"cast_target"},
		},
	}))
	if err != nil {
		t.Fatalf("UpsertConfigDevice failed: %v", err)
	}
	if upsertDevRes.Msg.Device.Name != "Living Room Apple TV" {
		t.Errorf("expected name Living Room Apple TV, got %s", upsertDevRes.Msg.Device.Name)
	}

	// 2. ListDevices (unified API)
	listDevRes, err := svc.ListDevices(ctx, connect.NewRequest(&routermonitorv1.ListDevicesRequest{}))
	if err != nil {
		t.Fatalf("ListDevices failed: %v", err)
	}
	if len(listDevRes.Msg.Devices) != 1 {
		t.Fatalf("expected 1 device, got %d", len(listDevRes.Msg.Devices))
	}
	dev := listDevRes.Msg.Devices[0]
	if dev.Vlan != "trusted" {
		t.Errorf("expected vlan trusted, got %s", dev.Vlan)
	}
	if !dev.IsConfigured {
		t.Errorf("expected IsConfigured=true, got %v", dev.IsConfigured)
	}
	if dev.ConfigId != "test-apple-tv" {
		t.Errorf("expected ConfigId test-apple-tv, got %s", dev.ConfigId)
	}
	if dev.ConfigName != "Living Room Apple TV" {
		t.Errorf("expected ConfigName Living Room Apple TV, got %s", dev.ConfigName)
	}
	if len(dev.ConfigHostnames) != 2 || dev.ConfigHostnames[0] != "apple-tv" {
		t.Errorf("expected ConfigHostnames [apple-tv, living-room], got %v", dev.ConfigHostnames)
	}

	// 3. UpsertConfigDnsRecord
	upsertDnsRes, err := svc.UpsertConfigDnsRecord(ctx, connect.NewRequest(&routermonitorv1.UpsertConfigDnsRecordRequest{
		Record: &routermonitorv1.ConfigDnsRecord{
			Name:    "photos",
			Ip:      "10.100.1.200",
			Aliases: []string{"photos.home.lan", "immich.home.lan"},
		},
	}))
	if err != nil {
		t.Fatalf("UpsertConfigDnsRecord failed: %v", err)
	}
	if upsertDnsRes.Msg.Record.Name != "photos" {
		t.Errorf("expected record name photos, got %s", upsertDnsRes.Msg.Record.Name)
	}

	// 4. ListConfigDnsRecords
	listDnsRes, err := svc.ListConfigDnsRecords(ctx, connect.NewRequest(&routermonitorv1.ListConfigDnsRecordsRequest{}))
	if err != nil {
		t.Fatalf("ListConfigDnsRecords failed: %v", err)
	}
	if len(listDnsRes.Msg.Records) != 1 {
		t.Fatalf("expected 1 dns record, got %d", len(listDnsRes.Msg.Records))
	}

	// 5. DeleteConfigDnsRecord
	delDnsRes, err := svc.DeleteConfigDnsRecord(ctx, connect.NewRequest(&routermonitorv1.DeleteConfigDnsRecordRequest{
		Name: "photos",
	}))
	if err != nil {
		t.Fatalf("DeleteConfigDnsRecord failed: %v", err)
	}
	if !delDnsRes.Msg.Success {
		t.Errorf("expected delete dns success=true")
	}

	// 6. DeleteConfigDevice
	delDevRes, err := svc.DeleteConfigDevice(ctx, connect.NewRequest(&routermonitorv1.DeleteConfigDeviceRequest{
		Id: "test-apple-tv",
	}))
	if err != nil {
		t.Fatalf("DeleteConfigDevice failed: %v", err)
	}
	if !delDevRes.Msg.Success {
		t.Errorf("expected delete device success=true")
	}

	// 7. Verify empty lists
	listDevResAfter, _ := svc.ListDevices(ctx, connect.NewRequest(&routermonitorv1.ListDevicesRequest{}))
	if len(listDevResAfter.Msg.Devices) != 0 {
		t.Errorf("expected 0 devices after delete, got %d", len(listDevResAfter.Msg.Devices))
	}
}



