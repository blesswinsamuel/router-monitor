package api

import (
	"context"
	"path/filepath"
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
	checker := routermonitor.NewInternetChecker(10*time.Second, []string{"1.1.1.1:53"})
	sampler := tsdb.NewSampler(db, ebpf, arp, checker, 1*time.Second)

	svc := NewRouterMonitorService("eth0", "10.100.0.0/16", ebpf, arp, checker, db, sampler)

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

	// 3. Test GetTrafficFlows
	flowsRes, err := svc.GetTrafficFlows(ctx, connect.NewRequest(&routermonitorv1.GetTrafficFlowsRequest{}))
	if err != nil {
		t.Fatalf("GetTrafficFlows failed: %v", err)
	}
	if flowsRes.Msg.Flows == nil {
		t.Errorf("expected non-nil flows list")
	}

	// 4. Test GetInternetHealth
	healthRes, err := svc.GetInternetHealth(ctx, connect.NewRequest(&routermonitorv1.GetInternetHealthRequest{}))
	if err != nil {
		t.Fatalf("GetInternetHealth failed: %v", err)
	}
	if len(healthRes.Msg.Targets) != 1 {
		t.Errorf("expected 1 target, got %d", len(healthRes.Msg.Targets))
	}

	// 5. Test QueryTimeSeries
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
