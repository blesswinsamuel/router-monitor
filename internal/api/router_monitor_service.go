package api

import (
	"context"
	"sort"
	"time"

	"connectrpc.com/connect"
	routermonitorv1 "github.com/blesswinsamuel/router-monitor/gen/go/routermonitor/v1"
	"github.com/blesswinsamuel/router-monitor/gen/go/routermonitor/v1/routermonitorv1connect"
	"github.com/blesswinsamuel/router-monitor/internal/routermonitor"
	"github.com/blesswinsamuel/router-monitor/internal/tsdb"
)

type RouterMonitorService struct {
	routermonitorv1connect.UnimplementedRouterMonitorServiceHandler

	interfaceName string
	lanSubnetCIDR string

	ebpfCollector   *routermonitor.EbpfCollector
	arpCollector    *routermonitor.ArpCollector
	internetChecker *routermonitor.InternetChecker
	tsdbDB          *tsdb.DB
	sampler         *tsdb.Sampler
}

func NewRouterMonitorService(
	ifaceName string,
	lanSubnet string,
	ebpf *routermonitor.EbpfCollector,
	arp *routermonitor.ArpCollector,
	checker *routermonitor.InternetChecker,
	db *tsdb.DB,
	sampler *tsdb.Sampler,
) *RouterMonitorService {
	return &RouterMonitorService{
		interfaceName:   ifaceName,
		lanSubnetCIDR:   lanSubnet,
		ebpfCollector:   ebpf,
		arpCollector:    arp,
		internetChecker: checker,
		tsdbDB:          db,
		sampler:         sampler,
	}
}

func liveRatesToTraffic(rates tsdb.LiveRates) (total, wan, lan *routermonitorv1.DirectionalTraffic) {
	total = &routermonitorv1.DirectionalTraffic{
		DownloadBytes:         rates.TotalDownloadBytes,
		UploadBytes:           rates.TotalUploadBytes,
		DownloadPackets:       rates.TotalDownloadPackets,
		UploadPackets:         rates.TotalUploadPackets,
		DownloadBytesPerSec:   rates.DownloadBytesPerSec,
		UploadBytesPerSec:     rates.UploadBytesPerSec,
		DownloadPacketsPerSec: rates.DownloadPacketsPerSec,
		UploadPacketsPerSec:   rates.UploadPacketsPerSec,
	}
	wan = &routermonitorv1.DirectionalTraffic{
		DownloadBytes:       rates.TotalWanDownloadBytes,
		UploadBytes:         rates.TotalWanUploadBytes,
		DownloadBytesPerSec: rates.WanDownloadBytesPerSec,
		UploadBytesPerSec:   rates.WanUploadBytesPerSec,
	}
	lan = &routermonitorv1.DirectionalTraffic{
		DownloadBytes:       rates.TotalLanDownloadBytes,
		UploadBytes:         rates.TotalLanUploadBytes,
		DownloadBytesPerSec: rates.LanDownloadBytesPerSec,
		UploadBytesPerSec:   rates.LanUploadBytesPerSec,
	}
	return
}

func (s *RouterMonitorService) GetOverview(
	ctx context.Context,
	req *connect.Request[routermonitorv1.GetOverviewRequest],
) (*connect.Response[routermonitorv1.GetOverviewResponse], error) {
	rates := s.sampler.GetLiveRates()
	total, wan, lan := liveRatesToTraffic(rates)

	res := &routermonitorv1.GetOverviewResponse{
		InterfaceName:           s.interfaceName,
		LanSubnetCidr:           s.lanSubnetCIDR,
		InternetIsUp:            rates.InternetIsUp,
		InternetLatencySeconds:  rates.InternetLatencySeconds,
		InternetStatus:          rates.InternetStatus,
		InternetPacketLossRatio: rates.InternetPacketLossRatio,
		InternetJitterSeconds:   rates.InternetJitterSeconds,
		ConnectedDevicesCount:   rates.ConnectedDevicesCount,
		Total:                   total,
		Wan:                     wan,
		Lan:                     lan,
	}

	return connect.NewResponse(res), nil
}

func (s *RouterMonitorService) ListDevices(
	ctx context.Context,
	req *connect.Request[routermonitorv1.ListDevicesRequest],
) (*connect.Response[routermonitorv1.ListDevicesResponse], error) {
	rawDevices := s.arpCollector.GetDevices()
	deviceRates := s.sampler.GetDeviceRates()

	// 1. Load persisted devices from SQLite TSDB
	persistedDevices, _ := s.tsdbDB.GetPersistedDevices()
	persistedByMAC := make(map[string]tsdb.PersistedDevice)
	for _, pd := range persistedDevices {
		persistedByMAC[pd.HWAddr] = pd
	}

	// 2. Query period usage from SQLite TSDB (default to last 1 hour if not specified)
	from := req.Msg.FromUnix
	to := req.Msg.ToUnix
	if to <= 0 {
		to = time.Now().Unix()
	}
	if from <= 0 {
		from = to - 3600
	}
	periodUsage, _ := s.tsdbDB.GetDeviceUsageByPeriod(from, to)

	now := time.Now().Unix()
	seenMACs := make(map[string]bool)
	seenIPs := make(map[string]bool)
	devices := make([]*routermonitorv1.Device, 0, len(rawDevices)+len(persistedDevices))

	createDevice := func(
		ip, mac, hostname, iface, status string,
		firstSeen, lastSeen int64,
		arpInfo *routermonitorv1.ArpInfo,
		rate tsdb.DeviceRate,
		pu *tsdb.DevicePeriodUsage,
	) *routermonitorv1.Device {
		var puDl, puUl, puWanDl, puWanUl, puLanDl, puLanUl uint64
		if pu != nil {
			puDl = pu.DownloadBytes
			puUl = pu.UploadBytes
			puWanDl = pu.WanDownloadBytes
			puWanUl = pu.WanUploadBytes
			puLanDl = pu.LanDownloadBytes
			puLanUl = pu.LanUploadBytes
		}

		return &routermonitorv1.Device{
			IpAddr:        ip,
			MacAddr:       mac,
			Hostname:      hostname,
			Interface:     iface,
			Status:        status,
			FirstSeenUnix: firstSeen,
			LastSeenUnix:  lastSeen,
			Arp:           arpInfo,
			Total: &routermonitorv1.DirectionalTraffic{
				DownloadBytes:         puDl,
				UploadBytes:           puUl,
				DownloadBytesPerSec:   rate.DownloadBytesPerSec,
				UploadBytesPerSec:     rate.UploadBytesPerSec,
				DownloadPacketsPerSec: rate.DownloadPacketsPerSec,
				UploadPacketsPerSec:   rate.UploadPacketsPerSec,
			},
			Wan: &routermonitorv1.DirectionalTraffic{
				DownloadBytes:         puWanDl,
				UploadBytes:           puWanUl,
				DownloadBytesPerSec:   rate.WanDownloadBytesPerSec,
				UploadBytesPerSec:     rate.WanUploadBytesPerSec,
				DownloadPacketsPerSec: rate.WanDownloadPacketsPerSec,
				UploadPacketsPerSec:   rate.WanUploadPacketsPerSec,
			},
			Lan: &routermonitorv1.DirectionalTraffic{
				DownloadBytes:         puLanDl,
				UploadBytes:           puLanUl,
				DownloadBytesPerSec:   rate.LanDownloadBytesPerSec,
				UploadBytesPerSec:     rate.LanUploadBytesPerSec,
				DownloadPacketsPerSec: rate.LanDownloadPacketsPerSec,
				UploadPacketsPerSec:   rate.LanUploadPacketsPerSec,
			},
		}
	}

	// 3. Process current ARP devices
	for _, d := range rawDevices {
		if d.HWAddr != "" && d.HWAddr != "00:00:00:00:00:00" {
			seenMACs[d.HWAddr] = true
		}
		seenIPs[d.IPAddr] = true

		// Determine human-friendly status:
		// Flag 0: Incomplete / probe sent but no ARP response received
		// Flag 2: Completed / active dynamic entry
		// Flag 4 or Flag 6: Permanent / static ARP entry
		status := "active"
		if d.Flag == 0 {
			status = "unreachable"
		} else if d.Flag&4 != 0 {
			status = "static"
		} else if !d.IsValid {
			status = "unreachable"
		}

		firstSeen := now
		lastSeen := now
		if pd, ok := persistedByMAC[d.HWAddr]; ok {
			firstSeen = pd.FirstSeen.Unix()
			lastSeen = pd.LastSeen.Unix()
		}

		rate := deviceRates[d.IPAddr]

		dev := createDevice(
			d.IPAddr, d.HWAddr, d.Hostname, d.Device, status,
			firstSeen, lastSeen,
			&routermonitorv1.ArpInfo{
				Flags:     d.Flag,
				IsValid:   d.IsValid,
				Interface: d.Device,
			},
			rate, periodUsage[d.IPAddr],
		)
		devices = append(devices, dev)
	}

	// 4. Add offline devices that are saved in SQLite but currently missing from ARP table
	for _, pd := range persistedDevices {
		if seenMACs[pd.HWAddr] || seenIPs[pd.IPAddr] {
			continue
		}
		seenMACs[pd.HWAddr] = true
		seenIPs[pd.IPAddr] = true

		rate := deviceRates[pd.IPAddr]

		dev := createDevice(
			pd.IPAddr, pd.HWAddr, pd.Hostname, pd.Device, "offline",
			pd.FirstSeen.Unix(), pd.LastSeen.Unix(), nil,
			rate, periodUsage[pd.IPAddr],
		)
		devices = append(devices, dev)
	}

	// 5. Sort devices: active/static first (by download volume descending), then offline by last seen
	sort.Slice(devices, func(i, j int) bool {
		iOnline := devices[i].Status == "active" || devices[i].Status == "static"
		jOnline := devices[j].Status == "active" || devices[j].Status == "static"
		if iOnline != jOnline {
			return iOnline
		}
		if iOnline {
			var iBytes, jBytes uint64
			if devices[i].Total != nil {
				iBytes = devices[i].Total.DownloadBytes
			}
			if devices[j].Total != nil {
				jBytes = devices[j].Total.DownloadBytes
			}
			return iBytes > jBytes
		}
		return devices[i].LastSeenUnix > devices[j].LastSeenUnix
	})

	return connect.NewResponse(&routermonitorv1.ListDevicesResponse{Devices: devices}), nil
}

func (s *RouterMonitorService) GetInternetHealth(
	ctx context.Context,
	req *connect.Request[routermonitorv1.GetInternetHealthRequest],
) (*connect.Response[routermonitorv1.GetInternetHealthResponse], error) {
	health := s.internetChecker.GetOverallHealth()
	rawResults := s.internetChecker.GetTargetResults()
	persistedOutages, _ := s.tsdbDB.GetRecentOutages(25)

	targets := make([]*routermonitorv1.TargetHealth, 0, len(rawResults))
	for _, r := range rawResults {
		targets = append(targets, &routermonitorv1.TargetHealth{
			Name:              r.Target.Name,
			Target:            r.Target.Target,
			ProbeType:         string(r.Target.Type),
			IsUp:              r.IsUp,
			LatencySeconds:    r.Latency.Seconds(),
			MinLatencySeconds: r.MinLatency.Seconds(),
			MaxLatencySeconds: r.MaxLatency.Seconds(),
			AvgLatencySeconds: r.AvgLatency.Seconds(),
			JitterSeconds:     r.Jitter.Seconds(),
			PacketLossRatio:   r.PacketLossRatio,
			LastError:         r.LastError,
			LastCheckedUnix:   r.Timestamp.Unix(),
		})
	}

	outages := make([]*routermonitorv1.OutageRecord, 0, len(persistedOutages))
	for _, o := range persistedOutages {
		var endUnix int64
		if !o.EndTime.IsZero() {
			endUnix = o.EndTime.Unix()
		}
		outages = append(outages, &routermonitorv1.OutageRecord{
			Id:              o.ID,
			StartUnix:       o.StartTime.Unix(),
			EndUnix:         endUnix,
			DurationSeconds: o.DurationSeconds,
			Status:          o.Status,
			Reason:          o.Reason,
		})
	}

	return connect.NewResponse(&routermonitorv1.GetInternetHealthResponse{
		OverallStatus:          health.Status,
		OverallIsUp:            health.IsUp,
		OverallLatencySeconds:  health.LatencySeconds,
		OverallPacketLossRatio: health.PacketLossRatio,
		OverallJitterSeconds:   health.JitterSeconds,
		Targets:                targets,
		RecentOutages:          outages,
	}), nil
}

func (s *RouterMonitorService) StreamLiveStats(
	ctx context.Context,
	req *connect.Request[routermonitorv1.StreamLiveStatsRequest],
	stream *connect.ServerStream[routermonitorv1.LiveStatsResponse],
) error {
	interval := time.Duration(req.Msg.IntervalSeconds) * time.Second
	if interval < 500*time.Millisecond {
		interval = 1 * time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	sendStats := func() error {
		rates := s.sampler.GetLiveRates()
		total, wan, lan := liveRatesToTraffic(rates)
		return stream.Send(&routermonitorv1.LiveStatsResponse{
			TimestampUnix:           time.Now().Unix(),
			InternetIsUp:            rates.InternetIsUp,
			InternetLatencySeconds:  rates.InternetLatencySeconds,
			InternetStatus:          rates.InternetStatus,
			InternetPacketLossRatio: rates.InternetPacketLossRatio,
			InternetJitterSeconds:   rates.InternetJitterSeconds,
			ConnectedDevicesCount:   rates.ConnectedDevicesCount,
			Total:                   total,
			Wan:                     wan,
			Lan:                     lan,
		})
	}

	// Send initial stats immediately
	if err := sendStats(); err != nil {
		return err
	}

	for {
		select {
		case <-ticker.C:
			if err := sendStats(); err != nil {
				return err
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func (s *RouterMonitorService) QueryTimeSeries(
	ctx context.Context,
	req *connect.Request[routermonitorv1.QueryTimeSeriesRequest],
) (*connect.Response[routermonitorv1.QueryTimeSeriesResponse], error) {
	from := time.Unix(req.Msg.FromUnix, 0)
	to := time.Unix(req.Msg.ToUnix, 0)
	if req.Msg.ToUnix <= 0 {
		to = time.Now()
	}
	if req.Msg.FromUnix <= 0 {
		from = to.Add(-1 * time.Hour)
	}

	results, err := s.tsdbDB.QueryRange(req.Msg.MetricName, req.Msg.MatchLabels, from, to, int(req.Msg.StepSeconds))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	seriesList := make([]*routermonitorv1.TimeSeries, 0, len(results))
	for _, res := range results {
		points := make([]*routermonitorv1.TimeSeriesPoint, 0, len(res.Points))
		for _, pt := range res.Points {
			points = append(points, &routermonitorv1.TimeSeriesPoint{
				TimestampUnix: pt.TimestampUnix,
				Value:         pt.Value,
				MinValue:      pt.MinValue,
				MaxValue:      pt.MaxValue,
			})
		}
		seriesList = append(seriesList, &routermonitorv1.TimeSeries{
			MetricName: res.MetricName,
			Labels:     res.Labels,
			Points:     points,
		})
	}

	return connect.NewResponse(&routermonitorv1.QueryTimeSeriesResponse{Series: seriesList}), nil
}
