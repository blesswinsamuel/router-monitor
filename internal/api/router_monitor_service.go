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

func (s *RouterMonitorService) GetOverview(
	ctx context.Context,
	req *connect.Request[routermonitorv1.GetOverviewRequest],
) (*connect.Response[routermonitorv1.GetOverviewResponse], error) {
	rates := s.sampler.GetLiveRates()

	res := &routermonitorv1.GetOverviewResponse{
		InterfaceName:                 s.interfaceName,
		LanSubnetCidr:                 s.lanSubnetCIDR,
		InternetIsUp:                  rates.InternetIsUp,
		InternetLatencySeconds:        rates.InternetLatencySeconds,
		ConnectedDevicesCount:         rates.ConnectedDevicesCount,
		TotalDownloadBytes:            rates.TotalDownloadBytes,
		TotalUploadBytes:              rates.TotalUploadBytes,
		TotalDownloadPackets:          rates.TotalDownloadPackets,
		TotalUploadPackets:            rates.TotalUploadPackets,
		CurrentDownloadBytesPerSec:    rates.DownloadBytesPerSec,
		CurrentUploadBytesPerSec:      rates.UploadBytesPerSec,
		CurrentDownloadPacketsPerSec:  rates.DownloadPacketsPerSec,
		CurrentUploadPacketsPerSec:    rates.UploadPacketsPerSec,
		ServerTimeUnix:                time.Now().Unix(),

		TotalWanDownloadBytes:         rates.TotalWanDownloadBytes,
		TotalWanUploadBytes:           rates.TotalWanUploadBytes,
		TotalLanDownloadBytes:         rates.TotalLanDownloadBytes,
		TotalLanUploadBytes:           rates.TotalLanUploadBytes,
		CurrentWanDownloadBytesPerSec: rates.WanDownloadBytesPerSec,
		CurrentWanUploadBytesPerSec:   rates.WanUploadBytesPerSec,
		CurrentLanDownloadBytesPerSec: rates.LanDownloadBytesPerSec,
		CurrentLanUploadBytesPerSec:   rates.LanUploadBytesPerSec,
	}

	return connect.NewResponse(res), nil
}

func (s *RouterMonitorService) ListDevices(
	ctx context.Context,
	req *connect.Request[routermonitorv1.ListDevicesRequest],
) (*connect.Response[routermonitorv1.ListDevicesResponse], error) {
	rawDevices := s.arpCollector.GetDevices()
	flows := s.ebpfCollector.GetFlowStats()
	deviceRates := s.sampler.GetDeviceRates()

	// 1. Separate flows into Internet and Device-to-Device (LAN) traffic
	type ipTraffic struct {
		internetDlBytes   uint64
		internetUlBytes   uint64
		lanDlBytes        uint64
		lanUlBytes        uint64
		internetDlPackets uint64
		internetUlPackets uint64
		lanDlPackets      uint64
		lanUlPackets      uint64
		dlPkts            uint64
		ulPkts            uint64
	}
	trafficByIP := make(map[string]*ipTraffic)
	getOrCreateTraffic := func(ip string) *ipTraffic {
		t, ok := trafficByIP[ip]
		if !ok {
			t = &ipTraffic{}
			trafficByIP[ip] = t
		}
		return t
	}

	for _, f := range flows {
		isLanToLan := f.SrcIP != "" && f.SrcIP != "internet" && f.DstIP != "" && f.DstIP != "internet"

		if isLanToLan {
			// Device-to-device (LAN) traffic
			srcT := getOrCreateTraffic(f.SrcIP)
			srcT.lanUlBytes += f.Bytes
			srcT.lanUlPackets += f.Packets
			srcT.ulPkts += f.Packets

			dstT := getOrCreateTraffic(f.DstIP)
			dstT.lanDlBytes += f.Bytes
			dstT.lanDlPackets += f.Packets
			dstT.dlPkts += f.Packets
		} else if f.SrcIP != "" && f.SrcIP != "internet" && (f.DstIP == "internet" || f.DstIP == "") {
			// Device uploading to Internet (WAN Upload)
			srcT := getOrCreateTraffic(f.SrcIP)
			srcT.internetUlBytes += f.Bytes
			srcT.internetUlPackets += f.Packets
			srcT.ulPkts += f.Packets
		} else if f.DstIP != "" && f.DstIP != "internet" && (f.SrcIP == "internet" || f.SrcIP == "") {
			// Device downloading from Internet (WAN Download)
			dstT := getOrCreateTraffic(f.DstIP)
			dstT.internetDlBytes += f.Bytes
			dstT.internetDlPackets += f.Packets
			dstT.dlPkts += f.Packets
		}
	}

	// 2. Load persisted devices from SQLite TSDB
	persistedDevices, _ := s.tsdbDB.GetPersistedDevices()
	persistedByMAC := make(map[string]tsdb.PersistedDevice)
	for _, pd := range persistedDevices {
		persistedByMAC[pd.HWAddr] = pd
	}

	var periodUsage map[string]*tsdb.DevicePeriodUsage
	if req.Msg.FromUnix > 0 {
		to := req.Msg.ToUnix
		if to <= 0 {
			to = time.Now().Unix()
		}
		periodUsage, _ = s.tsdbDB.GetDeviceUsageByPeriod(req.Msg.FromUnix, to)
	}

	now := time.Now().Unix()
	seenMACs := make(map[string]bool)
	seenIPs := make(map[string]bool)
	devices := make([]*routermonitorv1.ArpDevice, 0, len(rawDevices)+len(persistedDevices))

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

		dev := &routermonitorv1.ArpDevice{
			IpAddr:                             d.IPAddr,
			HwAddr:                             d.HWAddr,
			Hostname:                           d.Hostname,
			Device:                             d.Device,
			Flags:                              d.Flag,
			IsValid:                            d.IsValid,
			Status:                             status,
			FirstSeenUnix:                      firstSeen,
			LastSeenUnix:                       lastSeen,
			CurrentDownloadBytesPerSec:         rate.DownloadBytesPerSec,
			CurrentUploadBytesPerSec:           rate.UploadBytesPerSec,
			CurrentRateBytesPerSec:             rate.DownloadBytesPerSec + rate.UploadBytesPerSec,
			CurrentWanDownloadBytesPerSec:     rate.WanDownloadBytesPerSec,
			CurrentWanUploadBytesPerSec:       rate.WanUploadBytesPerSec,
			CurrentLanDownloadBytesPerSec:     rate.LanDownloadBytesPerSec,
			CurrentLanUploadBytesPerSec:       rate.LanUploadBytesPerSec,
			CurrentDownloadPacketsPerSec:       rate.DownloadPacketsPerSec,
			CurrentUploadPacketsPerSec:         rate.UploadPacketsPerSec,
			CurrentWanDownloadPacketsPerSec:   rate.WanDownloadPacketsPerSec,
			CurrentWanUploadPacketsPerSec:     rate.WanUploadPacketsPerSec,
			CurrentLanDownloadPacketsPerSec:   rate.LanDownloadPacketsPerSec,
			CurrentLanUploadPacketsPerSec:     rate.LanUploadPacketsPerSec,
		}

		if t, ok := trafficByIP[d.IPAddr]; ok {
			dev.InternetDownloadBytes = t.internetDlBytes
			dev.InternetUploadBytes = t.internetUlBytes
			dev.LanDownloadBytes = t.lanDlBytes
			dev.LanUploadBytes = t.lanUlBytes
			dev.DownloadBytes = t.internetDlBytes + t.lanDlBytes
			dev.UploadBytes = t.internetUlBytes + t.lanUlBytes
			dev.InternetDownloadPackets = t.internetDlPackets
			dev.InternetUploadPackets = t.internetUlPackets
			dev.LanDownloadPackets = t.lanDlPackets
			dev.LanUploadPackets = t.lanUlPackets
			dev.DownloadPackets = t.dlPkts
			dev.UploadPackets = t.ulPkts
		}

		if pu, ok := periodUsage[d.IPAddr]; ok && pu != nil {
			dev.PeriodDownloadBytes = pu.DownloadBytes
			dev.PeriodUploadBytes = pu.UploadBytes
			dev.PeriodWanDownloadBytes = pu.WanDownloadBytes
			dev.PeriodWanUploadBytes = pu.WanUploadBytes
			dev.PeriodLanDownloadBytes = pu.LanDownloadBytes
			dev.PeriodLanUploadBytes = pu.LanUploadBytes
		} else {
			dev.PeriodDownloadBytes = dev.DownloadBytes
			dev.PeriodUploadBytes = dev.UploadBytes
			dev.PeriodWanDownloadBytes = dev.InternetDownloadBytes
			dev.PeriodWanUploadBytes = dev.InternetUploadBytes
			dev.PeriodLanDownloadBytes = dev.LanDownloadBytes
			dev.PeriodLanUploadBytes = dev.LanUploadBytes
		}

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

		dev := &routermonitorv1.ArpDevice{
			IpAddr:                             pd.IPAddr,
			HwAddr:                             pd.HWAddr,
			Hostname:                           pd.Hostname,
			Device:                             pd.Device,
			Flags:                              0,
			IsValid:                            false,
			Status:                             "offline",
			FirstSeenUnix:                      pd.FirstSeen.Unix(),
			LastSeenUnix:                       pd.LastSeen.Unix(),
			CurrentDownloadBytesPerSec:         rate.DownloadBytesPerSec,
			CurrentUploadBytesPerSec:           rate.UploadBytesPerSec,
			CurrentRateBytesPerSec:             rate.DownloadBytesPerSec + rate.UploadBytesPerSec,
			CurrentWanDownloadBytesPerSec:     rate.WanDownloadBytesPerSec,
			CurrentWanUploadBytesPerSec:       rate.WanUploadBytesPerSec,
			CurrentLanDownloadBytesPerSec:     rate.LanDownloadBytesPerSec,
			CurrentLanUploadBytesPerSec:       rate.LanUploadBytesPerSec,
			CurrentDownloadPacketsPerSec:       rate.DownloadPacketsPerSec,
			CurrentUploadPacketsPerSec:         rate.UploadPacketsPerSec,
			CurrentWanDownloadPacketsPerSec:   rate.WanDownloadPacketsPerSec,
			CurrentWanUploadPacketsPerSec:     rate.WanUploadPacketsPerSec,
			CurrentLanDownloadPacketsPerSec:   rate.LanDownloadPacketsPerSec,
			CurrentLanUploadPacketsPerSec:     rate.LanUploadPacketsPerSec,
		}

		if t, ok := trafficByIP[pd.IPAddr]; ok {
			dev.InternetDownloadBytes = t.internetDlBytes
			dev.InternetUploadBytes = t.internetUlBytes
			dev.LanDownloadBytes = t.lanDlBytes
			dev.LanUploadBytes = t.lanUlBytes
			dev.DownloadBytes = t.internetDlBytes + t.lanDlBytes
			dev.UploadBytes = t.internetUlBytes + t.lanUlBytes
			dev.InternetDownloadPackets = t.internetDlPackets
			dev.InternetUploadPackets = t.internetUlPackets
			dev.LanDownloadPackets = t.lanDlPackets
			dev.LanUploadPackets = t.lanUlPackets
			dev.DownloadPackets = t.dlPkts
			dev.UploadPackets = t.ulPkts
		}

		if pu, ok := periodUsage[pd.IPAddr]; ok && pu != nil {
			dev.PeriodDownloadBytes = pu.DownloadBytes
			dev.PeriodUploadBytes = pu.UploadBytes
			dev.PeriodWanDownloadBytes = pu.WanDownloadBytes
			dev.PeriodWanUploadBytes = pu.WanUploadBytes
			dev.PeriodLanDownloadBytes = pu.LanDownloadBytes
			dev.PeriodLanUploadBytes = pu.LanUploadBytes
		} else {
			dev.PeriodDownloadBytes = dev.DownloadBytes
			dev.PeriodUploadBytes = dev.UploadBytes
			dev.PeriodWanDownloadBytes = dev.InternetDownloadBytes
			dev.PeriodWanUploadBytes = dev.InternetUploadBytes
			dev.PeriodLanDownloadBytes = dev.LanDownloadBytes
			dev.PeriodLanUploadBytes = dev.LanUploadBytes
		}

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
			return devices[i].DownloadBytes > devices[j].DownloadBytes
		}
		return devices[i].LastSeenUnix > devices[j].LastSeenUnix
	})

	return connect.NewResponse(&routermonitorv1.ListDevicesResponse{Devices: devices}), nil
}

func (s *RouterMonitorService) GetTrafficFlows(
	ctx context.Context,
	req *connect.Request[routermonitorv1.GetTrafficFlowsRequest],
) (*connect.Response[routermonitorv1.GetTrafficFlowsResponse], error) {
	rawFlows := s.ebpfCollector.GetFlowStats()

	limit := int(req.Msg.Limit)
	if limit <= 0 {
		limit = 100
	}

	var totalBytes, totalPackets uint64
	protoMap := make(map[string]*routermonitorv1.ProtocolStats)
	flows := make([]*routermonitorv1.TrafficFlow, 0, len(rawFlows))

	for _, f := range rawFlows {
		totalBytes += f.Bytes
		totalPackets += f.Packets

		protoName := f.IPProto
		if protoName == "" {
			protoName = f.EthProto
		}
		if protoName == "" {
			protoName = "OTHER"
		}
		ps, ok := protoMap[protoName]
		if !ok {
			ps = &routermonitorv1.ProtocolStats{Protocol: protoName}
			protoMap[protoName] = ps
		}
		ps.Bytes += f.Bytes
		ps.Packets += f.Packets

		flows = append(flows, &routermonitorv1.TrafficFlow{
			Direction: f.Direction,
			EthProto:  f.EthProto,
			IpProto:   f.IPProto,
			SrcIp:     f.SrcIP,
			DstIp:     f.DstIP,
			Packets:   f.Packets,
			Bytes:     f.Bytes,
		})
	}

	// Sort flows by bytes descending
	sort.Slice(flows, func(i, j int) bool {
		return flows[i].Bytes > flows[j].Bytes
	})
	if len(flows) > limit {
		flows = flows[:limit]
	}

	protocols := make([]*routermonitorv1.ProtocolStats, 0, len(protoMap))
	for _, ps := range protoMap {
		protocols = append(protocols, ps)
	}
	sort.Slice(protocols, func(i, j int) bool {
		return protocols[i].Bytes > protocols[j].Bytes
	})

	return connect.NewResponse(&routermonitorv1.GetTrafficFlowsResponse{
		Flows:        flows,
		Protocols:    protocols,
		TotalBytes:   totalBytes,
		TotalPackets: totalPackets,
	}), nil
}

func (s *RouterMonitorService) GetInternetHealth(
	ctx context.Context,
	req *connect.Request[routermonitorv1.GetInternetHealthRequest],
) (*connect.Response[routermonitorv1.GetInternetHealthResponse], error) {
	rawTargets := s.internetChecker.GetStatus()

	overallUp := false
	targets := make([]*routermonitorv1.PingTargetStatus, 0, len(rawTargets))
	for _, t := range rawTargets {
		if t.IsUp {
			overallUp = true
		}
		targets = append(targets, &routermonitorv1.PingTargetStatus{
			Addr:                   t.Addr,
			IsUp:                   t.IsUp,
			LastLatencySeconds:     t.LastLatencySec,
			AvgLatencySeconds:      t.AvgLatencySec,
			RecentLatenciesSeconds: t.RecentLatencies,
		})
	}

	return connect.NewResponse(&routermonitorv1.GetInternetHealthResponse{
		OverallIsUp: overallUp,
		Targets:     targets,
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
		return stream.Send(&routermonitorv1.LiveStatsResponse{
			TimestampUnix:           time.Now().Unix(),
			DownloadBytesPerSec:     rates.DownloadBytesPerSec,
			UploadBytesPerSec:       rates.UploadBytesPerSec,
			DownloadPacketsPerSec:   rates.DownloadPacketsPerSec,
			UploadPacketsPerSec:     rates.UploadPacketsPerSec,
			InternetIsUp:            rates.InternetIsUp,
			InternetLatencySeconds:  rates.InternetLatencySeconds,
			ConnectedDevicesCount:   rates.ConnectedDevicesCount,
			WanDownloadBytesPerSec: rates.WanDownloadBytesPerSec,
			WanUploadBytesPerSec:   rates.WanUploadBytesPerSec,
			LanDownloadBytesPerSec: rates.LanDownloadBytesPerSec,
			LanUploadBytesPerSec:   rates.LanUploadBytesPerSec,
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
