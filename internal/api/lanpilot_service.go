package api

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	lanpilotv1 "github.com/blesswinsamuel/lanpilot/gen/go/lanpilot/v1"
	"github.com/blesswinsamuel/lanpilot/gen/go/lanpilot/v1/lanpilotv1connect"
	"github.com/blesswinsamuel/lanpilot/internal/networkmgr"
	"github.com/blesswinsamuel/lanpilot/internal/lanpilot"
	"github.com/blesswinsamuel/lanpilot/internal/lanpilot/ddns"
	"github.com/blesswinsamuel/lanpilot/internal/tsdb"
	"github.com/endobit/oui"
)

type LanpilotService struct {
	lanpilotv1connect.UnimplementedLanpilotServiceHandler

	interfaceName string
	lanSubnetCIDR string

	ebpfCollector   *lanpilot.EbpfCollector
	arpCollector    *lanpilot.ArpCollector
	internetChecker *lanpilot.InternetChecker
	tsdbDB          *tsdb.DB
	sampler         *tsdb.Sampler
	dhcpReader      lanpilot.DHCPLeaseReader
	ddnsManager     *ddns.Manager
	networkMgr      *networkmgr.Manager
}

func NewLanpilotService(
	ifaceName string,
	lanSubnet string,
	ebpf *lanpilot.EbpfCollector,
	arp *lanpilot.ArpCollector,
	checker *lanpilot.InternetChecker,
	db *tsdb.DB,
	sampler *tsdb.Sampler,
	dhcpReader lanpilot.DHCPLeaseReader,
	ddnsMgr *ddns.Manager,
	networkMgr *networkmgr.Manager,
) *LanpilotService {
	return &LanpilotService{
		interfaceName:   ifaceName,
		lanSubnetCIDR:   lanSubnet,
		ebpfCollector:   ebpf,
		arpCollector:    arp,
		internetChecker: checker,
		tsdbDB:          db,
		sampler:         sampler,
		dhcpReader:      dhcpReader,
		ddnsManager:     ddnsMgr,
		networkMgr:      networkMgr,
	}
}

func liveRatesToTraffic(rates tsdb.LiveRates) (total, wan, lan *lanpilotv1.DirectionalTraffic) {
	total = &lanpilotv1.DirectionalTraffic{
		DownloadBytes:         rates.TotalDownloadBytes,
		UploadBytes:           rates.TotalUploadBytes,
		DownloadPackets:       rates.TotalDownloadPackets,
		UploadPackets:         rates.TotalUploadPackets,
		DownloadBytesPerSec:   rates.DownloadBytesPerSec,
		UploadBytesPerSec:     rates.UploadBytesPerSec,
		DownloadPacketsPerSec: rates.DownloadPacketsPerSec,
		UploadPacketsPerSec:   rates.UploadPacketsPerSec,
	}
	wan = &lanpilotv1.DirectionalTraffic{
		DownloadBytes:         rates.TotalWanDownloadBytes,
		UploadBytes:           rates.TotalWanUploadBytes,
		DownloadPackets:       rates.TotalWanDownloadPackets,
		UploadPackets:         rates.TotalWanUploadPackets,
		DownloadBytesPerSec:   rates.WanDownloadBytesPerSec,
		UploadBytesPerSec:     rates.WanUploadBytesPerSec,
		DownloadPacketsPerSec: rates.WanDownloadPacketsPerSec,
		UploadPacketsPerSec:   rates.WanUploadPacketsPerSec,
	}
	lan = &lanpilotv1.DirectionalTraffic{
		DownloadBytes:         rates.TotalLanDownloadBytes,
		UploadBytes:           rates.TotalLanUploadBytes,
		DownloadPackets:       rates.TotalLanDownloadPackets,
		UploadPackets:         rates.TotalLanUploadPackets,
		DownloadBytesPerSec:   rates.LanDownloadBytesPerSec,
		UploadBytesPerSec:     rates.LanUploadBytesPerSec,
		DownloadPacketsPerSec: rates.LanDownloadPacketsPerSec,
		UploadPacketsPerSec:   rates.LanUploadPacketsPerSec,
	}
	return
}

func (s *LanpilotService) GetOverview(
	ctx context.Context,
	req *connect.Request[lanpilotv1.GetOverviewRequest],
) (*connect.Response[lanpilotv1.GetOverviewResponse], error) {
	rates := s.sampler.GetLiveRates()
	total, wan, lan := liveRatesToTraffic(rates)

	from := req.Msg.FromUnix
	to := req.Msg.ToUnix
	if to <= 0 {
		to = time.Now().Unix()
	}
	if from <= 0 {
		from = to - 86400
	}

	if ovUsage, err := s.tsdbDB.GetOverviewUsageByPeriod(from, to); err == nil && ovUsage != nil {
		total.DownloadBytes = ovUsage.TotalDownloadBytes
		total.UploadBytes = ovUsage.TotalUploadBytes
		wan.DownloadBytes = ovUsage.WanDownloadBytes
		wan.UploadBytes = ovUsage.WanUploadBytes
		lan.DownloadBytes = ovUsage.LanDownloadBytes
		lan.UploadBytes = ovUsage.LanUploadBytes
	}

	res := &lanpilotv1.GetOverviewResponse{
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

func (s *LanpilotService) ListDevices(
	ctx context.Context,
	req *connect.Request[lanpilotv1.ListDevicesRequest],
) (*connect.Response[lanpilotv1.ListDevicesResponse], error) {
	var rawDevices []lanpilot.ArpDeviceEntry
	if s.arpCollector != nil {
		rawDevices = s.arpCollector.GetDevices()
	}
	var deviceRates map[string]tsdb.DeviceRate
	if s.sampler != nil {
		deviceRates = s.sampler.GetDeviceRates()
	}

	var leasesByIP map[string]lanpilot.DHCPLease
	var leasesByMAC map[string]lanpilot.DHCPLease
	if s.dhcpReader != nil {
		leasesByIP, leasesByMAC, _ = s.dhcpReader.GetLeasesMap()
	}

	// 1. Load persisted devices from SQLite TSDB
	var persistedDevices []tsdb.PersistedDevice
	if s.tsdbDB != nil {
		persistedDevices, _ = s.tsdbDB.GetPersistedDevices()
	}
	persistedByMAC := make(map[string]tsdb.PersistedDevice)
	ipToHostname := make(map[string]string)
	for _, pd := range persistedDevices {
		persistedByMAC[pd.HWAddr] = pd
		if pd.Hostname != "" {
			ipToHostname[pd.IPAddr] = pd.Hostname
		}
	}
	for ip, lease := range leasesByIP {
		if lease.Hostname != "" {
			if _, exists := ipToHostname[ip]; !exists {
				ipToHostname[ip] = lease.Hostname
			}
		}
	}

	// 2. Query period usage from SQLite TSDB (default to last 24 hours if not specified)
	from := req.Msg.FromUnix
	to := req.Msg.ToUnix
	if to <= 0 {
		to = time.Now().Unix()
	}
	if from <= 0 {
		from = to - 86400
	}
	periodUsage, _ := s.tsdbDB.GetDeviceUsageByPeriod(from, to)

	var configDevices []networkmgr.Device
	if s.networkMgr != nil {
		configDevices = s.networkMgr.GetDevices()
	}
	cfgByIP := make(map[string]networkmgr.Device, len(configDevices))
	cfgByMAC := make(map[string]networkmgr.Device, len(configDevices))
	for _, cd := range configDevices {
		if cd.IP != "" {
			cfgByIP[cd.IP] = cd
		}
		if cd.MAC != "" {
			cfgByMAC[strings.ToLower(cd.MAC)] = cd
		}
	}

	now := time.Now().Unix()
	seenMACs := make(map[string]bool)
	seenIPs := make(map[string]bool)
	devices := make([]*lanpilotv1.Device, 0, len(rawDevices)+len(persistedDevices)+len(configDevices))

	createDevice := func(
		ip, mac, rawHostname, iface, status string,
		firstSeen, lastSeen int64,
		arpInfo *lanpilotv1.ArpInfo,
		rate tsdb.DeviceRate,
		pu *tsdb.DevicePeriodUsage,
	) *lanpilotv1.Device {
		var matchedCfg *networkmgr.Device
		if cd, ok := cfgByIP[ip]; ok {
			matchedCfg = &cd
		} else if mac != "" && mac != "00:00:00:00:00:00" {
			if cd, ok := cfgByMAC[strings.ToLower(mac)]; ok {
				matchedCfg = &cd
			}
		}

		var tags []string
		var vlan string
		var configName string
		var configId string
		var configHostnames []string
		isConfigured := matchedCfg != nil
		if matchedCfg != nil {
			tags = matchedCfg.Tags
			vlan = matchedCfg.Vlan
			configName = matchedCfg.Name
			configId = matchedCfg.ID
			configHostnames = matchedCfg.Hostnames
		}

		var dhcpLeaseProto *lanpilotv1.DhcpLeaseInfo
		var lease lanpilot.DHCPLease
		var hasLease bool
		if leasesByIP != nil {
			lease, hasLease = leasesByIP[ip]
		}
		if !hasLease && leasesByMAC != nil && mac != "" && mac != "00:00:00:00:00:00" {
			lease, hasLease = leasesByMAC[strings.ToLower(mac)]
		}

		if hasLease {
			dhcpLeaseProto = &lanpilotv1.DhcpLeaseInfo{
				Hostname:             lease.Hostname,
				ClientId:             lease.ClientID,
				ValidLifetimeSeconds: int64(lease.ValidLifetime.Seconds()),
				ExpireUnix:           lease.Expire.Unix(),
				SubnetId:             lease.SubnetID,
				State:                lease.State,
			}
		}

		displayHostname := ""
		if configName != "" {
			displayHostname = configName
		} else if matchedCfg != nil && len(matchedCfg.Hostnames) > 0 {
			displayHostname = matchedCfg.Hostnames[0]
		} else if dhcpLeaseProto != nil && dhcpLeaseProto.Hostname != "" {
			displayHostname = dhcpLeaseProto.Hostname
		} else if rawHostname != "" {
			displayHostname = rawHostname
		}

		isKnown := isConfigured

		var puDl, puUl, puWanDl, puWanUl, puLanDl, puLanUl uint64
		if pu != nil {
			puDl = pu.DownloadBytes
			puUl = pu.UploadBytes
			puWanDl = pu.WanDownloadBytes
			puWanUl = pu.WanUploadBytes
			puLanDl = pu.LanDownloadBytes
			puLanUl = pu.LanUploadBytes
		}

		vendor := ""
		if mac != "" && mac != "00:00:00:00:00:00" {
			vendor = oui.Vendor(mac)
		}

		seenProtos := make(map[string]bool)
		protoList := make([]*lanpilotv1.ProtocolTraffic, 0, len(rate.Protocols))
		for _, p := range rate.Protocols {
			seenProtos[p.Protocol] = true
			dlBytes := p.DownloadBytes
			ulBytes := p.UploadBytes
			if pu != nil && pu.Protocols != nil {
				if protoUsage, ok := pu.Protocols[p.Protocol]; ok {
					dlBytes = protoUsage.DownloadBytes
					ulBytes = protoUsage.UploadBytes
				} else {
					dlBytes = 0
					ulBytes = 0
				}
			}
			protoList = append(protoList, &lanpilotv1.ProtocolTraffic{
				Protocol: p.Protocol,
				Traffic: &lanpilotv1.DirectionalTraffic{
					DownloadBytes:         dlBytes,
					UploadBytes:           ulBytes,
					DownloadPackets:       p.DownloadPackets,
					UploadPackets:         p.UploadPackets,
					DownloadBytesPerSec:   p.DownloadBytesPerSec,
					UploadBytesPerSec:     p.UploadBytesPerSec,
					DownloadPacketsPerSec: p.DownloadPacketsPerSec,
					UploadPacketsPerSec:   p.UploadPacketsPerSec,
				},
			})
		}
		if pu != nil && pu.Protocols != nil {
			for protoName, protoUsage := range pu.Protocols {
				if !seenProtos[protoName] {
					protoList = append(protoList, &lanpilotv1.ProtocolTraffic{
						Protocol: protoName,
						Traffic: &lanpilotv1.DirectionalTraffic{
							DownloadBytes: protoUsage.DownloadBytes,
							UploadBytes:   protoUsage.UploadBytes,
						},
					})
				}
			}
		}
		sort.Slice(protoList, func(a, b int) bool {
			return (protoList[a].Traffic.DownloadBytes + protoList[a].Traffic.UploadBytes) >
				(protoList[b].Traffic.DownloadBytes + protoList[b].Traffic.UploadBytes)
		})

		seenPeers := make(map[string]bool)
		peerList := make([]*lanpilotv1.PeerTraffic, 0, len(rate.Peers))
		for _, pr := range rate.Peers {
			seenPeers[pr.IPAddr] = true
			pHost := ipToHostname[pr.IPAddr]
			dlBytes := pr.BytesReceived
			ulBytes := pr.BytesSent
			if pu != nil && pu.Peers != nil {
				if peerUsage, ok := pu.Peers[pr.IPAddr]; ok {
					dlBytes = peerUsage.BytesReceived
					ulBytes = peerUsage.BytesSent
				} else {
					dlBytes = 0
					ulBytes = 0
				}
			}
			peerList = append(peerList, &lanpilotv1.PeerTraffic{
				IpAddr:   pr.IPAddr,
				Hostname: pHost,
				Traffic: &lanpilotv1.DirectionalTraffic{
					DownloadBytes:         dlBytes,
					UploadBytes:           ulBytes,
					DownloadPackets:       pr.PacketsReceived,
					UploadPackets:         pr.PacketsSent,
					DownloadBytesPerSec:   pr.DownloadBytesPerSec,
					UploadBytesPerSec:     pr.UploadBytesPerSec,
					DownloadPacketsPerSec: pr.DownloadPacketsPerSec,
					UploadPacketsPerSec:   pr.UploadPacketsPerSec,
				},
			})
		}
		if pu != nil && pu.Peers != nil {
			for peerIP, peerUsage := range pu.Peers {
				if !seenPeers[peerIP] {
					pHost := ipToHostname[peerIP]
					peerList = append(peerList, &lanpilotv1.PeerTraffic{
						IpAddr:   peerIP,
						Hostname: pHost,
						Traffic: &lanpilotv1.DirectionalTraffic{
							DownloadBytes: peerUsage.BytesReceived,
							UploadBytes:   peerUsage.BytesSent,
						},
					})
				}
			}
		}
		sort.Slice(peerList, func(a, b int) bool {
			return (peerList[a].Traffic.DownloadBytes + peerList[a].Traffic.UploadBytes) >
				(peerList[b].Traffic.DownloadBytes + peerList[b].Traffic.UploadBytes)
		})

		return &lanpilotv1.Device{
			IpAddr:        ip,
			MacAddr:       mac,
			Hostname:      displayHostname,
			Interface:     iface,
			Status:        status,
			FirstSeenUnix: firstSeen,
			LastSeenUnix:  lastSeen,
			Arp:           arpInfo,
			Total: &lanpilotv1.DirectionalTraffic{
				DownloadBytes:         puDl,
				UploadBytes:           puUl,
				DownloadBytesPerSec:   rate.DownloadBytesPerSec,
				UploadBytesPerSec:     rate.UploadBytesPerSec,
				DownloadPacketsPerSec: rate.DownloadPacketsPerSec,
				UploadPacketsPerSec:   rate.UploadPacketsPerSec,
			},
			Wan: &lanpilotv1.DirectionalTraffic{
				DownloadBytes:         puWanDl,
				UploadBytes:           puWanUl,
				DownloadBytesPerSec:   rate.WanDownloadBytesPerSec,
				UploadBytesPerSec:     rate.WanUploadBytesPerSec,
				DownloadPacketsPerSec: rate.WanDownloadPacketsPerSec,
				UploadPacketsPerSec:   rate.WanUploadPacketsPerSec,
			},
			Lan: &lanpilotv1.DirectionalTraffic{
				DownloadBytes:         puLanDl,
				UploadBytes:           puLanUl,
				DownloadBytesPerSec:   rate.LanDownloadBytesPerSec,
				UploadBytesPerSec:     rate.LanUploadBytesPerSec,
				DownloadPacketsPerSec: rate.LanDownloadPacketsPerSec,
				UploadPacketsPerSec:   rate.LanUploadPacketsPerSec,
			},
			Protocols: protoList,
			Peers:     peerList,
			Vendor:    vendor,
			IsKnown:   isKnown,
			DhcpLease: dhcpLeaseProto,
			Tags:            tags,
			Vlan:            vlan,
			ConfigName:      configName,
			ConfigId:        configId,
			ConfigHostnames: configHostnames,
			IsConfigured:    isConfigured,
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
		rawHostname := ""
		if pd, ok := persistedByMAC[d.HWAddr]; ok {
			firstSeen = pd.FirstSeen.Unix()
			lastSeen = pd.LastSeen.Unix()
			if pd.Hostname != "" {
				rawHostname = pd.Hostname
			}
		}

		rate := deviceRates[d.IPAddr]

		dev := createDevice(
			d.IPAddr, d.HWAddr, rawHostname, d.Device, status,
			firstSeen, lastSeen,
			&lanpilotv1.ArpInfo{
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

	// 4.5. Add configured devices that haven't been seen in ARP or SQLite
	for _, cd := range configDevices {
		if (cd.MAC != "" && seenMACs[cd.MAC]) || (cd.IP != "" && seenIPs[cd.IP]) {
			continue
		}
		if cd.MAC != "" {
			seenMACs[cd.MAC] = true
		}
		if cd.IP != "" {
			seenIPs[cd.IP] = true
		}
		dev := createDevice(
			cd.IP, cd.MAC, cd.Name, "", "offline",
			0, 0, nil,
			tsdb.DeviceRate{}, nil,
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

	return connect.NewResponse(&lanpilotv1.ListDevicesResponse{Devices: devices}), nil
}

func (s *LanpilotService) GetInternetHealth(
	ctx context.Context,
	req *connect.Request[lanpilotv1.GetInternetHealthRequest],
) (*connect.Response[lanpilotv1.GetInternetHealthResponse], error) {
	health := s.internetChecker.GetOverallHealth()
	rawResults := s.internetChecker.GetTargetResults()
	persistedOutages, _ := s.tsdbDB.GetRecentOutages(25)

	targets := make([]*lanpilotv1.TargetHealth, 0, len(rawResults))
	for _, r := range rawResults {
		targets = append(targets, &lanpilotv1.TargetHealth{
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

	outages := make([]*lanpilotv1.OutageRecord, 0, len(persistedOutages))
	for _, o := range persistedOutages {
		var endUnix int64
		if !o.EndTime.IsZero() {
			endUnix = o.EndTime.Unix()
		}
		outages = append(outages, &lanpilotv1.OutageRecord{
			Id:              o.ID,
			StartUnix:       o.StartTime.Unix(),
			EndUnix:         endUnix,
			DurationSeconds: o.DurationSeconds,
			Status:          o.Status,
			Reason:          o.Reason,
		})
	}

	return connect.NewResponse(&lanpilotv1.GetInternetHealthResponse{
		OverallStatus:          health.Status,
		OverallIsUp:            health.IsUp,
		OverallLatencySeconds:  health.LatencySeconds,
		OverallPacketLossRatio: health.PacketLossRatio,
		OverallJitterSeconds:   health.JitterSeconds,
		Targets:                targets,
		RecentOutages:          outages,
	}), nil
}

func (s *LanpilotService) StreamLiveStats(
	ctx context.Context,
	req *connect.Request[lanpilotv1.StreamLiveStatsRequest],
	stream *connect.ServerStream[lanpilotv1.LiveStatsResponse],
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
		return stream.Send(&lanpilotv1.LiveStatsResponse{
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

func (s *LanpilotService) QueryTimeSeries(
	ctx context.Context,
	req *connect.Request[lanpilotv1.QueryTimeSeriesRequest],
) (*connect.Response[lanpilotv1.QueryTimeSeriesResponse], error) {
	from := time.Unix(req.Msg.FromUnix, 0)
	to := time.Unix(req.Msg.ToUnix, 0)
	if req.Msg.ToUnix <= 0 {
		to = time.Now()
	}
	if req.Msg.FromUnix <= 0 {
		from = to.Add(-24 * time.Hour)
	}

	queries := make([]tsdb.TimeSeriesQuerySpec, 0, len(req.Msg.Queries))
	for _, q := range req.Msg.Queries {
		queries = append(queries, tsdb.TimeSeriesQuerySpec{
			MetricName:  q.MetricName,
			MatchLabels: q.MatchLabels,
		})
	}

	results, err := s.tsdbDB.QueryRanges(queries, from, to, int(req.Msg.StepSeconds))
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	seriesList := make([]*lanpilotv1.TimeSeries, 0, len(results))
	for _, res := range results {
		points := make([]*lanpilotv1.TimeSeriesPoint, 0, len(res.Points))
		for _, pt := range res.Points {
			points = append(points, &lanpilotv1.TimeSeriesPoint{
				TimestampUnix: pt.TimestampUnix,
				Value:         pt.Value,
				MinValue:      pt.MinValue,
				MaxValue:      pt.MaxValue,
			})
		}
		seriesList = append(seriesList, &lanpilotv1.TimeSeries{
			MetricName: res.MetricName,
			Labels:     res.Labels,
			Points:     points,
		})
	}

	return connect.NewResponse(&lanpilotv1.QueryTimeSeriesResponse{Series: seriesList}), nil
}

func (s *LanpilotService) PingDevice(
	ctx context.Context,
	req *connect.Request[lanpilotv1.PingDeviceRequest],
) (*connect.Response[lanpilotv1.PingDeviceResponse], error) {
	ip := req.Msg.IpAddr
	count := int(req.Msg.PacketCount)
	if count <= 0 {
		count = 4
	}

	stats := lanpilot.PingHost(ctx, ip, count, 2*time.Second)

	res := &lanpilotv1.PingDeviceResponse{
		IpAddr:             ip,
		IsReachable:        stats.IsReachable,
		PacketLossRatio:    stats.PacketLossRatio,
		MinLatencySeconds:  stats.MinLatency.Seconds(),
		AvgLatencySeconds:  stats.AvgLatency.Seconds(),
		MaxLatencySeconds:  stats.MaxLatency.Seconds(),
		JitterSeconds:      stats.Jitter.Seconds(),
		RoundTripTimesMs:   stats.RoundTripTimesMS,
		ErrorMessage:       stats.LastError,
	}

	return connect.NewResponse(res), nil
}

func (s *LanpilotService) WakeOnLan(
	ctx context.Context,
	req *connect.Request[lanpilotv1.WakeOnLanRequest],
) (*connect.Response[lanpilotv1.WakeOnLanResponse], error) {
	mac := strings.TrimSpace(req.Msg.MacAddr)
	ip := strings.TrimSpace(req.Msg.IpAddr)
	iface := strings.TrimSpace(req.Msg.Interface)

	// If MAC is empty but IP is provided, look up MAC from ARP/TSDB/DHCP
	if mac == "" && ip != "" {
		for _, dev := range s.arpCollector.GetDevices() {
			if dev.IPAddr == ip && dev.HWAddr != "" && dev.HWAddr != "00:00:00:00:00:00" {
				mac = dev.HWAddr
				if iface == "" && dev.Device != "" {
					iface = dev.Device
				}
				break
			}
		}
		if mac == "" && s.dhcpReader != nil {
			leasesByIP, _, _ := s.dhcpReader.GetLeasesMap()
			if lease, ok := leasesByIP[ip]; ok && lease.MACAddr != "" {
				mac = lease.MACAddr
			}
		}
		if mac == "" {
			persisted, _ := s.tsdbDB.GetPersistedDevices()
			for _, pd := range persisted {
				if pd.IPAddr == ip && pd.HWAddr != "" && pd.HWAddr != "00:00:00:00:00:00" {
					mac = pd.HWAddr
					if iface == "" && pd.Device != "" {
						iface = pd.Device
					}
					break
				}
			}
		}
	}

	// If interface is empty, try to resolve from device info or router default interface
	if iface == "" {
		if mac != "" {
			for _, dev := range s.arpCollector.GetDevices() {
				if strings.EqualFold(dev.HWAddr, mac) && dev.Device != "" {
					iface = dev.Device
					break
				}
			}
		}
		if iface == "" {
			iface = s.interfaceName
		}
	}

	if mac == "" {
		return connect.NewResponse(&lanpilotv1.WakeOnLanResponse{
			Success:      false,
			ErrorMessage: "A valid MAC address is required for Wake-on-LAN",
		}), nil
	}

	res, err := lanpilot.SendWakeOnLan(
		mac,
		ip,
		iface,
		int(req.Msg.Port),
		req.Msg.Password,
		s.lanSubnetCIDR,
	)
	if err != nil {
		return connect.NewResponse(&lanpilotv1.WakeOnLanResponse{
			Success:      false,
			MacAddr:      mac,
			Interface:    iface,
			ErrorMessage: err.Error(),
		}), nil
	}

	return connect.NewResponse(&lanpilotv1.WakeOnLanResponse{
		Success:       true,
		MacAddr:       res.MAC,
		BroadcastAddr: res.BroadcastAddr,
		Interface:     res.Interface,
	}), nil
}

func (s *LanpilotService) GetDDNSStatus(
	ctx context.Context,
	req *connect.Request[lanpilotv1.GetDDNSStatusRequest],
) (*connect.Response[lanpilotv1.GetDDNSStatusResponse], error) {
	if s.ddnsManager == nil {
		return connect.NewResponse(&lanpilotv1.GetDDNSStatusResponse{
			Enabled:         false,
			LastSyncStatus:  "disabled",
			LastSyncMessage: "DDNS is not configured",
		}), nil
	}

	st, err := s.ddnsManager.GetStatus(ctx)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}

	history := make([]*lanpilotv1.DDNSHistoryRecord, len(st.History))
	for i, h := range st.History {
		history[i] = &lanpilotv1.DDNSHistoryRecord{
			Id:            h.ID,
			TimestampUnix: h.Timestamp.Unix(),
			Provider:      h.Provider,
			Ipv4:          h.IPv4,
			Ipv6:          h.IPv6,
			Status:        h.Status,
			Message:       h.Message,
		}
	}

	return connect.NewResponse(&lanpilotv1.GetDDNSStatusResponse{
		Enabled:              st.Enabled,
		Provider:             st.Provider,
		Domains:              st.Domains,
		CurrentIpv4:          st.CurrentIPv4,
		CurrentIpv6:          st.CurrentIPv6,
		LastSyncUnix:         st.LastSyncUnix,
		LastSyncStatus:       st.LastSyncStatus,
		LastSyncMessage:      st.LastSyncMessage,
		CheckIntervalSeconds: st.CheckIntervalSeconds,
		History:              history,
	}), nil
}

func (s *LanpilotService) SyncDDNS(
	ctx context.Context,
	req *connect.Request[lanpilotv1.SyncDDNSRequest],
) (*connect.Response[lanpilotv1.SyncDDNSResponse], error) {
	if s.ddnsManager == nil {
		return connect.NewResponse(&lanpilotv1.SyncDDNSResponse{
			Success: false,
			Message: "DDNS is not configured",
		}), nil
	}

	res, err := s.ddnsManager.Sync(ctx, req.Msg.Force)
	statusRes, _ := s.GetDDNSStatus(ctx, connect.NewRequest(&lanpilotv1.GetDDNSStatusRequest{}))

	var status *lanpilotv1.GetDDNSStatusResponse
	if statusRes != nil {
		status = statusRes.Msg
	}

	if err != nil {
		return connect.NewResponse(&lanpilotv1.SyncDDNSResponse{
			Success: false,
			Message: err.Error(),
			Status:  status,
		}), nil
	}

	return connect.NewResponse(&lanpilotv1.SyncDDNSResponse{
		Success: res.Success,
		Message: res.Message,
		Status:  status,
	}), nil
}


func (s *LanpilotService) UpsertConfigDevice(
	ctx context.Context,
	req *connect.Request[lanpilotv1.UpsertConfigDeviceRequest],
) (*connect.Response[lanpilotv1.UpsertConfigDeviceResponse], error) {
	if s.networkMgr == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("network manager not configured"))
	}
	d := req.Msg.Device
	if d == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("device is required"))
	}
	dev := networkmgr.Device{
		ID:        d.Id,
		Name:      d.Name,
		MAC:       d.Mac,
		Vlan:      d.Vlan,
		IP:        d.Ip,
		Hostnames: d.Hostnames,
		Tags:      d.Tags,
	}
	if dev.ID == "" {
		if dev.Name != "" {
			dev.ID = dev.Name
		} else {
			dev.ID = strings.ReplaceAll(strings.ToLower(dev.MAC), ":", "-")
		}
	}
	if err := s.networkMgr.UpsertDevice(dev); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&lanpilotv1.UpsertConfigDeviceResponse{
		Device: &lanpilotv1.ConfigDevice{
			Id:        dev.ID,
			Name:      dev.Name,
			Mac:       dev.MAC,
			Vlan:      dev.Vlan,
			Ip:        dev.IP,
			Hostnames: dev.Hostnames,
			Tags:      dev.Tags,
		},
	}), nil
}

func (s *LanpilotService) DeleteConfigDevice(
	ctx context.Context,
	req *connect.Request[lanpilotv1.DeleteConfigDeviceRequest],
) (*connect.Response[lanpilotv1.DeleteConfigDeviceResponse], error) {
	if s.networkMgr == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("network manager not configured"))
	}
	if err := s.networkMgr.DeleteDevice(req.Msg.Id); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&lanpilotv1.DeleteConfigDeviceResponse{Success: true}), nil
}

func (s *LanpilotService) ListConfigDnsRecords(
	ctx context.Context,
	req *connect.Request[lanpilotv1.ListConfigDnsRecordsRequest],
) (*connect.Response[lanpilotv1.ListConfigDnsRecordsResponse], error) {
	if s.networkMgr == nil {
		return connect.NewResponse(&lanpilotv1.ListConfigDnsRecordsResponse{}), nil
	}
	recs := s.networkMgr.GetDnsRecords()
	res := make([]*lanpilotv1.ConfigDnsRecord, len(recs))
	for i, r := range recs {
		res[i] = &lanpilotv1.ConfigDnsRecord{
			Name:    r.Name,
			Ip:      r.IP,
			Aliases: r.Aliases,
		}
	}
	return connect.NewResponse(&lanpilotv1.ListConfigDnsRecordsResponse{Records: res}), nil
}

func (s *LanpilotService) UpsertConfigDnsRecord(
	ctx context.Context,
	req *connect.Request[lanpilotv1.UpsertConfigDnsRecordRequest],
) (*connect.Response[lanpilotv1.UpsertConfigDnsRecordResponse], error) {
	if s.networkMgr == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("network manager not configured"))
	}
	r := req.Msg.Record
	if r == nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, errors.New("record is required"))
	}
	rec := networkmgr.DnsRecord{
		Name:    r.Name,
		IP:      r.Ip,
		Aliases: r.Aliases,
	}
	if err := s.networkMgr.UpsertDnsRecord(rec); err != nil {
		return nil, connect.NewError(connect.CodeInternal, err)
	}
	return connect.NewResponse(&lanpilotv1.UpsertConfigDnsRecordResponse{
		Record: &lanpilotv1.ConfigDnsRecord{
			Name:    rec.Name,
			Ip:      rec.IP,
			Aliases: rec.Aliases,
		},
	}), nil
}

func (s *LanpilotService) DeleteConfigDnsRecord(
	ctx context.Context,
	req *connect.Request[lanpilotv1.DeleteConfigDnsRecordRequest],
) (*connect.Response[lanpilotv1.DeleteConfigDnsRecordResponse], error) {
	if s.networkMgr == nil {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("network manager not configured"))
	}
	if err := s.networkMgr.DeleteDnsRecord(req.Msg.Name); err != nil {
		return nil, connect.NewError(connect.CodeNotFound, err)
	}
	return connect.NewResponse(&lanpilotv1.DeleteConfigDnsRecordResponse{Success: true}), nil
}


