package tsdb

import (
	"context"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/blesswinsamuel/lanpilot/internal/lanpilot"
)

type LiveRates struct {
	DownloadBytesPerSec   float64
	UploadBytesPerSec     float64
	DownloadPacketsPerSec float64
	UploadPacketsPerSec   float64

	TotalDownloadBytes   uint64
	TotalUploadBytes     uint64
	TotalDownloadPackets uint64
	TotalUploadPackets   uint64

	WanDownloadBytesPerSec   float64
	WanUploadBytesPerSec     float64
	LanDownloadBytesPerSec   float64
	LanUploadBytesPerSec     float64
	WanDownloadPacketsPerSec float64
	WanUploadPacketsPerSec   float64
	LanDownloadPacketsPerSec float64
	LanUploadPacketsPerSec   float64

	TotalWanDownloadBytes   uint64
	TotalWanUploadBytes     uint64
	TotalLanDownloadBytes   uint64
	TotalLanUploadBytes     uint64
	TotalWanDownloadPackets uint64
	TotalWanUploadPackets   uint64
	TotalLanDownloadPackets uint64
	TotalLanUploadPackets   uint64

	InternetIsUp            bool
	InternetStatus          string
	InternetLatencySeconds  float64
	InternetPacketLossRatio float64
	InternetJitterSeconds   float64
	ConnectedDevicesCount   int32
	LastSampleTime          time.Time
}

type ProtocolStats struct {
	Protocol              string
	DownloadBytes         uint64
	UploadBytes           uint64
	DownloadPackets       uint64
	UploadPackets         uint64
	DownloadBytesPerSec   float64
	UploadBytesPerSec     float64
	DownloadPacketsPerSec float64
	UploadPacketsPerSec   float64
}

type PeerTrafficStat struct {
	IPAddr                string
	BytesSent             uint64
	BytesReceived         uint64
	PacketsSent           uint64
	PacketsReceived       uint64
	UploadBytesPerSec     float64
	DownloadBytesPerSec   float64
	UploadPacketsPerSec   float64
	DownloadPacketsPerSec float64
}

type trafficStats struct {
	dlBytes   uint64
	ulBytes   uint64
	dlPackets uint64
	ulPackets uint64
}

type DeviceRate struct {
	DownloadBytesPerSec      float64
	UploadBytesPerSec        float64
	WanDownloadBytesPerSec   float64
	WanUploadBytesPerSec     float64
	LanDownloadBytesPerSec   float64
	LanUploadBytesPerSec     float64
	DownloadPacketsPerSec    float64
	UploadPacketsPerSec      float64
	WanDownloadPacketsPerSec float64
	WanUploadPacketsPerSec   float64
	LanDownloadPacketsPerSec float64
	LanUploadPacketsPerSec   float64

	Protocols []ProtocolStats
	Peers     []PeerTrafficStat
}

type devByteCounts struct {
	wanDl uint64
	wanUl uint64
	lanDl uint64
	lanUl uint64
}

type devPacketCounts struct {
	wanDl uint64
	wanUl uint64
	lanDl uint64
	lanUl uint64
}

type Sampler struct {
	db              *DB
	ebpfCollector   *lanpilot.EbpfCollector
	arpCollector    *lanpilot.ArpCollector
	internetChecker *lanpilot.InternetChecker
	interval        time.Duration

	mu          sync.RWMutex
	liveRates   LiveRates
	deviceRates map[string]DeviceRate

	prevIngressBytes   uint64
	prevEgressBytes    uint64
	prevWanDlBytes     uint64
	prevWanUlBytes     uint64
	prevLanDlBytes     uint64
	prevLanUlBytes     uint64
	prevIngressPackets uint64
	prevEgressPackets  uint64
	prevWanDlPackets   uint64
	prevWanUlPackets   uint64
	prevLanDlPackets   uint64
	prevLanUlPackets   uint64
	prevTime           time.Time

	prevDeviceBytes   map[string]devByteCounts
	prevDevicePackets map[string]devPacketCounts
	prevDeviceProto   map[string]map[string]trafficStats
	prevDevicePeers   map[string]map[string]trafficStats

	lastDeviceUpsert time.Time
	knownDeviceState map[string]string
}

func normalizeProtocol(proto string) string {
	p := strings.ToUpper(strings.TrimSpace(proto))
	switch {
	case strings.Contains(p, "TCP"):
		return "TCP"
	case strings.Contains(p, "UDP"):
		return "UDP"
	case strings.Contains(p, "ICMP"):
		return "ICMP"
	case strings.Contains(p, "IGMP"):
		return "IGMP"
	case strings.Contains(p, "ESP"):
		return "ESP"
	case strings.Contains(p, "GRE"):
		return "GRE"
	default:
		if p == "" || p == "UNKNOWN" {
			return "OTHER"
		}
		return p
	}
}

func NewSampler(
	db *DB,
	ebpf *lanpilot.EbpfCollector,
	arp *lanpilot.ArpCollector,
	checker *lanpilot.InternetChecker,
	interval time.Duration,
) *Sampler {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	db.SetSampleInterval(interval)
	return &Sampler{
		db:                db,
		ebpfCollector:     ebpf,
		arpCollector:      arp,
		internetChecker:   checker,
		interval:          interval,
		deviceRates:       make(map[string]DeviceRate),
		prevDeviceBytes:   make(map[string]devByteCounts),
		prevDevicePackets: make(map[string]devPacketCounts),
		prevDeviceProto:   make(map[string]map[string]trafficStats),
		prevDevicePeers:   make(map[string]map[string]trafficStats),
		knownDeviceState:  make(map[string]string),
	}
}

func (s *Sampler) GetLiveRates() LiveRates {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.liveRates
}

func (s *Sampler) GetDeviceRates() map[string]DeviceRate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	res := make(map[string]DeviceRate, len(s.deviceRates))
	for k, v := range s.deviceRates {
		res[k] = v
	}
	return res
}

func (s *Sampler) SampleOnce() {
	now := time.Now()
	var samples []Sample

	// 1. Gather Traffic Stats
	flows := s.ebpfCollector.GetFlowStats()
	var curWanDlBytes, curWanUlBytes uint64
	var curLanDlBytes, curLanUlBytes uint64
	var curWanDlPackets, curWanUlPackets uint64
	var curLanDlPackets, curLanUlPackets uint64
	var curIngressPackets, curEgressPackets uint64
	curDeviceBytes := make(map[string]devByteCounts)
	curDevicePackets := make(map[string]devPacketCounts)
	curDeviceProto := make(map[string]map[string]trafficStats)
	curDevicePeers := make(map[string]map[string]trafficStats)

	addProto := func(ip, proto string, dlB, ulB, dlP, ulP uint64) {
		if ip == "" || ip == "internet" {
			return
		}
		m, ok := curDeviceProto[ip]
		if !ok {
			m = make(map[string]trafficStats)
			curDeviceProto[ip] = m
		}
		st := m[proto]
		st.dlBytes += dlB
		st.ulBytes += ulB
		st.dlPackets += dlP
		st.ulPackets += ulP
		m[proto] = st
	}

	addPeer := func(ip, peerIP string, sentB, rcvdB, sentP, rcvdP uint64) {
		if ip == "" || ip == "internet" || peerIP == "" || peerIP == "internet" || ip == peerIP {
			return
		}
		m, ok := curDevicePeers[ip]
		if !ok {
			m = make(map[string]trafficStats)
			curDevicePeers[ip] = m
		}
		st := m[peerIP]
		st.ulBytes += sentB
		st.dlBytes += rcvdB
		st.ulPackets += sentP
		st.dlPackets += rcvdP
		m[peerIP] = st
	}

	for _, f := range flows {
		if f.Direction == "ingress" {
			curIngressPackets += f.Packets
		} else if f.Direction == "egress" {
			curEgressPackets += f.Packets
		}

		proto := normalizeProtocol(f.IPProto)
		isLanToLan := f.SrcIP != "" && f.SrcIP != "internet" && f.DstIP != "" && f.DstIP != "internet"

		if isLanToLan {
			// Device-to-Device (LAN)
			curLanDlBytes += f.Bytes
			curLanUlBytes += f.Bytes
			curLanDlPackets += f.Packets
			curLanUlPackets += f.Packets

			sDevB := curDeviceBytes[f.SrcIP]
			sDevB.lanUl += f.Bytes
			curDeviceBytes[f.SrcIP] = sDevB

			dDevB := curDeviceBytes[f.DstIP]
			dDevB.lanDl += f.Bytes
			curDeviceBytes[f.DstIP] = dDevB

			sDevP := curDevicePackets[f.SrcIP]
			sDevP.lanUl += f.Packets
			curDevicePackets[f.SrcIP] = sDevP

			dDevP := curDevicePackets[f.DstIP]
			dDevP.lanDl += f.Packets
			curDevicePackets[f.DstIP] = dDevP

			// Track protocols for LAN devices
			addProto(f.SrcIP, proto, 0, f.Bytes, 0, f.Packets)
			addProto(f.DstIP, proto, f.Bytes, 0, f.Packets, 0)

			// Track peer communication
			addPeer(f.SrcIP, f.DstIP, f.Bytes, 0, f.Packets, 0)
			addPeer(f.DstIP, f.SrcIP, 0, f.Bytes, 0, f.Packets)
		} else if f.SrcIP != "" && f.SrcIP != "internet" && (f.DstIP == "internet" || f.DstIP == "") {
			// Device uploading to Internet (WAN Upload)
			curWanUlBytes += f.Bytes
			curWanUlPackets += f.Packets

			sDevB := curDeviceBytes[f.SrcIP]
			sDevB.wanUl += f.Bytes
			curDeviceBytes[f.SrcIP] = sDevB

			sDevP := curDevicePackets[f.SrcIP]
			sDevP.wanUl += f.Packets
			curDevicePackets[f.SrcIP] = sDevP

			addProto(f.SrcIP, proto, 0, f.Bytes, 0, f.Packets)
		} else if f.DstIP != "" && f.DstIP != "internet" && (f.SrcIP == "internet" || f.SrcIP == "") {
			// Device downloading from Internet (WAN Download)
			curWanDlBytes += f.Bytes
			curWanDlPackets += f.Packets

			dDevB := curDeviceBytes[f.DstIP]
			dDevB.wanDl += f.Bytes
			curDeviceBytes[f.DstIP] = dDevB

			dDevP := curDevicePackets[f.DstIP]
			dDevP.wanDl += f.Packets
			curDevicePackets[f.DstIP] = dDevP

			addProto(f.DstIP, proto, f.Bytes, 0, f.Packets, 0)
		}
	}

	curIngressBytes := curWanDlBytes + curLanDlBytes
	curEgressBytes := curWanUlBytes + curLanUlBytes

	var dlBytesRate, ulBytesRate, dlPktsRate, ulPktsRate float64
	var wanDlRate, wanUlRate, lanDlRate, lanUlRate float64
	var wanDlPktsRate, wanUlPktsRate, lanDlPktsRate, lanUlPktsRate float64
	var devSamples []Sample
	s.mu.Lock()
	if !s.prevTime.IsZero() {
		dt := now.Sub(s.prevTime).Seconds()
		if dt > 0 {
			if curWanDlBytes >= s.prevWanDlBytes {
				wanDlRate = float64(curWanDlBytes-s.prevWanDlBytes) / dt
			}
			if curWanUlBytes >= s.prevWanUlBytes {
				wanUlRate = float64(curWanUlBytes-s.prevWanUlBytes) / dt
			}
			if curLanDlBytes >= s.prevLanDlBytes {
				lanDlRate = float64(curLanDlBytes-s.prevLanDlBytes) / dt
			}
			if curLanUlBytes >= s.prevLanUlBytes {
				lanUlRate = float64(curLanUlBytes-s.prevLanUlBytes) / dt
			}
			dlBytesRate = wanDlRate + lanDlRate
			ulBytesRate = wanUlRate + lanUlRate

			if curIngressPackets >= s.prevIngressPackets {
				dlPktsRate = float64(curIngressPackets-s.prevIngressPackets) / dt
			}
			if curEgressPackets >= s.prevEgressPackets {
				ulPktsRate = float64(curEgressPackets-s.prevEgressPackets) / dt
			}
			if curWanDlPackets >= s.prevWanDlPackets {
				wanDlPktsRate = float64(curWanDlPackets-s.prevWanDlPackets) / dt
			}
			if curWanUlPackets >= s.prevWanUlPackets {
				wanUlPktsRate = float64(curWanUlPackets-s.prevWanUlPackets) / dt
			}
			if curLanDlPackets >= s.prevLanDlPackets {
				lanDlPktsRate = float64(curLanDlPackets-s.prevLanDlPackets) / dt
			}
			if curLanUlPackets >= s.prevLanUlPackets {
				lanUlPktsRate = float64(curLanUlPackets-s.prevLanUlPackets) / dt
			}

			// Calculate per-device rates
			curDevRates := make(map[string]DeviceRate)
			allIPs := make(map[string]struct{})
			for ip := range curDeviceBytes {
				allIPs[ip] = struct{}{}
			}
			for ip := range s.prevDeviceBytes {
				allIPs[ip] = struct{}{}
			}

			for ip := range allIPs {
				curB := curDeviceBytes[ip]
				prevB := s.prevDeviceBytes[ip]
				var dWanDl, dWanUl, dLanDl, dLanUl float64
				if curB.wanDl >= prevB.wanDl {
					dWanDl = float64(curB.wanDl-prevB.wanDl) / dt
				}
				if curB.wanUl >= prevB.wanUl {
					dWanUl = float64(curB.wanUl-prevB.wanUl) / dt
				}
				if curB.lanDl >= prevB.lanDl {
					dLanDl = float64(curB.lanDl-prevB.lanDl) / dt
				}
				if curB.lanUl >= prevB.lanUl {
					dLanUl = float64(curB.lanUl-prevB.lanUl) / dt
				}

				curP := curDevicePackets[ip]
				prevP := s.prevDevicePackets[ip]
				var dWanDlP, dWanUlP, dLanDlP, dLanUlP float64
				if curP.wanDl >= prevP.wanDl {
					dWanDlP = float64(curP.wanDl-prevP.wanDl) / dt
				}
				if curP.wanUl >= prevP.wanUl {
					dWanUlP = float64(curP.wanUl-prevP.wanUl) / dt
				}
				if curP.lanDl >= prevP.lanDl {
					dLanDlP = float64(curP.lanDl-prevP.lanDl) / dt
				}
				if curP.lanUl >= prevP.lanUl {
					dLanUlP = float64(curP.lanUl-prevP.lanUl) / dt
				}

				devDlRate := dWanDl + dLanDl
				devUlRate := dWanUl + dLanUl
				devDlPktsRate := dWanDlP + dLanDlP
				devUlPktsRate := dWanUlP + dLanUlP

				// Compute protocol rates & cumulative stats
				curProtMap := curDeviceProto[ip]
				prevProtMap := s.prevDeviceProto[ip]
				var protoStatsList []ProtocolStats
				for pName, curP := range curProtMap {
					prevP := prevProtMap[pName]
					var dlBRate, ulBRate, dlPRate, ulPRate float64
					if curP.dlBytes >= prevP.dlBytes {
						dlBRate = float64(curP.dlBytes-prevP.dlBytes) / dt
					}
					if curP.ulBytes >= prevP.ulBytes {
						ulBRate = float64(curP.ulBytes-prevP.ulBytes) / dt
					}
					if curP.dlPackets >= prevP.dlPackets {
						dlPRate = float64(curP.dlPackets-prevP.dlPackets) / dt
					}
					if curP.ulPackets >= prevP.ulPackets {
						ulPRate = float64(curP.ulPackets-prevP.ulPackets) / dt
					}
					protoStatsList = append(protoStatsList, ProtocolStats{
						Protocol:              pName,
						DownloadBytes:         curP.dlBytes,
						UploadBytes:           curP.ulBytes,
						DownloadPackets:       curP.dlPackets,
						UploadPackets:         curP.ulPackets,
						DownloadBytesPerSec:   dlBRate,
						UploadBytesPerSec:     ulBRate,
						DownloadPacketsPerSec: dlPRate,
						UploadPacketsPerSec:   ulPRate,
					})
				}
				sort.Slice(protoStatsList, func(a, b int) bool {
					return (protoStatsList[a].DownloadBytes + protoStatsList[a].UploadBytes) > (protoStatsList[b].DownloadBytes + protoStatsList[b].UploadBytes)
				})

				// Compute peer rates & cumulative stats
				curPeerMap := curDevicePeers[ip]
				prevPeerMap := s.prevDevicePeers[ip]
				var peerStatsList []PeerTrafficStat
				for peerIP, curPeer := range curPeerMap {
					prevPeer := prevPeerMap[peerIP]
					var sentBRate, rcvdBRate, sentPRate, rcvdPRate float64
					if curPeer.ulBytes >= prevPeer.ulBytes {
						sentBRate = float64(curPeer.ulBytes-prevPeer.ulBytes) / dt
					}
					if curPeer.dlBytes >= prevPeer.dlBytes {
						rcvdBRate = float64(curPeer.dlBytes-prevPeer.dlBytes) / dt
					}
					if curPeer.ulPackets >= prevPeer.ulPackets {
						sentPRate = float64(curPeer.ulPackets-prevPeer.ulPackets) / dt
					}
					if curPeer.dlPackets >= prevPeer.dlPackets {
						rcvdPRate = float64(curPeer.dlPackets-prevPeer.dlPackets) / dt
					}
					peerStatsList = append(peerStatsList, PeerTrafficStat{
						IPAddr:                peerIP,
						BytesSent:             curPeer.ulBytes,
						BytesReceived:         curPeer.dlBytes,
						PacketsSent:           curPeer.ulPackets,
						PacketsReceived:       curPeer.dlPackets,
						UploadBytesPerSec:     sentBRate,
						DownloadBytesPerSec:   rcvdBRate,
						UploadPacketsPerSec:   sentPRate,
						DownloadPacketsPerSec: rcvdPRate,
					})
				}
				sort.Slice(peerStatsList, func(a, b int) bool {
					return (peerStatsList[a].BytesSent + peerStatsList[a].BytesReceived) > (peerStatsList[b].BytesSent + peerStatsList[b].BytesReceived)
				})

				prevRate := s.deviceRates[ip]
				if devDlRate > 0 || devUlRate > 0 || devDlPktsRate > 0 || devUlPktsRate > 0 || prevRate.DownloadBytesPerSec > 0 || prevRate.UploadBytesPerSec > 0 || len(protoStatsList) > 0 || len(peerStatsList) > 0 {
					curDevRates[ip] = DeviceRate{
						DownloadBytesPerSec:      devDlRate,
						UploadBytesPerSec:        devUlRate,
						WanDownloadBytesPerSec:   dWanDl,
						WanUploadBytesPerSec:     dWanUl,
						LanDownloadBytesPerSec:   dLanDl,
						LanUploadBytesPerSec:     dLanUl,
						DownloadPacketsPerSec:    devDlPktsRate,
						UploadPacketsPerSec:      devUlPktsRate,
						WanDownloadPacketsPerSec: dWanDlP,
						WanUploadPacketsPerSec:   dWanUlP,
						LanDownloadPacketsPerSec: dLanDlP,
						LanUploadPacketsPerSec:   dLanUlP,
						Protocols:                protoStatsList,
						Peers:                    peerStatsList,
					}
					if devDlRate > 0 || prevRate.DownloadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_traffic_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "ingress"},
							Timestamp: now,
							Value:     devDlRate,
						})
					}
					if devUlRate > 0 || prevRate.UploadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_traffic_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "egress"},
							Timestamp: now,
							Value:     devUlRate,
						})
					}
					if dWanDl > 0 || prevRate.WanDownloadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_wan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "ingress"},
							Timestamp: now,
							Value:     dWanDl,
						})
					}
					if dWanUl > 0 || prevRate.WanUploadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_wan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "egress"},
							Timestamp: now,
							Value:     dWanUl,
						})
					}
					if dLanDl > 0 || prevRate.LanDownloadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_lan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "ingress"},
							Timestamp: now,
							Value:     dLanDl,
						})
					}
					if dLanUl > 0 || prevRate.LanUploadBytesPerSec > 0 {
						devSamples = append(devSamples, Sample{
							Metric:    "device_lan_bytes_rate",
							Labels:    map[string]string{"ip": ip, "direction": "egress"},
							Timestamp: now,
							Value:     dLanUl,
						})
					}
					for _, proto := range protoStatsList {
						if proto.DownloadBytesPerSec > 0 {
							devSamples = append(devSamples, Sample{
								Metric:    "device_protocol_bytes_rate",
								Labels:    map[string]string{"ip": ip, "protocol": proto.Protocol, "direction": "ingress"},
								Timestamp: now,
								Value:     proto.DownloadBytesPerSec,
							})
						}
						if proto.UploadBytesPerSec > 0 {
							devSamples = append(devSamples, Sample{
								Metric:    "device_protocol_bytes_rate",
								Labels:    map[string]string{"ip": ip, "protocol": proto.Protocol, "direction": "egress"},
								Timestamp: now,
								Value:     proto.UploadBytesPerSec,
							})
						}
					}
					for _, peer := range peerStatsList {
						if peer.DownloadBytesPerSec > 0 {
							devSamples = append(devSamples, Sample{
								Metric:    "device_peer_bytes_rate",
								Labels:    map[string]string{"ip": ip, "peer_ip": peer.IPAddr, "direction": "ingress"},
								Timestamp: now,
								Value:     peer.DownloadBytesPerSec,
							})
						}
						if peer.UploadBytesPerSec > 0 {
							devSamples = append(devSamples, Sample{
								Metric:    "device_peer_bytes_rate",
								Labels:    map[string]string{"ip": ip, "peer_ip": peer.IPAddr, "direction": "egress"},
								Timestamp: now,
								Value:     peer.UploadBytesPerSec,
							})
						}
					}
				}
			}
			s.deviceRates = curDevRates
		}
	}
	s.prevDeviceBytes = curDeviceBytes
	s.prevDevicePackets = curDevicePackets
	s.prevDeviceProto = curDeviceProto
	s.prevDevicePeers = curDevicePeers
	s.prevWanDlBytes = curWanDlBytes
	s.prevWanUlBytes = curWanUlBytes
	s.prevLanDlBytes = curLanDlBytes
	s.prevLanUlBytes = curLanUlBytes
	s.prevIngressBytes = curIngressBytes
	s.prevEgressBytes = curEgressBytes
	s.prevWanDlPackets = curWanDlPackets
	s.prevWanUlPackets = curWanUlPackets
	s.prevLanDlPackets = curLanDlPackets
	s.prevLanUlPackets = curLanUlPackets
	s.prevIngressPackets = curIngressPackets
	s.prevEgressPackets = curEgressPackets
	s.prevTime = now
	s.mu.Unlock()

	samples = append(samples,
		Sample{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: dlBytesRate},
		Sample{Metric: "traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: ulBytesRate},
		Sample{Metric: "traffic_packets_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: dlPktsRate},
		Sample{Metric: "traffic_packets_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: ulPktsRate},
		Sample{Metric: "wan_traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: wanDlRate},
		Sample{Metric: "wan_traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: wanUlRate},
		Sample{Metric: "wan_traffic_packets_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: wanDlPktsRate},
		Sample{Metric: "wan_traffic_packets_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: wanUlPktsRate},
		Sample{Metric: "lan_traffic_bytes_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: lanDlRate},
		Sample{Metric: "lan_traffic_bytes_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: lanUlRate},
		Sample{Metric: "lan_traffic_packets_rate", Labels: map[string]string{"direction": "ingress"}, Timestamp: now, Value: lanDlPktsRate},
		Sample{Metric: "lan_traffic_packets_rate", Labels: map[string]string{"direction": "egress"}, Timestamp: now, Value: lanUlPktsRate},
	)
	samples = append(samples, devSamples...)

	// 2. Gather Internet Check Stats
	health := s.internetChecker.GetOverallHealth()

	// 3. Gather Devices
	devices := s.arpCollector.GetDevices()
	var validDevices int32
	var devicesToUpsert []PersistedDevice
	needsPeriodicRefresh := now.Sub(s.lastDeviceUpsert) >= 5*time.Minute

	for _, d := range devices {
		if d.IsValid {
			validDevices++
		}
		if d.HWAddr != "" && d.HWAddr != "00:00:00:00:00:00" && (d.Flag&2 != 0 || d.Flag&4 != 0) {
			stateSig := d.IPAddr + "|" + d.Device
			if needsPeriodicRefresh || s.knownDeviceState[d.HWAddr] != stateSig {
				s.knownDeviceState[d.HWAddr] = stateSig
				devicesToUpsert = append(devicesToUpsert, PersistedDevice{
					HWAddr:    d.HWAddr,
					IPAddr:    d.IPAddr,
					Device:    d.Device,
					FirstSeen: now,
					LastSeen:  now,
				})
			}
		}
	}

	if len(devicesToUpsert) > 0 {
		if err := s.db.UpsertDevices(devicesToUpsert); err != nil {
			log.Printf("error upserting devices to tsdb: %v", err)
		} else {
			s.lastDeviceUpsert = now
		}
	}

	samples = append(samples,
		Sample{Metric: "connected_devices_count", Labels: map[string]string{}, Timestamp: now, Value: float64(validDevices)},
	)

	// Update LiveRates cache
	s.mu.Lock()
	s.liveRates = LiveRates{
		DownloadBytesPerSec:      dlBytesRate,
		UploadBytesPerSec:        ulBytesRate,
		DownloadPacketsPerSec:    dlPktsRate,
		UploadPacketsPerSec:      ulPktsRate,
		TotalDownloadBytes:       curIngressBytes,
		TotalUploadBytes:         curEgressBytes,
		InternetIsUp:             health.IsUp,
		InternetStatus:           health.Status,
		InternetLatencySeconds:   health.LatencySeconds,
		InternetPacketLossRatio:  health.PacketLossRatio,
		InternetJitterSeconds:    health.JitterSeconds,
		ConnectedDevicesCount:    validDevices,
		LastSampleTime:           now,
		WanDownloadBytesPerSec:   wanDlRate,
		WanUploadBytesPerSec:     wanUlRate,
		LanDownloadBytesPerSec:   lanDlRate,
		LanUploadBytesPerSec:     lanUlRate,
		WanDownloadPacketsPerSec: wanDlPktsRate,
		WanUploadPacketsPerSec:   wanUlPktsRate,
		LanDownloadPacketsPerSec: lanDlPktsRate,
		LanUploadPacketsPerSec:   lanUlPktsRate,
		TotalWanDownloadBytes:    curWanDlBytes,
		TotalWanUploadBytes:      curWanUlBytes,
		TotalLanDownloadBytes:    curLanDlBytes,
		TotalLanUploadBytes:      curLanUlBytes,
		TotalWanDownloadPackets:  curWanDlPackets,
		TotalWanUploadPackets:    curWanUlPackets,
		TotalLanDownloadPackets:  curLanDlPackets,
		TotalLanUploadPackets:    curLanUlPackets,
	}
	s.mu.Unlock()

	// Write batch to SQLite TSDB
	if err := s.db.InsertSamples(samples); err != nil {
		log.Printf("error inserting metric samples to tsdb: %v", err)
	}
}

func (s *Sampler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	// Sample immediately on start
	go s.SampleOnce()

	go func() {
		for {
			select {
			case <-ticker.C:
				s.SampleOnce()
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}
