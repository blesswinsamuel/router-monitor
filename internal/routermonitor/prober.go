package routermonitor

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type ProbeType string

const (
	ProbeICMP ProbeType = "icmp"
	ProbeDNS  ProbeType = "dns"
	ProbeHTTP ProbeType = "http"
	ProbeTCP  ProbeType = "tcp"
)

type TargetConfig struct {
	Name   string    `json:"name"`
	Target string    `json:"target"`
	Type   ProbeType `json:"type"`
}

type ProbeResult struct {
	Target          TargetConfig
	IsUp            bool
	Latency         time.Duration
	MinLatency      time.Duration
	MaxLatency      time.Duration
	AvgLatency      time.Duration
	Jitter          time.Duration
	PacketLossRatio float64
	LastError       string
	Timestamp       time.Time
}

// TargetState maintains rolling historical performance for a specific probe target.
type TargetState struct {
	Config          TargetConfig
	IsUp            bool
	LastLatency     time.Duration
	MinLatency      time.Duration
	MaxLatency      time.Duration
	AvgLatency      time.Duration
	Jitter          time.Duration
	PacketLossRatio float64
	LastError       string
	LastChecked     time.Time

	prevRTT   time.Duration
	latencies []time.Duration
	mu        sync.RWMutex
}

func NewTargetState(cfg TargetConfig) *TargetState {
	return &TargetState{
		Config: cfg,
	}
}

func (ts *TargetState) Update(res ProbeResult) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	ts.IsUp = res.IsUp
	ts.LastLatency = res.Latency
	ts.MinLatency = res.MinLatency
	ts.MaxLatency = res.MaxLatency
	ts.AvgLatency = res.AvgLatency
	ts.Jitter = res.Jitter
	ts.PacketLossRatio = res.PacketLossRatio
	ts.LastError = res.LastError
	ts.LastChecked = res.Timestamp

	if res.IsUp && res.Latency > 0 {
		ts.latencies = append(ts.latencies, res.Latency)
		if len(ts.latencies) > 20 {
			ts.latencies = ts.latencies[len(ts.latencies)-20:]
		}
	}
}

func (ts *TargetState) Snapshot() ProbeResult {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	return ProbeResult{
		Target:          ts.Config,
		IsUp:            ts.IsUp,
		Latency:         ts.LastLatency,
		MinLatency:      ts.MinLatency,
		MaxLatency:      ts.MaxLatency,
		AvgLatency:      ts.AvgLatency,
		Jitter:          ts.Jitter,
		PacketLossRatio: ts.PacketLossRatio,
		LastError:       ts.LastError,
		Timestamp:       ts.LastChecked,
	}
}

// computeICMPChecksum computes the 16-bit one's complement checksum.
func computeICMPChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for (sum >> 16) > 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// probeICMP performs a 3-packet ICMP Echo probe via raw socket net.ListenPacket("ip4:icmp", ...).
func probeICMP(ctx context.Context, host string, timeout time.Duration) ProbeResult {
	now := time.Now()
	res := ProbeResult{
		Target:    TargetConfig{Target: host, Type: ProbeICMP},
		Timestamp: now,
	}

	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		res.LastError = err.Error()
		res.PacketLossRatio = 1.0
		return res
	}

	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		// If raw socket cannot be created (e.g. permission denied outside router),
		// fall back to a TCP connect probe if target has a known port or port 53.
		return probeTCPFallback(ctx, host, timeout)
	}
	defer conn.Close()

	const count = 3
	perPacketTimeout := timeout / count
	if perPacketTimeout < 200*time.Millisecond {
		perPacketTimeout = 200 * time.Millisecond
	}

	var rtts []time.Duration
	pid := os.Getpid() & 0xffff
	id := uint16(pid ^ int(rand.Int32()&0xffff))

	for seq := uint16(1); seq <= count; seq++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		pkt := make([]byte, 64)
		pkt[0] = 8 // ICMP Echo Request
		pkt[1] = 0 // Code 0
		pkt[2] = 0 // Checksum high byte
		pkt[3] = 0 // Checksum low byte
		binary.BigEndian.PutUint16(pkt[4:6], id)
		binary.BigEndian.PutUint16(pkt[6:8], seq)
		binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Now().UnixNano()))

		csum := computeICMPChecksum(pkt)
		binary.BigEndian.PutUint16(pkt[2:4], csum)

		t0 := time.Now()
		_ = conn.SetDeadline(t0.Add(perPacketTimeout))

		if _, err := conn.WriteTo(pkt, ipAddr); err != nil {
			continue
		}

		replyBuf := make([]byte, 256)
		for {
			n, peer, err := conn.ReadFrom(replyBuf)
			if err != nil {
				break
			}
			rtt := time.Since(t0)

			// ICMP packet could start after IPv4 header or directly depending on socket type.
			icmpPkt := replyBuf[:n]
			if n >= 20 && icmpPkt[0] == 0x45 {
				// Has 20-byte IP header
				icmpPkt = icmpPkt[20:]
			}
			if len(icmpPkt) < 8 {
				continue
			}

			// Check if it is Echo Reply (Type 0, Code 0)
			if icmpPkt[0] == 0 && icmpPkt[1] == 0 {
				replyID := binary.BigEndian.Uint16(icmpPkt[4:6])
				replySeq := binary.BigEndian.Uint16(icmpPkt[6:8])
				if replyID == id && replySeq == seq {
					_ = peer
					rtts = append(rtts, rtt)
					break
				}
			}
		}
	}

	packetsReceived := len(rtts)
	res.PacketLossRatio = float64(count-packetsReceived) / float64(count)

	if packetsReceived == 0 {
		res.LastError = "100% packet loss (timeout)"
		return res
	}

	res.IsUp = true
	var sum time.Duration
	res.MinLatency = rtts[0]
	res.MaxLatency = rtts[0]
	for _, d := range rtts {
		sum += d
		if d < res.MinLatency {
			res.MinLatency = d
		}
		if d > res.MaxLatency {
			res.MaxLatency = d
		}
	}
	res.AvgLatency = sum / time.Duration(packetsReceived)
	res.Latency = rtts[packetsReceived-1]

	// RFC 3550 jitter approximation across consecutive packets
	if packetsReceived > 1 {
		var jitterSum float64
		for i := 1; i < packetsReceived; i++ {
			diff := math.Abs(float64(rtts[i].Nanoseconds() - rtts[i-1].Nanoseconds()))
			jitterSum += diff
		}
		res.Jitter = time.Duration(jitterSum / float64(packetsReceived-1))
	}

	return res
}

func probeTCPFallback(ctx context.Context, host string, timeout time.Duration) ProbeResult {
	now := time.Now()
	res := ProbeResult{
		Target:    TargetConfig{Target: host, Type: ProbeICMP},
		Timestamp: now,
	}

	targetAddr := host
	if !strings.Contains(targetAddr, ":") {
		targetAddr = net.JoinHostPort(targetAddr, "53")
	}

	t0 := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		res.LastError = err.Error()
		res.PacketLossRatio = 1.0
		return res
	}
	_ = conn.Close()
	rtt := time.Since(t0)

	res.IsUp = true
	res.Latency = rtt
	res.MinLatency = rtt
	res.MaxLatency = rtt
	res.AvgLatency = rtt
	res.PacketLossRatio = 0.0
	return res
}

// probeDNS performs domain resolution using net.Resolver.
// target format: "domain" or "domain@dns-server:port" (e.g. "cloudflare.com@1.1.1.1:53")
func probeDNS(ctx context.Context, target string, timeout time.Duration) ProbeResult {
	now := time.Now()
	res := ProbeResult{
		Target:    TargetConfig{Target: target, Type: ProbeDNS},
		Timestamp: now,
	}

	domain := target
	dnsServer := ""
	if strings.Contains(target, "@") {
		parts := strings.SplitN(target, "@", 2)
		domain = parts[0]
		dnsServer = parts[1]
		if !strings.Contains(dnsServer, ":") {
			dnsServer = net.JoinHostPort(dnsServer, "53")
		}
	}

	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	resolver := net.DefaultResolver
	if dnsServer != "" {
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", dnsServer)
			},
		}
	}

	t0 := time.Now()
	ips, err := resolver.LookupIP(lookupCtx, "ip4", domain)
	rtt := time.Since(t0)

	if err != nil || len(ips) == 0 {
		errMsg := "lookup failed"
		if err != nil {
			errMsg = err.Error()
		}
		res.LastError = errMsg
		res.PacketLossRatio = 1.0
		return res
	}

	res.IsUp = true
	res.Latency = rtt
	res.MinLatency = rtt
	res.MaxLatency = rtt
	res.AvgLatency = rtt
	res.PacketLossRatio = 0.0
	return res
}

// probeHTTP performs a lightweight GET request checking for 204 or 200.
func probeHTTP(ctx context.Context, urlStr string, timeout time.Duration) ProbeResult {
	now := time.Now()
	res := ProbeResult{
		Target:    TargetConfig{Target: urlStr, Type: ProbeHTTP},
		Timestamp: now,
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, urlStr, nil)
	if err != nil {
		res.LastError = err.Error()
		res.PacketLossRatio = 1.0
		return res
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Do not follow redirects (captive portal detection)
			return errors.New("redirect detected (possible captive portal)")
		},
	}

	t0 := time.Now()
	resp, err := client.Do(req)
	rtt := time.Since(t0)

	if err != nil {
		res.LastError = err.Error()
		res.PacketLossRatio = 1.0
		return res
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		res.LastError = fmt.Sprintf("HTTP %d unexpected status", resp.StatusCode)
		res.PacketLossRatio = 1.0
		return res
	}

	res.IsUp = true
	res.Latency = rtt
	res.MinLatency = rtt
	res.MaxLatency = rtt
	res.AvgLatency = rtt
	res.PacketLossRatio = 0.0
	return res
}

// probeTCP performs a standard TCP handshake to host:port.
func probeTCP(ctx context.Context, addr string, timeout time.Duration) ProbeResult {
	now := time.Now()
	res := ProbeResult{
		Target:    TargetConfig{Target: addr, Type: ProbeTCP},
		Timestamp: now,
	}

	t0 := time.Now()
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	rtt := time.Since(t0)

	if err != nil {
		res.LastError = err.Error()
		res.PacketLossRatio = 1.0
		return res
	}
	defer conn.Close()

	res.IsUp = true
	res.Latency = rtt
	res.MinLatency = rtt
	res.MaxLatency = rtt
	res.AvgLatency = rtt
	res.PacketLossRatio = 0.0
	return res
}

// RunProbe executes the appropriate probe based on target configuration.
func RunProbe(ctx context.Context, cfg TargetConfig, timeout time.Duration) ProbeResult {
	switch cfg.Type {
	case ProbeICMP:
		return probeICMP(ctx, cfg.Target, timeout)
	case ProbeDNS:
		return probeDNS(ctx, cfg.Target, timeout)
	case ProbeHTTP:
		return probeHTTP(ctx, cfg.Target, timeout)
	case ProbeTCP:
		return probeTCP(ctx, cfg.Target, timeout)
	default:
		// Auto-detect based on format
		if strings.HasPrefix(cfg.Target, "http://") || strings.HasPrefix(cfg.Target, "https://") {
			return probeHTTP(ctx, cfg.Target, timeout)
		}
		if strings.Contains(cfg.Target, ":") {
			return probeTCP(ctx, cfg.Target, timeout)
		}
		return probeICMP(ctx, cfg.Target, timeout)
	}
}

type PingStats struct {
	IsReachable      bool
	PacketLossRatio  float64
	MinLatency       time.Duration
	AvgLatency       time.Duration
	MaxLatency       time.Duration
	Jitter           time.Duration
	RoundTripTimesMS []float64
	LastError        string
}

func PingHost(ctx context.Context, host string, count int, timeout time.Duration) PingStats {
	if count <= 0 {
		count = 4
	}
	if count > 10 {
		count = 10
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	ipAddr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return PingStats{
			PacketLossRatio: 1.0,
			LastError:       err.Error(),
		}
	}

	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return PingStats{
			PacketLossRatio: 1.0,
			LastError:       fmt.Sprintf("raw icmp socket error: %v", err),
		}
	}
	defer conn.Close()

	perPacketTimeout := timeout / time.Duration(count)
	if perPacketTimeout < 150*time.Millisecond {
		perPacketTimeout = 150 * time.Millisecond
	}

	var rtts []time.Duration
	var rttsMS []float64
	pid := os.Getpid() & 0xffff
	id := uint16(pid ^ int(rand.Int32()&0xffff))

	for seq := uint16(1); seq <= uint16(count); seq++ {
		select {
		case <-ctx.Done():
			break
		default:
		}

		pkt := make([]byte, 64)
		pkt[0] = 8 // ICMP Echo Request
		pkt[1] = 0 // Code 0
		pkt[2] = 0 // Checksum high byte
		pkt[3] = 0 // Checksum low byte
		binary.BigEndian.PutUint16(pkt[4:6], id)
		binary.BigEndian.PutUint16(pkt[6:8], seq)
		binary.BigEndian.PutUint64(pkt[8:16], uint64(time.Now().UnixNano()))

		csum := computeICMPChecksum(pkt)
		binary.BigEndian.PutUint16(pkt[2:4], csum)

		t0 := time.Now()
		_ = conn.SetDeadline(t0.Add(perPacketTimeout))

		if _, err := conn.WriteTo(pkt, ipAddr); err != nil {
			rttsMS = append(rttsMS, -1.0)
			continue
		}

		replyBuf := make([]byte, 256)
		received := false
		for {
			n, _, err := conn.ReadFrom(replyBuf)
			if err != nil {
				break
			}
			rtt := time.Since(t0)

			icmpPkt := replyBuf[:n]
			if n >= 20 && icmpPkt[0] == 0x45 {
				icmpPkt = icmpPkt[20:]
			}
			if len(icmpPkt) < 8 {
				continue
			}

			if icmpPkt[0] == 0 && icmpPkt[1] == 0 {
				replyID := binary.BigEndian.Uint16(icmpPkt[4:6])
				replySeq := binary.BigEndian.Uint16(icmpPkt[6:8])
				if replyID == id && replySeq == seq {
					rtts = append(rtts, rtt)
					rttsMS = append(rttsMS, float64(rtt.Microseconds())/1000.0)
					received = true
					break
				}
			}
		}

		if !received {
			rttsMS = append(rttsMS, -1.0)
		}
	}

	packetsReceived := len(rtts)
	lossRatio := float64(count-packetsReceived) / float64(count)

	if packetsReceived == 0 {
		return PingStats{
			PacketLossRatio:  1.0,
			RoundTripTimesMS: rttsMS,
			LastError:        "100% packet loss (host unreachable or timeout)",
		}
	}

	minLat := rtts[0]
	maxLat := rtts[0]
	var sumLat time.Duration
	for _, d := range rtts {
		sumLat += d
		if d < minLat {
			minLat = d
		}
		if d > maxLat {
			maxLat = d
		}
	}
	avgLat := sumLat / time.Duration(packetsReceived)

	var jitter time.Duration
	if packetsReceived > 1 {
		var jitterSum float64
		for i := 1; i < packetsReceived; i++ {
			diff := math.Abs(float64(rtts[i].Nanoseconds() - rtts[i-1].Nanoseconds()))
			jitterSum += diff
		}
		jitter = time.Duration(jitterSum / float64(packetsReceived-1))
	}

	return PingStats{
		IsReachable:      true,
		PacketLossRatio:  lossRatio,
		MinLatency:       minLat,
		AvgLatency:       avgLat,
		MaxLatency:       maxLat,
		Jitter:           jitter,
		RoundTripTimesMS: rttsMS,
	}
}

