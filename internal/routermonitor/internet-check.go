package routermonitor

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type OutageStore interface {
	RecordOutageStart(status, reason string, startTime time.Time) (int64, error)
	RecordOutageEnd(id int64, endTime time.Time) error
}

type MetricSample struct {
	Metric    string
	Labels    map[string]string
	Timestamp time.Time
	Value     float64
}

type OverallHealth struct {
	Status          string // "operational", "degraded", "down"
	IsUp            bool
	LatencySeconds  float64
	PacketLossRatio float64
	JitterSeconds   float64
	LastChecked     time.Time
}

type InternetChecker struct {
	interval    time.Duration
	timeout     time.Duration
	targets     []*TargetState
	outageStore OutageStore
	sampleSink  func([]MetricSample)

	statusMu        sync.RWMutex
	overall         OverallHealth
	currentOutageID int64
	currentStatus   string

	internetStatus          prometheus.Gauge
	internetLatencyGauge    *prometheus.GaugeVec
	internetPacketLossGauge *prometheus.GaugeVec
	internetJitterGauge     *prometheus.GaugeVec
}

var DefaultTargets = []TargetConfig{
	{Name: "Cloudflare (1.1.1.1)", Target: "1.1.1.1", Type: ProbeICMP},
	{Name: "Google (8.8.8.8)", Target: "8.8.8.8", Type: ProbeICMP},
	{Name: "Quad9 (9.9.9.9)", Target: "9.9.9.9", Type: ProbeICMP},
	{Name: "DNS (cloudflare.com)", Target: "cloudflare.com", Type: ProbeDNS},
	{Name: "HTTP (Cloudflare 204)", Target: "http://cp.cloudflare.com/generate_204", Type: ProbeHTTP},
}

// ParseTargetConfigs parses comma-separated target definitions, e.g.:
// "icmp:1.1.1.1,dns:google.com,http:http://cp.cloudflare.com/generate_204"
func ParseTargetConfigs(raw string) ([]TargetConfig, error) {
	if strings.TrimSpace(raw) == "" {
		return append([]TargetConfig(nil), DefaultTargets...), nil
	}

	parts := strings.Split(raw, ",")
	var configs []TargetConfig
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}

		var cfg TargetConfig
		if strings.HasPrefix(item, "icmp:") {
			cfg.Type = ProbeICMP
			cfg.Target = strings.TrimPrefix(item, "icmp:")
			cfg.Name = "ICMP (" + cfg.Target + ")"
		} else if strings.HasPrefix(item, "dns:") {
			cfg.Type = ProbeDNS
			cfg.Target = strings.TrimPrefix(item, "dns:")
			cfg.Name = "DNS (" + cfg.Target + ")"
		} else if strings.HasPrefix(item, "http:") || strings.HasPrefix(item, "https:") {
			cfg.Type = ProbeHTTP
			cfg.Target = item
			if strings.HasPrefix(item, "http:http://") || strings.HasPrefix(item, "http:https://") {
				cfg.Target = strings.TrimPrefix(item, "http:")
			}
			cfg.Name = "HTTP (" + cfg.Target + ")"
		} else if strings.HasPrefix(item, "tcp:") {
			cfg.Type = ProbeTCP
			cfg.Target = strings.TrimPrefix(item, "tcp:")
			cfg.Name = "TCP (" + cfg.Target + ")"
		} else if strings.Contains(item, ":") {
			cfg.Type = ProbeTCP
			cfg.Target = item
			cfg.Name = "TCP (" + item + ")"
		} else {
			cfg.Type = ProbeICMP
			cfg.Target = item
			cfg.Name = "ICMP (" + item + ")"
		}

		configs = append(configs, cfg)
	}

	if len(configs) == 0 {
		return append([]TargetConfig(nil), DefaultTargets...), nil
	}
	return configs, nil
}

func NewInternetChecker(interval time.Duration, targets []TargetConfig, store OutageStore) *InternetChecker {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if len(targets) == 0 {
		targets = DefaultTargets
	}

	targetStates := make([]*TargetState, len(targets))
	for i, cfg := range targets {
		targetStates[i] = NewTargetState(cfg)
	}

	checker := &InternetChecker{
		interval:      interval,
		timeout:       2 * time.Second,
		targets:       targetStates,
		outageStore:   store,
		currentStatus: "operational",
		overall: OverallHealth{
			Status: "operational",
			IsUp:   true,
		},
		internetStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "router_monitor_internet_status",
			Help: "Internet connectivity state (1 = operational, 0.5 = degraded, 0 = down).",
		}),
		internetLatencyGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "router_monitor_internet_latency_seconds",
			Help: "Round-trip latency in seconds per probe target.",
		}, []string{"target", "type"}),
		internetPacketLossGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "router_monitor_internet_packet_loss_ratio",
			Help: "Packet loss ratio (0.0 - 1.0) per probe target.",
		}, []string{"target", "type"}),
		internetJitterGauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "router_monitor_internet_jitter_seconds",
			Help: "Interarrival jitter in seconds per probe target.",
		}, []string{"target", "type"}),
	}

	checker.internetStatus.Set(1.0)
	return checker
}

func (c *InternetChecker) SetOutageStore(store OutageStore) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.outageStore = store
}

func (c *InternetChecker) SetSampleSink(sink func([]MetricSample)) {
	c.statusMu.Lock()
	defer c.statusMu.Unlock()
	c.sampleSink = sink
}

func (c *InternetChecker) Register(registry prometheus.Registerer) {
	registry.MustRegister(c.internetStatus)
	registry.MustRegister(c.internetLatencyGauge)
	registry.MustRegister(c.internetPacketLossGauge)
	registry.MustRegister(c.internetJitterGauge)
}

func (c *InternetChecker) GetOverallHealth() OverallHealth {
	c.statusMu.RLock()
	defer c.statusMu.RUnlock()
	return c.overall
}

func (c *InternetChecker) GetTargetResults() []ProbeResult {
	c.statusMu.RLock()
	defer c.statusMu.RUnlock()

	results := make([]ProbeResult, len(c.targets))
	for i, t := range c.targets {
		results[i] = t.Snapshot()
	}
	return results
}

func (c *InternetChecker) CheckOnce(ctx context.Context) {
	var wg sync.WaitGroup
	results := make([]ProbeResult, len(c.targets))

	for i, ts := range c.targets {
		wg.Add(1)
		go func(idx int, target TargetConfig) {
			defer wg.Done()
			results[idx] = RunProbe(ctx, target, c.timeout)
		}(i, ts.Config)
	}
	wg.Wait()

	now := time.Now()
	var totalLoss float64
	var latencySum float64
	var latencyCount int
	var jitterSum float64
	var jitterCount int
	upCount := 0
	totalTargets := len(results)

	var samples []MetricSample

	for i, res := range results {
		c.targets[i].Update(res)

		totalLoss += res.PacketLossRatio
		if res.IsUp {
			upCount++
			if res.Latency > 0 {
				latencySum += res.Latency.Seconds()
				latencyCount++
			}
			if res.Jitter > 0 {
				jitterSum += res.Jitter.Seconds()
				jitterCount++
			}
		}

		targetLabel := res.Target.Target
		typeLabel := string(res.Target.Type)

		latSec := res.Latency.Seconds()
		jitterSec := res.Jitter.Seconds()

		c.internetLatencyGauge.WithLabelValues(targetLabel, typeLabel).Set(latSec)
		c.internetPacketLossGauge.WithLabelValues(targetLabel, typeLabel).Set(res.PacketLossRatio)
		c.internetJitterGauge.WithLabelValues(targetLabel, typeLabel).Set(jitterSec)

		samples = append(samples,
			MetricSample{Metric: "internet_latency_seconds", Labels: map[string]string{"target": targetLabel, "type": typeLabel}, Timestamp: now, Value: latSec},
			MetricSample{Metric: "internet_packet_loss_ratio", Labels: map[string]string{"target": targetLabel, "type": typeLabel}, Timestamp: now, Value: res.PacketLossRatio},
			MetricSample{Metric: "internet_jitter_seconds", Labels: map[string]string{"target": targetLabel, "type": typeLabel}, Timestamp: now, Value: jitterSec},
		)
	}

	avgLoss := 0.0
	if totalTargets > 0 {
		avgLoss = totalLoss / float64(totalTargets)
	}
	avgLatency := 0.0
	if latencyCount > 0 {
		avgLatency = latencySum / float64(latencyCount)
	}
	avgJitter := 0.0
	if jitterCount > 0 {
		avgJitter = jitterSum / float64(jitterCount)
	}

	status := "operational"
	statusGaugeVal := 1.0
	isUp := true
	var reason string

	if upCount == 0 || avgLoss >= 0.95 {
		status = "down"
		statusGaugeVal = 0.0
		isUp = false
		reason = fmt.Sprintf("Total network outage: 0/%d targets reachable", totalTargets)
	} else if avgLoss >= 0.05 || upCount < totalTargets || avgLatency > 0.35 {
		status = "degraded"
		statusGaugeVal = 0.5
		if upCount < totalTargets {
			reason = fmt.Sprintf("%d/%d targets failing (packet loss %.1f%%)", totalTargets-upCount, totalTargets, avgLoss*100)
		} else if avgLoss >= 0.05 {
			reason = fmt.Sprintf("Elevated packet loss: %.1f%%", avgLoss*100)
		} else {
			reason = fmt.Sprintf("Elevated latency: %.1f ms", avgLatency*1000)
		}
	}

	c.internetStatus.Set(statusGaugeVal)
	samples = append(samples, MetricSample{
		Metric:    "internet_status",
		Labels:    map[string]string{},
		Timestamp: now,
		Value:     statusGaugeVal,
	})

	c.statusMu.Lock()
	prevStatus := c.currentStatus
	c.currentStatus = status
	c.overall = OverallHealth{
		Status:          status,
		IsUp:            isUp,
		LatencySeconds:  avgLatency,
		PacketLossRatio: avgLoss,
		JitterSeconds:   avgJitter,
		LastChecked:     now,
	}

	store := c.outageStore
	activeOutageID := c.currentOutageID
	sink := c.sampleSink

	if status != prevStatus {
		log.Printf("Internet health transition: %s -> %s (%s)", prevStatus, status, reason)
		if activeOutageID > 0 && store != nil {
			_ = store.RecordOutageEnd(activeOutageID, now)
			c.currentOutageID = 0
		}
		if status != "operational" && store != nil {
			newID, err := store.RecordOutageStart(status, reason, now)
			if err == nil {
				c.currentOutageID = newID
			}
		}
	}
	c.statusMu.Unlock()

	// Direct sample insertion to TSDB sink
	if sink != nil && len(samples) > 0 {
		sink(samples)
	}
}

func (c *InternetChecker) Start(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Run first check immediately
	c.CheckOnce(ctx)

	for {
		select {
		case <-ticker.C:
			c.CheckOnce(ctx)
		case <-ctx.Done():
			return
		}
	}
}
