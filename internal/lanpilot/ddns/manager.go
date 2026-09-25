package ddns

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/blesswinsamuel/lanpilot/internal/tsdb"
	"github.com/prometheus/client_golang/prometheus"
)

// HistoryStore represents persistence for DDNS update events.
type HistoryStore interface {
	RecordDDNSEvent(timestamp time.Time, provider, ipv4, ipv6, status, message string) (int64, error)
	GetRecentDDNSHistory(limit int) ([]tsdb.DDNSEvent, error)
}

// ManagerConfig configures the DDNS Manager.
type ManagerConfig struct {
	Enabled   bool
	Provider  Provider
	Detector  IPDetector
	Domains   []string
	Interval  time.Duration
	CheckIPv4 bool
	CheckIPv6 bool
	Store     HistoryStore
}

// Status represents the current state of DDNS.
type Status struct {
	Enabled               bool
	Provider              string
	Domains               []string
	CurrentIPv4           string
	CurrentIPv6           string
	LastSyncUnix          int64
	LastSyncStatus        string // "success", "failure", "pending", "disabled"
	LastSyncMessage       string
	CheckIntervalSeconds  int64
	History               []tsdb.DDNSEvent
}

type Manager struct {
	cfg ManagerConfig

	stateMu         sync.RWMutex
	currentIPv4     string
	currentIPv6     string
	lastSyncedIPv4  string
	lastSyncedIPv6  string
	lastSyncTime    time.Time
	lastSyncStatus  string
	lastSyncMessage string

	syncMu sync.Mutex

	lastSyncTimestamp prometheus.Gauge
	syncTotal         *prometheus.CounterVec
	currentIPInfo     *prometheus.GaugeVec
}

func NewManager(cfg ManagerConfig) *Manager {
	if cfg.Interval <= 0 {
		cfg.Interval = 5 * time.Minute
	}
	// Default IPv4 to true if both false
	if !cfg.CheckIPv4 && !cfg.CheckIPv6 {
		cfg.CheckIPv4 = true
	}

	initialStatus := "disabled"
	if cfg.Enabled {
		initialStatus = "pending"
	}

	m := &Manager{
		cfg:            cfg,
		lastSyncStatus: initialStatus,
		lastSyncMessage: "Initialized",

		lastSyncTimestamp: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "lanpilot_ddns_last_sync_timestamp_seconds",
			Help: "Timestamp of the last DDNS sync attempt in unix seconds",
		}),
		syncTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "lanpilot_ddns_sync_total",
			Help: "Total number of DDNS sync operations",
		}, []string{"status"}),
		currentIPInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "lanpilot_ddns_current_ip_info",
			Help: "Current detected public WAN IP information",
		}, []string{"ipv4", "ipv6"}),
	}

	return m
}

func (m *Manager) Register(reg prometheus.Registerer) {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	reg.MustRegister(m.lastSyncTimestamp)
	reg.MustRegister(m.syncTotal)
	reg.MustRegister(m.currentIPInfo)
}

func (m *Manager) Start(ctx context.Context) {
	if !m.cfg.Enabled {
		log.Printf("DDNS is disabled")
		return
	}

	providerName := "none"
	if m.cfg.Provider != nil {
		providerName = m.cfg.Provider.Name()
	}
	log.Printf("Starting DDNS background worker (provider: %s, domains: %v, interval: %v)",
		providerName, m.cfg.Domains, m.cfg.Interval)

	// Run initial sync after a short startup delay to let networking initialize
	go func() {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
			if _, err := m.Sync(ctx, false); err != nil {
				log.Printf("DDNS initial sync error: %v", err)
			}
		}
	}()

	ticker := time.NewTicker(m.cfg.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Printf("Stopping DDNS background worker")
			return
		case <-ticker.C:
			if _, err := m.Sync(ctx, false); err != nil {
				log.Printf("DDNS periodic sync error: %v", err)
			}
		}
	}
}

func (m *Manager) Sync(ctx context.Context, force bool) (*UpdateResult, error) {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()

	if !m.cfg.Enabled {
		return &UpdateResult{
			Success: false,
			Message: "DDNS is not enabled",
		}, nil
	}

	if m.cfg.Provider == nil {
		return nil, fmt.Errorf("no DDNS provider configured")
	}

	if m.cfg.Detector == nil {
		return nil, fmt.Errorf("no WAN IP detector configured")
	}

	// 1. Detect WAN IPs
	pair, err := m.cfg.Detector.DetectIPs(ctx, m.cfg.CheckIPv4, m.cfg.CheckIPv6)
	if err != nil {
		m.recordFailure("detection_error", err.Error())
		return nil, fmt.Errorf("detect WAN IPs: %w", err)
	}

	m.stateMu.Lock()
	m.currentIPv4 = pair.IPv4
	m.currentIPv6 = pair.IPv6
	lastV4 := m.lastSyncedIPv4
	lastV6 := m.lastSyncedIPv6
	prevStatus := m.lastSyncStatus
	m.stateMu.Unlock()

	// Update current IP prometheus gauge
	m.currentIPInfo.Reset()
	m.currentIPInfo.WithLabelValues(pair.IPv4, pair.IPv6).Set(1)

	// 2. Check if IP has changed
	ipChanged := false
	if m.cfg.CheckIPv4 && pair.IPv4 != "" && pair.IPv4 != lastV4 {
		ipChanged = true
	}
	if m.cfg.CheckIPv6 && pair.IPv6 != "" && pair.IPv6 != lastV6 {
		ipChanged = true
	}

	// If no change, previous sync was successful, and not forced, skip calling provider API
	if !ipChanged && !force && prevStatus == "success" {
		msg := fmt.Sprintf("IP unchanged (IPv4: %s, IPv6: %s), skipping DNS update", pair.IPv4, pair.IPv6)
		m.stateMu.Lock()
		m.lastSyncTime = time.Now()
		m.lastSyncMessage = msg
		m.stateMu.Unlock()
		m.lastSyncTimestamp.Set(float64(time.Now().Unix()))
		return &UpdateResult{
			UpdatedRecords: 0,
			Message:        msg,
			Success:        true,
		}, nil
	}

	// 3. Call Provider Update
	log.Printf("DDNS: Syncing DNS records (force=%v, ipChanged=%v, IPv4=%s, IPv6=%s)...",
		force, ipChanged, pair.IPv4, pair.IPv6)

	updateReq := UpdateRequest{
		Domains: m.cfg.Domains,
		IPv4:    pair.IPv4,
		IPv6:    pair.IPv6,
		Force:   force,
	}

	res, err := m.cfg.Provider.Update(ctx, updateReq)
	now := time.Now()
	m.lastSyncTimestamp.Set(float64(now.Unix()))

	if err != nil {
		m.recordFailure(pair.IPv4, err.Error())
		return nil, err
	}

	// 4. Record Success
	m.stateMu.Lock()
	m.lastSyncedIPv4 = pair.IPv4
	m.lastSyncedIPv6 = pair.IPv6
	m.lastSyncTime = now
	m.lastSyncStatus = "success"
	m.lastSyncMessage = res.Message
	m.stateMu.Unlock()

	m.syncTotal.WithLabelValues("success").Inc()

	if m.cfg.Store != nil {
		_, _ = m.cfg.Store.RecordDDNSEvent(now, m.cfg.Provider.Name(), pair.IPv4, pair.IPv6, "success", res.Message)
	}

	log.Printf("DDNS sync successful: %s", res.Message)
	return res, nil
}

func (m *Manager) recordFailure(detectedIP, errMsg string) {
	now := time.Now()
	m.stateMu.Lock()
	m.lastSyncTime = now
	m.lastSyncStatus = "failure"
	m.lastSyncMessage = errMsg
	v4 := m.currentIPv4
	v6 := m.currentIPv6
	m.stateMu.Unlock()

	m.lastSyncTimestamp.Set(float64(now.Unix()))
	m.syncTotal.WithLabelValues("failure").Inc()

	providerName := "none"
	if m.cfg.Provider != nil {
		providerName = m.cfg.Provider.Name()
	}

	if m.cfg.Store != nil {
		_, _ = m.cfg.Store.RecordDDNSEvent(now, providerName, v4, v6, "failure", errMsg)
	}
	log.Printf("DDNS sync failed: %s", errMsg)
}

func (m *Manager) GetStatus(ctx context.Context) (*Status, error) {
	m.stateMu.RLock()
	st := &Status{
		Enabled:              m.cfg.Enabled,
		Domains:              append([]string(nil), m.cfg.Domains...),
		CurrentIPv4:          m.currentIPv4,
		CurrentIPv6:          m.currentIPv6,
		LastSyncUnix:         m.lastSyncTime.Unix(),
		LastSyncStatus:       m.lastSyncStatus,
		LastSyncMessage:      m.lastSyncMessage,
		CheckIntervalSeconds: int64(m.cfg.Interval.Seconds()),
	}
	if m.cfg.Provider != nil {
		st.Provider = m.cfg.Provider.Name()
	}
	m.stateMu.RUnlock()

	if m.cfg.Store != nil {
		history, err := m.cfg.Store.GetRecentDDNSHistory(20)
		if err == nil {
			st.History = history
		}
	}

	return st, nil
}
