package tsdb

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

type Sample struct {
	Metric    string
	Labels    map[string]string
	Timestamp time.Time
	Value     float64
}

type TimeSeriesPoint struct {
	TimestampUnix int64
	Value         float64
	MinValue      float64
	MaxValue      float64
}

type TimeSeriesResult struct {
	MetricName string
	Labels     map[string]string
	Points     []TimeSeriesPoint
}

type PersistedDevice struct {
	HWAddr    string    `json:"hw_addr"`
	IPAddr    string    `json:"ip_addr"`
	Hostname  string    `json:"hostname"`
	Device    string    `json:"device"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type seriesMetaInfo struct {
	Name      string
	IP        string
	Direction string
}

type cachedUsage struct {
	fromUnix int64
	toUnix   int64
	expiry   time.Time
	data     map[string]*DevicePeriodUsage
}

type DB struct {
	db             *sql.DB
	sampleInterval float64
	seriesCache    map[string]int64
	seriesMeta     map[int64]seriesMetaInfo
	cacheMu        sync.RWMutex
	writeMu        sync.Mutex

	usageCacheMu sync.RWMutex
	usageCache   map[string]cachedUsage
}

func Open(dbPath string) (*DB, error) {
	dsn := dbPath
	if !strings.Contains(dsn, "?") {
		if strings.HasPrefix(dbPath, ":memory:") {
			dsn += "?_pragma=busy_timeout(5000)&_pragma=cache_size(-8000)&_pragma=temp_store(MEMORY)"
		} else {
			dsn += "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)&_pragma=cache_size(-8000)&_pragma=temp_store(MEMORY)&_pragma=mmap_size(67108864)"
		}
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)

	goose.SetBaseFS(migrationFS)
	goose.SetLogger(goose.NopLogger())
	if err := goose.SetDialect("sqlite3"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(db, "migrations"); err != nil {
		db.Close()
		return nil, fmt.Errorf("run goose migrations: %w", err)
	}

	t := &DB{
		db:             db,
		sampleInterval: 15.0,
		seriesCache:    make(map[string]int64),
		seriesMeta:     make(map[int64]seriesMetaInfo),
		usageCache:     make(map[string]cachedUsage),
	}

	if err := t.loadSeriesCache(); err != nil {
		log.Printf("warn: failed to warm series cache: %v", err)
	}

	return t, nil
}

func (d *DB) SetSampleInterval(interval time.Duration) {
	if interval <= 0 {
		interval = 15 * time.Second
	}
	d.sampleInterval = interval.Seconds()
}

func (d *DB) Close() error {
	return d.db.Close()
}

func canonicalLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	sb := strings.Builder{}
	sb.WriteString("{")
	for i, k := range keys {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(fmt.Sprintf("%q:%q", k, labels[k]))
	}
	sb.WriteString("}")
	return sb.String()
}

func parseSeriesMeta(name, labelsJSON string) seriesMetaInfo {
	meta := seriesMetaInfo{Name: name}
	var labels map[string]string
	if err := json.Unmarshal([]byte(labelsJSON), &labels); err == nil {
		meta.IP = labels["ip"]
		meta.Direction = labels["direction"]
	}
	return meta
}

func (d *DB) loadSeriesCache() error {
	rows, err := d.db.Query("SELECT id, name, labels_json FROM series")
	if err != nil {
		return err
	}
	defer rows.Close()

	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	for rows.Next() {
		var id int64
		var name, labelsJSON string
		if err := rows.Scan(&id, &name, &labelsJSON); err == nil {
			d.seriesCache[name+":"+labelsJSON] = id
			d.seriesMeta[id] = parseSeriesMeta(name, labelsJSON)
		}
	}
	return nil
}

func (d *DB) getOrCreateSeriesID(metric string, labels map[string]string) (int64, error) {
	lblStr := canonicalLabels(labels)
	cacheKey := metric + ":" + lblStr

	d.cacheMu.RLock()
	id, ok := d.seriesCache[cacheKey]
	d.cacheMu.RUnlock()
	if ok {
		return id, nil
	}

	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()

	// Double check after lock
	if id, ok = d.seriesCache[cacheKey]; ok {
		return id, nil
	}

	_, err := d.db.Exec("INSERT OR IGNORE INTO series(name, labels_json) VALUES(?, ?)", metric, lblStr)
	if err != nil {
		return 0, fmt.Errorf("insert series: %w", err)
	}

	err = d.db.QueryRow("SELECT id FROM series WHERE name = ? AND labels_json = ?", metric, lblStr).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("query series id: %w", err)
	}

	d.seriesCache[cacheKey] = id
	d.seriesMeta[id] = seriesMetaInfo{
		Name:      metric,
		IP:        labels["ip"],
		Direction: labels["direction"],
	}
	return id, nil
}

func (d *DB) InsertSamples(samples []Sample) error {
	if len(samples) == 0 {
		return nil
	}

	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	// 1. Resolve all series IDs before opening the transaction
	type sampleWithID struct {
		seriesID int64
		sample   Sample
	}
	prepared := make([]sampleWithID, len(samples))
	for i, s := range samples {
		seriesID, err := d.getOrCreateSeriesID(s.Metric, s.Labels)
		if err != nil {
			return err
		}
		prepared[i] = sampleWithID{seriesID: seriesID, sample: s}
	}

	// 2. Insert samples in a single transaction
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare("INSERT INTO samples(series_id, timestamp, value) VALUES(?, ?, ?)")
	if err != nil {
		return fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	for _, p := range prepared {
		ts := p.sample.Timestamp.Unix()
		if _, err := stmt.Exec(p.seriesID, ts, p.sample.Value); err != nil {
			return fmt.Errorf("exec insert: %w", err)
		}
	}

	return tx.Commit()
}

func (d *DB) QueryRange(metric string, matchLabels map[string]string, from, to time.Time, stepSeconds int) ([]TimeSeriesResult, error) {
	if stepSeconds <= 0 {
		span := to.Sub(from)
		if span <= 15*time.Minute {
			stepSeconds = 5
		} else if span <= 1*time.Hour {
			stepSeconds = 15
		} else if span <= 6*time.Hour {
			stepSeconds = 60
		} else {
			stepSeconds = 300
		}
	}

	fromUnix := from.Unix()
	toUnix := to.Unix()

	// Find matching series
	rows, err := d.db.Query("SELECT id, name, labels_json FROM series WHERE name = ?", metric)
	if err != nil {
		return nil, fmt.Errorf("query series: %w", err)
	}

	type matchedSeries struct {
		id     int64
		name   string
		labels map[string]string
	}
	var matched []matchedSeries

	for rows.Next() {
		var id int64
		var name, labelsJSON string
		if err := rows.Scan(&id, &name, &labelsJSON); err != nil {
			continue
		}
		var parsedLabels map[string]string
		if err := json.Unmarshal([]byte(labelsJSON), &parsedLabels); err != nil {
			continue
		}

		matches := true
		for k, v := range matchLabels {
			if parsedLabels[k] != v {
				matches = false
				break
			}
		}
		if matches {
			matched = append(matched, matchedSeries{id: id, name: name, labels: parsedLabels})
		}
	}
	rows.Close()

	if len(matched) == 0 {
		return nil, nil
	}

	results := make([]TimeSeriesResult, 0, len(matched))

	for _, s := range matched {
		q := `
		SELECT (timestamp / ?) * ? AS bucket,
		       AVG(value),
		       MIN(value),
		       MAX(value)
		FROM samples
		WHERE series_id = ? AND timestamp >= ? AND timestamp <= ?
		GROUP BY bucket
		ORDER BY bucket ASC
		`
		sampleRows, err := d.db.Query(q, stepSeconds, stepSeconds, s.id, fromUnix, toUnix)
		if err != nil {
			return nil, fmt.Errorf("query samples for series %d: %w", s.id, err)
		}

		var points []TimeSeriesPoint
		for sampleRows.Next() {
			var p TimeSeriesPoint
			if err := sampleRows.Scan(&p.TimestampUnix, &p.Value, &p.MinValue, &p.MaxValue); err != nil {
				continue
			}
			points = append(points, p)
		}
		sampleRows.Close()

		results = append(results, TimeSeriesResult{
			MetricName: s.name,
			Labels:     s.labels,
			Points:     points,
		})
	}

	return results, nil
}

type DevicePeriodUsage struct {
	DownloadBytes    uint64
	UploadBytes      uint64
	WanDownloadBytes uint64
	WanUploadBytes   uint64
	LanDownloadBytes uint64
	LanUploadBytes   uint64
}

// GetDeviceUsageByPeriod aggregates device traffic samples over [fromUnix, toUnix].
// Leverages covering index idx_samples_time_series_val and caches recent results in memory.
func (d *DB) GetDeviceUsageByPeriod(fromUnix, toUnix int64) (map[string]*DevicePeriodUsage, error) {
	cacheKey := fmt.Sprintf("%d:%d", fromUnix/15, toUnix/15)
	d.usageCacheMu.RLock()
	if cu, ok := d.usageCache[cacheKey]; ok && time.Now().Before(cu.expiry) {
		d.usageCacheMu.RUnlock()
		return cu.data, nil
	}
	d.usageCacheMu.RUnlock()

	q := `
	SELECT series_id, COALESCE(SUM(value), 0)
	FROM samples
	WHERE timestamp >= ? AND timestamp <= ?
	GROUP BY series_id
	`
	rows, err := d.db.Query(q, fromUnix, toUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	interval := d.sampleInterval
	if interval <= 0 {
		interval = 15.0
	}

	usage := make(map[string]*DevicePeriodUsage)
	for rows.Next() {
		var seriesID int64
		var sumRate float64
		if err := rows.Scan(&seriesID, &sumRate); err != nil {
			continue
		}

		d.cacheMu.RLock()
		meta, ok := d.seriesMeta[seriesID]
		d.cacheMu.RUnlock()
		if !ok || meta.IP == "" {
			continue
		}

		u, exists := usage[meta.IP]
		if !exists {
			u = &DevicePeriodUsage{}
			usage[meta.IP] = u
		}

		b := uint64(sumRate * interval)
		switch meta.Name {
		case "device_traffic_bytes_rate":
			if meta.Direction == "ingress" {
				u.DownloadBytes = b
			} else if meta.Direction == "egress" {
				u.UploadBytes = b
			}
		case "device_wan_bytes_rate":
			if meta.Direction == "ingress" {
				u.WanDownloadBytes = b
			} else if meta.Direction == "egress" {
				u.WanUploadBytes = b
			}
		case "device_lan_bytes_rate":
			if meta.Direction == "ingress" {
				u.LanDownloadBytes = b
			} else if meta.Direction == "egress" {
				u.LanUploadBytes = b
			}
		}
	}

	d.usageCacheMu.Lock()
	d.usageCache[cacheKey] = cachedUsage{
		fromUnix: fromUnix,
		toUnix:   toUnix,
		expiry:   time.Now().Add(15 * time.Second),
		data:     usage,
	}
	if len(d.usageCache) > 50 {
		d.usageCache = make(map[string]cachedUsage)
	}
	d.usageCacheMu.Unlock()

	return usage, nil
}

func (d *DB) PurgeOlderThan(retention time.Duration) (int64, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	threshold := time.Now().Add(-retention).Unix()
	res, err := d.db.Exec("DELETE FROM samples WHERE timestamp < ?", threshold)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (d *DB) StartRetentionWorker(ctx context.Context, interval time.Duration, retention time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ticker.C:
				deleted, err := d.PurgeOlderThan(retention)
				if err != nil {
					log.Printf("error purging old samples: %v", err)
				} else if deleted > 0 {
					log.Printf("purged %d expired metric samples", deleted)
				}
			case <-ctx.Done():
				ticker.Stop()
				return
			}
		}
	}()
}

// UpsertDevices updates device state in batch within a single transaction.
func (d *DB) UpsertDevices(devices []PersistedDevice) error {
	if len(devices) == 0 {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	q := `
	INSERT INTO devices (mac, ip, hostname, interface, first_seen, last_seen)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(mac) DO UPDATE SET
		ip = excluded.ip,
		hostname = CASE WHEN excluded.hostname != '' AND excluded.hostname NOT LIKE 'unknown:%' THEN excluded.hostname ELSE devices.hostname END,
		interface = excluded.interface,
		last_seen = excluded.last_seen
	`
	stmt, err := tx.Prepare(q)
	if err != nil {
		return fmt.Errorf("prepare upsert devices: %w", err)
	}
	defer stmt.Close()

	for _, dev := range devices {
		if dev.HWAddr == "" || dev.HWAddr == "00:00:00:00:00:00" {
			continue
		}
		firstUnix := dev.FirstSeen.Unix()
		lastUnix := dev.LastSeen.Unix()
		if firstUnix <= 0 {
			firstUnix = lastUnix
		}
		if _, err := stmt.Exec(dev.HWAddr, dev.IPAddr, dev.Hostname, dev.Device, firstUnix, lastUnix); err != nil {
			return fmt.Errorf("exec upsert device %s: %w", dev.HWAddr, err)
		}
	}

	return tx.Commit()
}

func (d *DB) UpsertDevice(hwAddr, ipAddr, hostname, iface string, seenAt time.Time) error {
	return d.UpsertDevices([]PersistedDevice{
		{
			HWAddr:    hwAddr,
			IPAddr:    ipAddr,
			Hostname:  hostname,
			Device:    iface,
			FirstSeen: seenAt,
			LastSeen:  seenAt,
		},
	})
}

func (d *DB) GetPersistedDevices() ([]PersistedDevice, error) {
	rows, err := d.db.Query("SELECT mac, ip, hostname, interface, first_seen, last_seen FROM devices ORDER BY last_seen DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var devices []PersistedDevice
	for rows.Next() {
		var dev PersistedDevice
		var firstUnix, lastUnix int64
		if err := rows.Scan(&dev.HWAddr, &dev.IPAddr, &dev.Hostname, &dev.Device, &firstUnix, &lastUnix); err != nil {
			continue
		}
		dev.FirstSeen = time.Unix(firstUnix, 0)
		dev.LastSeen = time.Unix(lastUnix, 0)
		devices = append(devices, dev)
	}
	return devices, nil
}

type OutageRecord struct {
	ID              int64     `json:"id"`
	StartTime       time.Time `json:"start_time"`
	EndTime         time.Time `json:"end_time"`
	DurationSeconds float64   `json:"duration_seconds"`
	Status          string    `json:"status"`
	Reason          string    `json:"reason"`
}

func (d *DB) RecordOutageStart(status, reason string, startTime time.Time) (int64, error) {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	res, err := d.db.Exec(
		"INSERT INTO internet_outages(start_time, status, reason) VALUES(?, ?, ?)",
		startTime.Unix(), status, reason,
	)
	if err != nil {
		return 0, fmt.Errorf("insert outage start: %w", err)
	}
	return res.LastInsertId()
}

func (d *DB) RecordOutageEnd(id int64, endTime time.Time) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	var startUnix int64
	err := d.db.QueryRow("SELECT start_time FROM internet_outages WHERE id = ?", id).Scan(&startUnix)
	if err != nil {
		return fmt.Errorf("query outage start_time: %w", err)
	}

	duration := float64(endTime.Unix() - startUnix)
	if duration < 0 {
		duration = 0
	}

	_, err = d.db.Exec(
		"UPDATE internet_outages SET end_time = ?, duration_seconds = ? WHERE id = ?",
		endTime.Unix(), duration, id,
	)
	if err != nil {
		return fmt.Errorf("update outage end: %w", err)
	}
	return nil
}

func (d *DB) GetRecentOutages(limit int) ([]OutageRecord, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := d.db.Query(
		"SELECT id, start_time, COALESCE(end_time, 0), COALESCE(duration_seconds, 0), status, reason FROM internet_outages ORDER BY start_time DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, fmt.Errorf("query recent outages: %w", err)
	}
	defer rows.Close()

	var outages []OutageRecord
	for rows.Next() {
		var o OutageRecord
		var startUnix, endUnix int64
		if err := rows.Scan(&o.ID, &startUnix, &endUnix, &o.DurationSeconds, &o.Status, &o.Reason); err != nil {
			continue
		}
		o.StartTime = time.Unix(startUnix, 0)
		if endUnix > 0 {
			o.EndTime = time.Unix(endUnix, 0)
		}
		outages = append(outages, o)
	}
	return outages, nil
}
