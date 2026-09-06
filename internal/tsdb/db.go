package tsdb

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

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

type DB struct {
	db          *sql.DB
	seriesCache map[string]int64
	cacheMu     sync.RWMutex
	writeMu     sync.Mutex
}

func Open(dbPath string) (*DB, error) {
	dsn := dbPath
	if !strings.Contains(dsn, "?") {
		dsn += "?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)"
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite db: %w", err)
	}

	db.SetMaxOpenConns(5)
	db.SetMaxIdleConns(5)

	schema := `
	CREATE TABLE IF NOT EXISTS series (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		labels_json TEXT NOT NULL,
		UNIQUE(name, labels_json)
	);
	CREATE TABLE IF NOT EXISTS samples (
		series_id INTEGER NOT NULL REFERENCES series(id) ON DELETE CASCADE,
		timestamp INTEGER NOT NULL,
		value REAL NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_samples_series_time ON samples(series_id, timestamp);
	CREATE TABLE IF NOT EXISTS devices (
		mac TEXT PRIMARY KEY,
		ip TEXT NOT NULL,
		hostname TEXT NOT NULL,
		interface TEXT NOT NULL,
		first_seen INTEGER NOT NULL,
		last_seen INTEGER NOT NULL
	);
	CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
	`
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init sqlite schema: %w", err)
	}

	t := &DB{
		db:          db,
		seriesCache: make(map[string]int64),
	}

	if err := t.loadSeriesCache(); err != nil {
		log.Printf("warn: failed to warm series cache: %v", err)
	}

	return t, nil
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

func (d *DB) loadSeriesCache() error {
	rows, err := d.db.Query("SELECT id, name, labels_json FROM series")
	if err != nil {
		return err
	}

	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	for rows.Next() {
		var id int64
		var name, labelsJSON string
		if err := rows.Scan(&id, &name, &labelsJSON); err == nil {
			d.seriesCache[name+":"+labelsJSON] = id
		}
	}
	rows.Close()
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

func (d *DB) UpsertDevice(hwAddr, ipAddr, hostname, iface string, seenAt time.Time) error {
	if hwAddr == "" || hwAddr == "00:00:00:00:00:00" {
		return nil
	}
	d.writeMu.Lock()
	defer d.writeMu.Unlock()

	ts := seenAt.Unix()
	q := `
	INSERT INTO devices (mac, ip, hostname, interface, first_seen, last_seen)
	VALUES (?, ?, ?, ?, ?, ?)
	ON CONFLICT(mac) DO UPDATE SET
		ip = excluded.ip,
		hostname = CASE WHEN excluded.hostname != '' AND excluded.hostname NOT LIKE 'unknown:%' THEN excluded.hostname ELSE devices.hostname END,
		interface = excluded.interface,
		last_seen = excluded.last_seen
	`
	_, err := d.db.Exec(q, hwAddr, ipAddr, hostname, iface, ts, ts)
	return err
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

