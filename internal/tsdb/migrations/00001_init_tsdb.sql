-- +goose Up
-- +goose StatementBegin
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

-- Index for per-series range queries (QueryRange)
CREATE INDEX IF NOT EXISTS idx_samples_series_time ON samples(series_id, timestamp);

-- Covering composite index for time-range filtering, group-by, and retention purges
CREATE INDEX IF NOT EXISTS idx_samples_time_series_val ON samples(timestamp, series_id, value);

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT NOT NULL,
    hostname TEXT NOT NULL,
    interface TEXT NOT NULL,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS devices;
DROP TABLE IF EXISTS samples;
DROP TABLE IF EXISTS series;
-- +goose StatementEnd
