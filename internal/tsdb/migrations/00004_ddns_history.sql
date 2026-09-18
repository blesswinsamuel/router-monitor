-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS ddns_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp_unix INTEGER NOT NULL,
    provider TEXT NOT NULL,
    ipv4 TEXT,
    ipv6 TEXT,
    status TEXT NOT NULL,
    message TEXT
);

CREATE INDEX IF NOT EXISTS idx_ddns_history_timestamp ON ddns_history(timestamp_unix DESC);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS ddns_history;
-- +goose StatementEnd
