-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS internet_outages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    start_time INTEGER NOT NULL,
    end_time INTEGER,
    duration_seconds REAL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_outages_start ON internet_outages(start_time);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS internet_outages;
-- +goose StatementEnd
