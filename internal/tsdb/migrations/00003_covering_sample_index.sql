-- +goose Up
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_samples_series_time;
CREATE INDEX IF NOT EXISTS idx_samples_series_time_val ON samples(series_id, timestamp, value);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP INDEX IF EXISTS idx_samples_series_time_val;
CREATE INDEX IF NOT EXISTS idx_samples_series_time ON samples(series_id, timestamp);
-- +goose StatementEnd
