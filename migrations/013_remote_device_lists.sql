-- Migration: Remote Device Lists Cache
-- Caches device lists from remote servers for E2EE federation

CREATE TABLE IF NOT EXISTS remote_device_lists (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    device_display_name TEXT,
    keys TEXT,                          -- JSON blob of device keys
    stream_id INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_remote_device_lists_user ON remote_device_lists(user_id);
CREATE INDEX IF NOT EXISTS idx_remote_device_lists_stream ON remote_device_lists(stream_id);

-- Track which remote device list changes we've processed
CREATE TABLE IF NOT EXISTS remote_device_list_streams (
    user_id TEXT PRIMARY KEY,
    stream_id INTEGER NOT NULL DEFAULT 0,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
