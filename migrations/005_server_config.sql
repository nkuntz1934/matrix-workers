-- Server configuration table for admin-controlled settings
-- Migration 005: Server Config

CREATE TABLE IF NOT EXISTS server_config (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Insert default registration setting (enabled by default)
INSERT OR IGNORE INTO server_config (key, value, updated_at) VALUES ('registration_enabled', 'true', 0);
