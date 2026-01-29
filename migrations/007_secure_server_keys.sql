-- Migration 007: Secure Server Keys
-- Updates server_keys table to store Ed25519 private keys in JWK format
-- and adds key_version to distinguish between old (insecure) and new (secure) keys

-- Add new columns for JWK storage and versioning
ALTER TABLE server_keys ADD COLUMN private_key_jwk TEXT;
ALTER TABLE server_keys ADD COLUMN key_version INTEGER DEFAULT 1;

-- Note: Existing keys with key_version=1 are the old placeholder keys
-- New keys generated after this migration will have key_version=2 and use private_key_jwk
-- The old private_key column is kept for backwards compatibility but should not be used

-- Mark existing keys as version 1 (legacy/insecure - need regeneration)
UPDATE server_keys SET key_version = 1 WHERE key_version IS NULL;

-- Create index for faster lookups
CREATE INDEX IF NOT EXISTS idx_server_keys_version ON server_keys(key_version);

-- Add table for caching remote server keys (for federation auth)
CREATE TABLE IF NOT EXISTS remote_server_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    server_name TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key TEXT NOT NULL,
    valid_from INTEGER NOT NULL,
    valid_until INTEGER,
    fetched_at INTEGER NOT NULL,
    verified INTEGER DEFAULT 0,
    UNIQUE(server_name, key_id)
);

CREATE INDEX IF NOT EXISTS idx_remote_server_keys_server ON remote_server_keys(server_name);
CREATE INDEX IF NOT EXISTS idx_remote_server_keys_valid ON remote_server_keys(valid_until);
