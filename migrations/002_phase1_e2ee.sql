-- Phase 1: E2EE and Critical Features Migration
-- This migration adds tables for key backups, enhanced device keys, pushers, and transaction tracking

-- ============================================
-- KEY BACKUPS (for E2E encryption key recovery)
-- ============================================

-- Stores backup version metadata
CREATE TABLE IF NOT EXISTS key_backup_versions (
    version INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,                     -- e.g., 'm.megolm_backup.v1.curve25519-aes-sha2'
    auth_data TEXT NOT NULL,                     -- JSON: public key and signatures
    etag TEXT NOT NULL,                          -- For conflict detection
    count INTEGER NOT NULL DEFAULT 0,            -- Number of keys in backup
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    deleted INTEGER NOT NULL DEFAULT 0,          -- Soft delete flag
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_key_backup_versions_user ON key_backup_versions(user_id, deleted);

-- Stores encrypted room keys per session
CREATE TABLE IF NOT EXISTS key_backup_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    room_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    first_message_index INTEGER NOT NULL,
    forwarded_count INTEGER NOT NULL,
    is_verified INTEGER NOT NULL DEFAULT 0,
    session_data TEXT NOT NULL,                  -- Encrypted session data (JSON)
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    UNIQUE(user_id, version, room_id, session_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_key_backup_keys_user_version ON key_backup_keys(user_id, version);
CREATE INDEX IF NOT EXISTS idx_key_backup_keys_room ON key_backup_keys(user_id, version, room_id);

-- ============================================
-- ENHANCED DEVICE KEYS (cross-signing support)
-- ============================================

-- User cross-signing keys (master, self-signing, user-signing)
CREATE TABLE IF NOT EXISTS cross_signing_keys (
    user_id TEXT NOT NULL,
    key_type TEXT NOT NULL,                      -- 'master', 'self_signing', 'user_signing'
    key_id TEXT NOT NULL,                        -- e.g., 'ed25519:ABCDEF'
    key_data TEXT NOT NULL,                      -- JSON: full key object with signatures
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (user_id, key_type),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cross_signing_keys_user ON cross_signing_keys(user_id);

-- Cross-signing signatures (who signed what)
CREATE TABLE IF NOT EXISTS cross_signing_signatures (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,                       -- User whose key was signed
    key_id TEXT NOT NULL,                        -- Key that was signed
    signer_user_id TEXT NOT NULL,                -- User who made the signature
    signer_key_id TEXT NOT NULL,                 -- Key used to sign
    signature TEXT NOT NULL,                     -- The actual signature
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    UNIQUE(user_id, key_id, signer_user_id, signer_key_id)
);
CREATE INDEX IF NOT EXISTS idx_cross_signing_sigs_user ON cross_signing_signatures(user_id);
CREATE INDEX IF NOT EXISTS idx_cross_signing_sigs_signer ON cross_signing_signatures(signer_user_id);

-- Device key changes tracking (for /keys/changes endpoint)
CREATE TABLE IF NOT EXISTS device_key_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,                       -- User whose keys changed
    device_id TEXT,                              -- NULL for cross-signing key changes
    change_type TEXT NOT NULL,                   -- 'new', 'update', 'delete'
    stream_position INTEGER NOT NULL,            -- For sync ordering
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_device_key_changes_stream ON device_key_changes(stream_position);
CREATE INDEX IF NOT EXISTS idx_device_key_changes_user ON device_key_changes(user_id);

-- One-time keys storage (enhance existing)
CREATE TABLE IF NOT EXISTS one_time_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,                     -- e.g., 'curve25519', 'signed_curve25519'
    key_id TEXT NOT NULL,                        -- Key identifier
    key_data TEXT NOT NULL,                      -- JSON: key and optional signature
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    claimed INTEGER NOT NULL DEFAULT 0,          -- Has this key been claimed?
    claimed_at INTEGER,
    UNIQUE(user_id, device_id, algorithm, key_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_one_time_keys_user_device ON one_time_keys(user_id, device_id, algorithm, claimed);

-- Fallback keys (used when one-time keys exhausted)
CREATE TABLE IF NOT EXISTS fallback_keys (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    key_id TEXT NOT NULL,
    key_data TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,             -- Has this fallback been used?
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (user_id, device_id, algorithm),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- ============================================
-- TO-DEVICE MESSAGES
-- ============================================

CREATE TABLE IF NOT EXISTS to_device_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_user_id TEXT NOT NULL,
    recipient_device_id TEXT NOT NULL,           -- '*' for all devices
    sender_user_id TEXT NOT NULL,
    event_type TEXT NOT NULL,                    -- e.g., 'm.room_key', 'm.room.encrypted'
    content TEXT NOT NULL,                       -- JSON message content
    message_id TEXT NOT NULL,                    -- Unique message ID for deduplication
    stream_position INTEGER NOT NULL,            -- For sync ordering
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    delivered INTEGER NOT NULL DEFAULT 0,        -- Has been synced to device
    UNIQUE(recipient_user_id, recipient_device_id, message_id)
);
CREATE INDEX IF NOT EXISTS idx_to_device_recipient ON to_device_messages(recipient_user_id, recipient_device_id, delivered);
CREATE INDEX IF NOT EXISTS idx_to_device_stream ON to_device_messages(stream_position);

-- ============================================
-- PUSH NOTIFICATIONS
-- ============================================

-- Registered push endpoints
CREATE TABLE IF NOT EXISTS pushers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    access_token_id TEXT,                        -- Token that registered this pusher
    pushkey TEXT NOT NULL,                       -- Unique identifier for push destination
    kind TEXT NOT NULL,                          -- 'http', 'email', etc.
    app_id TEXT NOT NULL,                        -- Application identifier
    app_display_name TEXT NOT NULL,
    device_display_name TEXT NOT NULL,
    profile_tag TEXT,                            -- For multiple pushers per app
    lang TEXT NOT NULL,
    data TEXT NOT NULL,                          -- JSON: URL and format info
    enabled INTEGER NOT NULL DEFAULT 1,
    last_success INTEGER,                        -- Last successful push timestamp
    last_failure INTEGER,                        -- Last failed push timestamp
    failure_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    UNIQUE(user_id, pushkey, app_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_pushers_user ON pushers(user_id);

-- Notification queue (for async push delivery)
CREATE TABLE IF NOT EXISTS notification_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL,
    event_id TEXT NOT NULL,
    notification_type TEXT NOT NULL,             -- 'message', 'invite', 'mention', etc.
    actions TEXT NOT NULL,                       -- JSON: actions to perform
    read INTEGER NOT NULL DEFAULT 0,             -- Has user seen this?
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    pushed INTEGER NOT NULL DEFAULT 0,           -- Has been sent to pushers?
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_notification_queue_user ON notification_queue(user_id, read);
CREATE INDEX IF NOT EXISTS idx_notification_queue_pending ON notification_queue(pushed, created_at);

-- ============================================
-- TRANSACTION ID TRACKING (idempotency)
-- ============================================

CREATE TABLE IF NOT EXISTS transaction_ids (
    user_id TEXT NOT NULL,
    device_id TEXT,
    txn_id TEXT NOT NULL,
    event_id TEXT,                               -- Resulting event ID if applicable
    response TEXT,                               -- Cached JSON response
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (user_id, txn_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_transaction_ids_cleanup ON transaction_ids(created_at);

-- ============================================
-- STREAM POSITION TRACKING (for sync)
-- ============================================

-- Global stream position counter
CREATE TABLE IF NOT EXISTS stream_positions (
    stream_name TEXT PRIMARY KEY,                -- 'events', 'device_keys', 'to_device', etc.
    position INTEGER NOT NULL DEFAULT 0
);

-- Initialize stream positions
INSERT OR IGNORE INTO stream_positions (stream_name, position) VALUES ('events', 0);
INSERT OR IGNORE INTO stream_positions (stream_name, position) VALUES ('device_keys', 0);
INSERT OR IGNORE INTO stream_positions (stream_name, position) VALUES ('to_device', 0);
INSERT OR IGNORE INTO stream_positions (stream_name, position) VALUES ('presence', 0);
INSERT OR IGNORE INTO stream_positions (stream_name, position) VALUES ('receipts', 0);
INSERT OR IGNORE INTO stream_positions (stream_name, position) VALUES ('typing', 0);
INSERT OR IGNORE INTO stream_positions (stream_name, position) VALUES ('account_data', 0);

-- ============================================
-- ENHANCED ACCOUNT DATA
-- ============================================

-- Add stream position to account_data for sync
-- Note: We alter the existing table by recreating it with new column
-- SQLite doesn't support ADD COLUMN with DEFAULT in all cases

-- First check if column exists, if not we need to handle migration
-- For now, we'll use a separate table for account data changes
CREATE TABLE IF NOT EXISTS account_data_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL DEFAULT '',            -- Empty for global
    event_type TEXT NOT NULL,
    stream_position INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_account_data_changes_stream ON account_data_changes(stream_position);
CREATE INDEX IF NOT EXISTS idx_account_data_changes_user ON account_data_changes(user_id, room_id);
