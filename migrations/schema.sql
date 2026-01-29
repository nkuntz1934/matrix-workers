-- Tuwunel Matrix Homeserver Database Schema for Cloudflare D1
-- This schema implements the core Matrix data model

-- Users table
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,                    -- @localpart:domain format
    localpart TEXT NOT NULL,
    password_hash TEXT,                          -- Argon2 hash
    display_name TEXT,
    avatar_url TEXT,
    is_guest INTEGER DEFAULT 0,
    is_deactivated INTEGER DEFAULT 0,
    admin INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);
CREATE INDEX IF NOT EXISTS idx_users_localpart ON users(localpart);

-- User devices
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    display_name TEXT,
    last_seen_ts INTEGER,
    last_seen_ip TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (user_id, device_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Access tokens
CREATE TABLE IF NOT EXISTS access_tokens (
    token_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,             -- SHA-256 hash of the actual token
    user_id TEXT NOT NULL,
    device_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    expires_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_access_tokens_hash ON access_tokens(token_hash);

-- Rooms
CREATE TABLE IF NOT EXISTS rooms (
    room_id TEXT PRIMARY KEY,                    -- !opaque_id:domain format
    room_version TEXT NOT NULL DEFAULT '10',
    is_public INTEGER DEFAULT 0,
    creator_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

-- Room state (current state)
CREATE TABLE IF NOT EXISTS room_state (
    room_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    state_key TEXT NOT NULL DEFAULT '',
    event_id TEXT NOT NULL,
    PRIMARY KEY (room_id, event_type, state_key),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_room_state_event ON room_state(event_id);

-- Room aliases
CREATE TABLE IF NOT EXISTS room_aliases (
    alias TEXT PRIMARY KEY,                      -- #alias:domain format
    room_id TEXT NOT NULL,
    creator_id TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_room_aliases_room ON room_aliases(room_id);

-- Events (the core of Matrix)
CREATE TABLE IF NOT EXISTS events (
    event_id TEXT PRIMARY KEY,                   -- $base64:domain format
    room_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    event_type TEXT NOT NULL,
    state_key TEXT,                              -- NULL for non-state events
    content TEXT NOT NULL,                       -- JSON blob
    origin_server_ts INTEGER NOT NULL,
    unsigned TEXT,                               -- JSON blob for unsigned data
    depth INTEGER NOT NULL,
    auth_events TEXT NOT NULL,                   -- JSON array of event IDs
    prev_events TEXT NOT NULL,                   -- JSON array of event IDs
    hashes TEXT,                                 -- JSON blob for content hashes
    signatures TEXT,                             -- JSON blob for signatures
    stream_ordering INTEGER,                     -- For sync ordering
    FOREIGN KEY (room_id) REFERENCES rooms(room_id)
);
CREATE INDEX IF NOT EXISTS idx_events_room ON events(room_id);
CREATE INDEX IF NOT EXISTS idx_events_sender ON events(sender);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_stream ON events(stream_ordering);
CREATE INDEX IF NOT EXISTS idx_events_room_stream ON events(room_id, stream_ordering);
CREATE INDEX IF NOT EXISTS idx_events_room_depth ON events(room_id, depth);

-- Room memberships (denormalized for fast lookups)
CREATE TABLE IF NOT EXISTS room_memberships (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    membership TEXT NOT NULL,                    -- 'join', 'invite', 'leave', 'ban', 'knock'
    event_id TEXT NOT NULL,
    display_name TEXT,
    avatar_url TEXT,
    PRIMARY KEY (room_id, user_id),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_memberships_user ON room_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_memberships_state ON room_memberships(membership);

-- Event relations (for threads, reactions, edits)
CREATE TABLE IF NOT EXISTS event_relations (
    event_id TEXT NOT NULL,
    relates_to_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,                 -- 'm.annotation', 'm.replace', 'm.thread', etc.
    aggregation_key TEXT,                        -- For reactions, the emoji
    PRIMARY KEY (event_id, relates_to_id, relation_type),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_relations_target ON event_relations(relates_to_id);
CREATE INDEX IF NOT EXISTS idx_relations_type ON event_relations(relation_type);

-- Push rules (per-user notification settings)
CREATE TABLE IF NOT EXISTS push_rules (
    user_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    kind TEXT NOT NULL,                          -- 'override', 'underride', 'sender', 'room', 'content'
    priority INTEGER NOT NULL,
    conditions TEXT,                             -- JSON array
    actions TEXT NOT NULL,                       -- JSON array
    enabled INTEGER DEFAULT 1,
    PRIMARY KEY (user_id, kind, rule_id),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Account data (per-user settings)
CREATE TABLE IF NOT EXISTS account_data (
    user_id TEXT NOT NULL,
    room_id TEXT NOT NULL DEFAULT '',            -- Empty string for global account data
    event_type TEXT NOT NULL,
    content TEXT NOT NULL,                       -- JSON blob
    PRIMARY KEY (user_id, room_id, event_type),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Presence
CREATE TABLE IF NOT EXISTS presence (
    user_id TEXT PRIMARY KEY,
    presence TEXT NOT NULL DEFAULT 'offline',    -- 'online', 'offline', 'unavailable'
    status_msg TEXT,
    last_active_ts INTEGER,
    currently_active INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Receipts (read markers)
CREATE TABLE IF NOT EXISTS receipts (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    receipt_type TEXT NOT NULL,                  -- 'm.read', 'm.read.private', etc.
    event_id TEXT NOT NULL,
    thread_id TEXT NOT NULL DEFAULT '',          -- Empty string for main timeline
    ts INTEGER NOT NULL,
    PRIMARY KEY (room_id, user_id, receipt_type, thread_id),
    FOREIGN KEY (room_id) REFERENCES rooms(room_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_receipts_event ON receipts(event_id);

-- Typing notifications (ephemeral, but tracked for sync)
CREATE TABLE IF NOT EXISTS typing (
    room_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    timeout_ts INTEGER NOT NULL,
    PRIMARY KEY (room_id, user_id)
);

-- Federation servers we know about
CREATE TABLE IF NOT EXISTS servers (
    server_name TEXT PRIMARY KEY,
    signing_keys TEXT,                           -- JSON blob of verify keys
    valid_until_ts INTEGER,
    last_successful_fetch INTEGER,
    retry_count INTEGER DEFAULT 0
);

-- Outbound federation queue
CREATE TABLE IF NOT EXISTS federation_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    destination TEXT NOT NULL,
    event_id TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    retry_count INTEGER DEFAULT 0,
    next_retry_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_federation_queue_dest ON federation_queue(destination);
CREATE INDEX IF NOT EXISTS idx_federation_queue_retry ON federation_queue(next_retry_at);

-- Media metadata
CREATE TABLE IF NOT EXISTS media (
    media_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    content_type TEXT NOT NULL,
    content_length INTEGER NOT NULL,
    filename TEXT,
    upload_name TEXT,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    quarantined INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);

-- Thumbnails metadata
CREATE TABLE IF NOT EXISTS thumbnails (
    media_id TEXT NOT NULL,
    width INTEGER NOT NULL,
    height INTEGER NOT NULL,
    method TEXT NOT NULL,                        -- 'crop' or 'scale'
    content_type TEXT NOT NULL,
    content_length INTEGER NOT NULL,
    PRIMARY KEY (media_id, width, height, method),
    FOREIGN KEY (media_id) REFERENCES media(media_id) ON DELETE CASCADE
);

-- Server signing keys
CREATE TABLE IF NOT EXISTS server_keys (
    key_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    private_key TEXT NOT NULL,                   -- Encrypted
    valid_from INTEGER NOT NULL,
    valid_until INTEGER,
    is_current INTEGER DEFAULT 1
);

-- Stream position tracking for sync
CREATE TABLE IF NOT EXISTS sync_tokens (
    user_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    token TEXT NOT NULL,
    stream_position INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (user_id, device_id, token)
);

-- Rate limiting
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,                        -- IP or user_id
    action_type TEXT NOT NULL,
    count INTEGER NOT NULL DEFAULT 1,
    window_start INTEGER NOT NULL
);
