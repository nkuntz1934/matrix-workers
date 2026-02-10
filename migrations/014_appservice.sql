-- Migration: Application Service Support
-- Adds tables for AS registration and transaction tracking

CREATE TABLE IF NOT EXISTS appservice_registrations (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,                              -- HS → AS URL
    as_token TEXT NOT NULL UNIQUE,                  -- Token the AS uses to auth with HS
    hs_token TEXT NOT NULL UNIQUE,                  -- Token the HS uses to auth with AS
    sender_localpart TEXT NOT NULL,                 -- User localpart the AS uses
    rate_limited INTEGER NOT NULL DEFAULT 1,
    protocols TEXT,                                 -- JSON array of protocols
    namespaces TEXT NOT NULL,                       -- JSON: {users: [], rooms: [], aliases: []}
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000)
);

CREATE INDEX IF NOT EXISTS idx_appservice_as_token ON appservice_registrations(as_token);
CREATE INDEX IF NOT EXISTS idx_appservice_hs_token ON appservice_registrations(hs_token);

CREATE TABLE IF NOT EXISTS appservice_transactions (
    txn_id INTEGER PRIMARY KEY AUTOINCREMENT,
    appservice_id TEXT NOT NULL,
    events TEXT NOT NULL,                           -- JSON array of events
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    sent_at INTEGER,
    retry_count INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (appservice_id) REFERENCES appservice_registrations(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_appservice_txn_as ON appservice_transactions(appservice_id);
CREATE INDEX IF NOT EXISTS idx_appservice_txn_unsent ON appservice_transactions(sent_at) WHERE sent_at IS NULL;
