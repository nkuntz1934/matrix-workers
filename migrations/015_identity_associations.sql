-- Migration: Identity Service Associations
-- Stores 3PID → MXID lookup associations

CREATE TABLE IF NOT EXISTS identity_associations (
    medium TEXT NOT NULL,                           -- 'email' or 'msisdn'
    address TEXT NOT NULL,                          -- The 3PID (e.g., email address)
    mxid TEXT NOT NULL,                             -- The Matrix user ID
    ts INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    not_before INTEGER NOT NULL DEFAULT 0,
    not_after INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (medium, address)
);

CREATE INDEX IF NOT EXISTS idx_identity_mxid ON identity_associations(mxid);
CREATE INDEX IF NOT EXISTS idx_identity_medium ON identity_associations(medium);
