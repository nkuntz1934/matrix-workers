-- Migration: Account Management
-- Adds support for third-party identifiers (3PIDs) like email and phone

-- User third-party identifiers (email, phone)
CREATE TABLE IF NOT EXISTS user_threepids (
    user_id TEXT NOT NULL,
    medium TEXT NOT NULL,                        -- 'email' or 'msisdn'
    address TEXT NOT NULL,                       -- The actual email/phone number
    validated_at INTEGER NOT NULL,               -- When it was validated (timestamp ms)
    added_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    PRIMARY KEY (medium, address),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_threepids_user ON user_threepids(user_id);

-- Add relation columns to events table for relations/threads if they don't exist
-- Note: D1 doesn't support ALTER TABLE ADD COLUMN IF NOT EXISTS, so we check first
-- This should be done manually or via application code
