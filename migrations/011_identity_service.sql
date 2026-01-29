-- Migration: Identity Service Integration
-- Adds support for email verification sessions for 3PID management

-- Email verification sessions for 3PID validation
CREATE TABLE IF NOT EXISTS email_verification_sessions (
    session_id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    user_id TEXT,                                 -- NULL during registration, set for account binding
    client_secret TEXT NOT NULL,
    token TEXT NOT NULL,                          -- 6-digit verification code
    send_attempt INTEGER NOT NULL DEFAULT 1,
    validated INTEGER NOT NULL DEFAULT 0,
    validated_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_email_sessions_email ON email_verification_sessions(email);
CREATE INDEX IF NOT EXISTS idx_email_sessions_token ON email_verification_sessions(token);
CREATE INDEX IF NOT EXISTS idx_email_sessions_expires ON email_verification_sessions(expires_at);
