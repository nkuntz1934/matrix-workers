-- Migration: Fix content_reports schema to allow nullable room_id and event_id
-- Required for room reports (no event_id) and user reports (no room_id or event_id)

-- Create new table with correct schema
CREATE TABLE content_reports_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reporter_user_id TEXT NOT NULL,
    room_id TEXT,                    -- Nullable for user reports
    event_id TEXT,                   -- Nullable for room/user reports
    reason TEXT NOT NULL DEFAULT '',
    score INTEGER NOT NULL DEFAULT -100,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now') * 1000),
    resolved INTEGER NOT NULL DEFAULT 0,
    resolved_by TEXT,
    resolved_at INTEGER,
    resolution_note TEXT,
    report_type TEXT NOT NULL DEFAULT 'event',
    reported_user_id TEXT,
    FOREIGN KEY (reporter_user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

-- Copy existing data
INSERT INTO content_reports_new
    (id, reporter_user_id, room_id, event_id, reason, score, created_at, resolved, resolved_by, resolved_at, resolution_note, report_type, reported_user_id)
SELECT
    id, reporter_user_id, room_id, event_id, reason, score, created_at, resolved, resolved_by, resolved_at, resolution_note, report_type, reported_user_id
FROM content_reports;

-- Drop old table
DROP TABLE content_reports;

-- Rename new table
ALTER TABLE content_reports_new RENAME TO content_reports;

-- Recreate indexes
CREATE INDEX idx_content_reports_reporter ON content_reports(reporter_user_id);
CREATE INDEX idx_content_reports_room ON content_reports(room_id);
CREATE INDEX idx_content_reports_resolved ON content_reports(resolved, created_at);
CREATE INDEX idx_content_reports_reported_user ON content_reports(reported_user_id);
CREATE INDEX idx_content_reports_type ON content_reports(report_type);

-- Unique constraint for event reports
CREATE UNIQUE INDEX idx_content_reports_unique_event ON content_reports(reporter_user_id, room_id, event_id)
    WHERE report_type = 'event';

-- Unique constraint for room reports
CREATE UNIQUE INDEX idx_content_reports_unique_room ON content_reports(reporter_user_id, room_id)
    WHERE report_type = 'room' AND event_id IS NULL;

-- Unique constraint for user reports
CREATE UNIQUE INDEX idx_content_reports_unique_user ON content_reports(reporter_user_id, reported_user_id)
    WHERE report_type = 'user';
