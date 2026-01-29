-- Migration: Extended Reports Support
-- Adds support for room reports and user reports in addition to event reports

-- Add report_type column to distinguish between event, room, and user reports
-- Default to 'event' for backwards compatibility with existing reports
ALTER TABLE content_reports ADD COLUMN report_type TEXT NOT NULL DEFAULT 'event';

-- Add reported_user_id column for user reports
ALTER TABLE content_reports ADD COLUMN reported_user_id TEXT;

-- Drop the NOT NULL constraint on room_id and event_id by recreating relevant indexes
-- (SQLite doesn't support DROP CONSTRAINT, but the columns already allow NULL in practice)

-- Create index for user reports
CREATE INDEX IF NOT EXISTS idx_content_reports_reported_user ON content_reports(reported_user_id);

-- Create index for report type filtering
CREATE INDEX IF NOT EXISTS idx_content_reports_type ON content_reports(report_type);

-- Update existing unique constraint to allow room-only reports (NULL event_id)
-- Note: SQLite unique indexes treat each NULL as distinct, so this works naturally
-- But we still want an index for the new report patterns
CREATE INDEX IF NOT EXISTS idx_content_reports_room_report ON content_reports(reporter_user_id, room_id) WHERE event_id IS NULL AND report_type = 'room';
CREATE INDEX IF NOT EXISTS idx_content_reports_user_report ON content_reports(reporter_user_id, reported_user_id) WHERE report_type = 'user';
