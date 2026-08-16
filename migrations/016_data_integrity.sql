-- Migration 016: Data integrity improvements
-- Adds missing indexes, unique constraints, and a stream_positions backfill
-- to fix race conditions and improve cleanup performance.

-- Ensure stream_positions for 'events' is in sync with actual data.
-- This is a one-time backfill for the atomic stream ordering fix.
UPDATE stream_positions
SET position = COALESCE((SELECT MAX(stream_ordering) FROM events), 0)
WHERE stream_name = 'events';

-- Add unique constraint on stream_ordering to prevent duplicates (safety net).
-- D1/SQLite allows CREATE UNIQUE INDEX on existing data if no dupes exist.
CREATE UNIQUE INDEX IF NOT EXISTS idx_events_stream_unique ON events(stream_ordering);

-- Add indexes on notification_queue for efficient cascade-like cleanup
CREATE INDEX IF NOT EXISTS idx_notification_queue_room ON notification_queue(room_id);
CREATE INDEX IF NOT EXISTS idx_notification_queue_event ON notification_queue(event_id);

-- Add index on to_device_messages for sender cleanup
CREATE INDEX IF NOT EXISTS idx_to_device_sender ON to_device_messages(sender_user_id);

-- Add index on event_relations.relates_to_id for cascade-like cleanup
-- (idx_relations_target already exists, but verify)

-- Add index on key_backup_keys for room cleanup
CREATE INDEX IF NOT EXISTS idx_key_backup_room ON key_backup_keys(room_id);

-- Add index for content_reports cleanup
CREATE INDEX IF NOT EXISTS idx_content_reports_user ON content_reports(reported_user_id);
CREATE INDEX IF NOT EXISTS idx_content_reports_room ON content_reports(room_id);
CREATE INDEX IF NOT EXISTS idx_content_reports_event ON content_reports(event_id);

-- Add unique constraint on room_memberships to prevent duplicate joins
CREATE UNIQUE INDEX IF NOT EXISTS idx_memberships_unique ON room_memberships(room_id, user_id);
