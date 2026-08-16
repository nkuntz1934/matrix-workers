-- Migration 017: Query optimization and event size limits (issue 004 items 4-6)
--
-- Adds the indexes that support the batched required_state query and the
-- combined room-state lookups used by sliding sync. The 1MB row-size limit
-- is enforced at the application layer in src/services/database.ts
-- (validateEventSize); there is no SQL-level size check for TEXT columns
-- in SQLite, so this migration is index-only.

-- Composite index on (room_id, event_type, state_key) accelerates the OR-ed
-- required_state query that replaced the per-type N+1 loop. Existing
-- idx_room_state_room_type only covers (room_id, event_type).
CREATE INDEX IF NOT EXISTS idx_room_state_room_type_key
ON room_state(room_id, event_type, state_key);

-- Index supporting bounded auth-chain traversal: getEventsByIds pages through
-- the input list in chunks of 100. The events PRIMARY KEY already covers
-- event_id lookups; this index speeds up reverse lookups by sender used in
-- some auth checks.
CREATE INDEX IF NOT EXISTS idx_events_sender_type
ON events(sender, event_type);
