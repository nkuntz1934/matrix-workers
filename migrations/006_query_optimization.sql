-- Query Optimization Indexes
-- These indexes dramatically improve sliding-sync performance by eliminating table scans

-- Index for room state lookups by type (critical for name/avatar/topic queries)
-- Used in: sliding-sync.ts getUserRooms(), getRoomData()
CREATE INDEX IF NOT EXISTS idx_room_state_room_type
ON room_state(room_id, event_type);

-- Composite index for membership queries with room filtering
-- Used in: sliding-sync.ts member count queries, DM detection
CREATE INDEX IF NOT EXISTS idx_memberships_room_membership
ON room_memberships(room_id, membership);

-- Index for events by room and type (for finding latest state events)
-- Used in: sliding-sync.ts timeline queries, state lookups
CREATE INDEX IF NOT EXISTS idx_events_room_type
ON events(room_id, event_type);

-- Index for account data lookups (for notification counts, read markers)
-- Used in: sliding-sync.ts notification count calculation
CREATE INDEX IF NOT EXISTS idx_account_data_user_room_type
ON account_data(user_id, room_id, event_type);
