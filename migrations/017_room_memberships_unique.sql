-- Migration 017: Reinforce room operation race-condition guards (issue #009)
--
-- 1. Re-affirm the unique constraint on room_memberships(room_id, user_id).
--    Migration 016 already added this; the IF NOT EXISTS makes it safe to
--    apply again on partially-migrated databases.
-- 2. Add a unique index on events(event_id) is unnecessary (PRIMARY KEY).
-- 3. Add a fast lookup index on events(room_id, event_type, sender) used by
--    the deterministic-id idempotent join path so duplicate join writes can
--    be detected cheaply when INSERT OR IGNORE silently skips them.
-- 4. Ensure account_data table tolerates a "version" column for optimistic
--    concurrency. SQLite cannot ADD COLUMN IF NOT EXISTS prior to 3.35;
--    D1 does support it, but we guard with a permissive ALTER that fails
--    silently if the column already exists by wrapping in a try-block at
--    the application layer. Here we only add the column; rerunning the
--    migration on a DB that already has it will error and should be a noop
--    (D1 ignores migration files that have already run via the migrations
--    table maintained by wrangler).

CREATE UNIQUE INDEX IF NOT EXISTS idx_memberships_unique ON room_memberships(room_id, user_id);

-- Speeds up duplicate-detection lookups for deterministic join event IDs.
CREATE INDEX IF NOT EXISTS idx_events_room_type_sender ON events(room_id, event_type, sender);

-- Add an optional version column to account_data to support optimistic
-- concurrency. New writes can supply a version; clients that don't care
-- can omit it. NULL means "unversioned" and behaves like the previous
-- last-write-wins semantics.
ALTER TABLE account_data ADD COLUMN version INTEGER NOT NULL DEFAULT 0;
