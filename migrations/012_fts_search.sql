-- Migration: Full-Text Search with FTS5
-- Adds FTS5 virtual tables for event content and user directory search

-- FTS5 virtual table for event content search
CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    event_id UNINDEXED,
    room_id UNINDEXED,
    sender UNINDEXED,
    body,
    content='events',
    content_rowid='rowid'
);

-- Trigger to keep FTS index in sync on insert
CREATE TRIGGER IF NOT EXISTS events_fts_insert AFTER INSERT ON events
WHEN NEW.event_type = 'm.room.message'
BEGIN
    INSERT INTO events_fts(rowid, event_id, room_id, sender, body)
    VALUES (NEW.rowid, NEW.event_id, NEW.room_id, NEW.sender,
            json_extract(NEW.content, '$.body'));
END;

-- Trigger to handle deletes
CREATE TRIGGER IF NOT EXISTS events_fts_delete AFTER DELETE ON events
WHEN OLD.event_type = 'm.room.message'
BEGIN
    INSERT INTO events_fts(events_fts, rowid, event_id, room_id, sender, body)
    VALUES ('delete', OLD.rowid, OLD.event_id, OLD.room_id, OLD.sender,
            json_extract(OLD.content, '$.body'));
END;

-- FTS5 virtual table for user directory search
CREATE VIRTUAL TABLE IF NOT EXISTS users_fts USING fts5(
    user_id UNINDEXED,
    localpart,
    display_name,
    content='users',
    content_rowid='rowid'
);

-- Trigger to keep user FTS in sync
CREATE TRIGGER IF NOT EXISTS users_fts_insert AFTER INSERT ON users
BEGIN
    INSERT INTO users_fts(rowid, user_id, localpart, display_name)
    VALUES (NEW.rowid, NEW.user_id, NEW.localpart, NEW.display_name);
END;

CREATE TRIGGER IF NOT EXISTS users_fts_update AFTER UPDATE ON users
BEGIN
    INSERT INTO users_fts(users_fts, rowid, user_id, localpart, display_name)
    VALUES ('delete', OLD.rowid, OLD.user_id, OLD.localpart, OLD.display_name);
    INSERT INTO users_fts(rowid, user_id, localpart, display_name)
    VALUES (NEW.rowid, NEW.user_id, NEW.localpart, NEW.display_name);
END;

CREATE TRIGGER IF NOT EXISTS users_fts_delete AFTER DELETE ON users
BEGIN
    INSERT INTO users_fts(users_fts, rowid, user_id, localpart, display_name)
    VALUES ('delete', OLD.rowid, OLD.user_id, OLD.localpart, OLD.display_name);
END;
