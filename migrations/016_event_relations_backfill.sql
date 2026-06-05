-- Migration: Event relations persistence and backfill
-- Keeps Matrix relations/threads out of JSON-only event content so relations endpoints
-- continue to work after deploys and on databases that predate relation persistence.

CREATE TABLE IF NOT EXISTS event_relations (
    event_id TEXT NOT NULL,
    relates_to_id TEXT NOT NULL,
    relation_type TEXT NOT NULL,
    aggregation_key TEXT,
    PRIMARY KEY (event_id, relates_to_id, relation_type),
    FOREIGN KEY (event_id) REFERENCES events(event_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_relations_target ON event_relations(relates_to_id);
CREATE INDEX IF NOT EXISTS idx_relations_type ON event_relations(relation_type);
CREATE INDEX IF NOT EXISTS idx_relations_target_type ON event_relations(relates_to_id, relation_type);

INSERT OR IGNORE INTO event_relations (event_id, relates_to_id, relation_type, aggregation_key)
SELECT
    event_id,
    json_extract(content, '$."m.relates_to".event_id'),
    json_extract(content, '$."m.relates_to".rel_type'),
    json_extract(content, '$."m.relates_to".key')
FROM events
WHERE json_type(content, '$."m.relates_to"') = 'object'
  AND json_type(content, '$."m.relates_to".event_id') = 'text'
  AND json_type(content, '$."m.relates_to".rel_type') = 'text';
