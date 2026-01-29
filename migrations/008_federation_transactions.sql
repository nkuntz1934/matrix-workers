-- Federation Transaction and PDU Tracking
-- For transaction deduplication and PDU processing state

-- Track processed federation transactions for idempotency
-- Same txnId from same origin should return same response
CREATE TABLE IF NOT EXISTS federation_transactions (
  txn_id TEXT NOT NULL,
  origin TEXT NOT NULL,
  received_at INTEGER NOT NULL,
  response TEXT,
  PRIMARY KEY (origin, txn_id)
);

CREATE INDEX IF NOT EXISTS idx_fed_txn_cleanup ON federation_transactions(received_at);

-- Track processed PDUs to avoid reprocessing
CREATE TABLE IF NOT EXISTS processed_pdus (
  event_id TEXT PRIMARY KEY,
  origin TEXT NOT NULL,
  room_id TEXT NOT NULL,
  processed_at INTEGER NOT NULL,
  accepted INTEGER NOT NULL DEFAULT 1,
  rejection_reason TEXT
);

CREATE INDEX IF NOT EXISTS idx_processed_pdus_room ON processed_pdus(room_id);
CREATE INDEX IF NOT EXISTS idx_processed_pdus_origin ON processed_pdus(origin);

-- Track EDU processing state (for typing, presence, device_lists, etc.)
CREATE TABLE IF NOT EXISTS processed_edus (
  edu_id TEXT PRIMARY KEY,
  edu_type TEXT NOT NULL,
  origin TEXT NOT NULL,
  processed_at INTEGER NOT NULL,
  content TEXT
);

CREATE INDEX IF NOT EXISTS idx_processed_edus_type ON processed_edus(edu_type);
CREATE INDEX IF NOT EXISTS idx_processed_edus_origin ON processed_edus(origin);

-- Remote server keys cache (extends existing table)
CREATE TABLE IF NOT EXISTS remote_server_keys (
  server_name TEXT NOT NULL,
  key_id TEXT NOT NULL,
  public_key TEXT NOT NULL,
  valid_from INTEGER NOT NULL,
  valid_until INTEGER,
  fetched_at INTEGER NOT NULL,
  verified INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server_name, key_id)
);

CREATE INDEX IF NOT EXISTS idx_remote_keys_valid ON remote_server_keys(valid_until);
