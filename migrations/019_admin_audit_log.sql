-- Migration 019: Admin audit log
--
-- Records every privileged admin API operation so that suspend/deactivate/
-- reset-password/config-change etc. can be investigated after the fact.
-- Inserts only — no DELETE/UPDATE codepath in the application — so the table
-- functions as an append-only log.
--
-- Note: numbering is tentatively-high. Other in-flight branches (M1, M2)
-- may also add migrations; if a collision occurs at merge time, renumber
-- this file before applying.

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,                 -- ms since epoch
  actor_user_id TEXT NOT NULL,         -- admin who performed the action
  action TEXT NOT NULL,                -- short stable identifier, e.g. 'user.reset_password'
  target TEXT,                         -- target user_id / room_id / resource id (nullable)
  ip TEXT,                             -- best-effort source IP (CF-Connecting-IP)
  success INTEGER NOT NULL DEFAULT 1,  -- 1 = success, 0 = failure
  details TEXT                         -- optional JSON blob for extra context
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_ts ON admin_audit_log(ts DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_actor ON admin_audit_log(actor_user_id, ts DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_target ON admin_audit_log(target, ts DESC);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action ON admin_audit_log(action, ts DESC);
