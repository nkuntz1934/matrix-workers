// Admin audit log helper.
//
// Records privileged admin API operations to the `admin_audit_log` table
// (migration 019). Append-only; only the application reads — operators
// query via the dedicated GET /admin/api/audit endpoint.

import type { Context } from 'hono';
import type { AppEnv } from '../types';

export interface AuditEntry {
  action: string;
  target?: string | null;
  success?: boolean;
  details?: unknown;
}

// Best-effort source IP extraction. Mirrors the rate-limit middleware:
// CF-Connecting-IP is authoritative on Cloudflare; X-Forwarded-For is only
// trusted when explicitly opted in via TRUST_FORWARDED_FOR.
export function getActorIp(c: Context<AppEnv>): string | null {
  const cf = c.req.header('CF-Connecting-IP');
  if (cf) return cf;
  if (c.env.TRUST_FORWARDED_FOR === 'true') {
    const xff = c.req.header('X-Forwarded-For');
    const first = xff?.split(',')[0]?.trim();
    if (first) return first;
  }
  return null;
}

// Write a single audit log entry. Failures are logged but never surfaced —
// the audit log must not break the admin operation it is recording.
export async function logAdminAction(
  c: Context<AppEnv>,
  entry: AuditEntry,
): Promise<void> {
  const actor = c.get('userId');
  if (!actor) {
    // Should be unreachable behind requireAuth+requireAdmin, but stay defensive.
    console.warn('[admin-audit] logAdminAction called without userId; skipping');
    return;
  }

  try {
    await c.env.DB.prepare(
      `INSERT INTO admin_audit_log (ts, actor_user_id, action, target, ip, success, details)
       VALUES (?, ?, ?, ?, ?, ?, ?)`,
    )
      .bind(
        Date.now(),
        actor,
        entry.action,
        entry.target ?? null,
        getActorIp(c),
        entry.success === false ? 0 : 1,
        entry.details === undefined ? null : JSON.stringify(entry.details),
      )
      .run();
  } catch (err) {
    console.error('[admin-audit] Failed to write audit entry:', err);
  }
}
