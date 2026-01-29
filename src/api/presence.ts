// Presence API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#presence
//
// Presence indicates whether users are online, offline, or unavailable.
// Status messages can also be set.

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';

const app = new Hono<AppEnv>();

// ============================================
// Constants
// ============================================

const PRESENCE_TIMEOUT = 5 * 60 * 1000; // 5 minutes - consider offline after this

// ============================================
// Endpoints
// ============================================

// PUT /_matrix/client/v3/presence/:userId/status - Set presence status
app.put('/_matrix/client/v3/presence/:userId/status', requireAuth(), async (c) => {
  const requestingUserId = c.get('userId');
  const targetUserId = c.req.param('userId');
  const db = c.env.DB;

  // Users can only set their own presence
  if (requestingUserId !== targetUserId) {
    return Errors.forbidden('Cannot set presence for other users').toResponse();
  }

  let body: { presence: string; status_msg?: string };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { presence, status_msg } = body;

  // Validate presence state
  const validStates = ['online', 'offline', 'unavailable'];
  if (!presence || !validStates.includes(presence)) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: `Invalid presence state: ${presence}. Must be one of: ${validStates.join(', ')}`,
    }, 400);
  }

  const now = Date.now();

  // Store presence in D1
  await db.prepare(`
    INSERT INTO presence (user_id, presence, status_msg, last_active_ts)
    VALUES (?, ?, ?, ?)
    ON CONFLICT (user_id) DO UPDATE SET
      presence = excluded.presence,
      status_msg = excluded.status_msg,
      last_active_ts = excluded.last_active_ts
  `).bind(requestingUserId, presence, status_msg || null, now).run();

  // Write-through to KV cache for fast reads (5 minute TTL)
  await c.env.CACHE.put(
    `presence:${requestingUserId}`,
    JSON.stringify({
      presence,
      status_msg: status_msg || null,
      last_active_ts: now,
    }),
    { expirationTtl: 5 * 60 } // 5 minutes
  );

  return c.json({});
});

// GET /_matrix/client/v3/presence/:userId/status - Get presence status
app.get('/_matrix/client/v3/presence/:userId/status', requireAuth(), async (c) => {
  const targetUserId = c.req.param('userId');
  const db = c.env.DB;

  // Check if target user exists
  const user = await db.prepare(`
    SELECT user_id FROM users WHERE user_id = ?
  `).bind(targetUserId).first();

  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Try KV cache first for faster reads
  const cached = await c.env.CACHE.get(`presence:${targetUserId}`, 'json') as {
    presence: string;
    status_msg: string | null;
    last_active_ts: number;
  } | null;

  let presence: {
    presence: string;
    status_msg: string | null;
    last_active_ts: number;
  } | null = cached;

  // Fall back to D1 if not in cache
  if (!presence) {
    presence = await db.prepare(`
      SELECT presence, status_msg, last_active_ts
      FROM presence
      WHERE user_id = ?
    `).bind(targetUserId).first<{
      presence: string;
      status_msg: string | null;
      last_active_ts: number;
    }>();
  }

  if (!presence) {
    // Default to offline if no presence set
    return c.json({
      presence: 'offline',
      currently_active: false,
    });
  }

  const now = Date.now();
  const isActive = (now - presence.last_active_ts) < PRESENCE_TIMEOUT;

  // If presence was set to online but they've been inactive, report as unavailable
  let effectivePresence = presence.presence;
  if (presence.presence === 'online' && !isActive) {
    effectivePresence = 'unavailable';
  }

  return c.json({
    presence: effectivePresence,
    status_msg: presence.status_msg || undefined,
    last_active_ago: now - presence.last_active_ts,
    currently_active: isActive && presence.presence === 'online',
  });
});

// ============================================
// Internal Helpers
// ============================================

// Get presence for multiple users (for sync)
// This function requires KVNamespace to be passed for caching
export async function getPresenceForUsers(
  db: D1Database,
  userIds: string[],
  cache?: KVNamespace
): Promise<Record<string, {
  presence: string;
  status_msg?: string;
  last_active_ago?: number;
  currently_active?: boolean;
}>> {
  if (userIds.length === 0) return {};

  const now = Date.now();
  const byUser: Record<string, {
    presence: string;
    status_msg?: string;
    last_active_ago?: number;
    currently_active?: boolean;
  }> = {};

  const uncachedUserIds: string[] = [];

  // Try to get from KV cache first
  if (cache) {
    for (const userId of userIds) {
      const cached = await cache.get(`presence:${userId}`, 'json') as {
        presence: string;
        status_msg: string | null;
        last_active_ts: number;
      } | null;

      if (cached) {
        const isActive = (now - cached.last_active_ts) < PRESENCE_TIMEOUT;
        let effectivePresence = cached.presence;
        if (cached.presence === 'online' && !isActive) {
          effectivePresence = 'unavailable';
        }

        byUser[userId] = {
          presence: effectivePresence,
          status_msg: cached.status_msg || undefined,
          last_active_ago: now - cached.last_active_ts,
          currently_active: isActive && cached.presence === 'online',
        };
      } else {
        uncachedUserIds.push(userId);
      }
    }
  } else {
    uncachedUserIds.push(...userIds);
  }

  // Fall back to D1 for uncached users
  if (uncachedUserIds.length > 0) {
    const placeholders = uncachedUserIds.map(() => '?').join(',');

    const results = await db.prepare(`
      SELECT user_id, presence, status_msg, last_active_ts
      FROM presence
      WHERE user_id IN (${placeholders})
    `).bind(...uncachedUserIds).all<{
      user_id: string;
      presence: string;
      status_msg: string | null;
      last_active_ts: number;
    }>();

    for (const row of results.results) {
      const isActive = (now - row.last_active_ts) < PRESENCE_TIMEOUT;
      let effectivePresence = row.presence;
      if (row.presence === 'online' && !isActive) {
        effectivePresence = 'unavailable';
      }

      byUser[row.user_id] = {
        presence: effectivePresence,
        status_msg: row.status_msg || undefined,
        last_active_ago: now - row.last_active_ts,
        currently_active: isActive && row.presence === 'online',
      };
    }
  }

  return byUser;
}

// Update last active timestamp (call this on API activity)
export async function updateLastActive(
  db: D1Database,
  userId: string
): Promise<void> {
  const now = Date.now();

  await db.prepare(`
    UPDATE presence SET last_active_ts = ? WHERE user_id = ?
  `).bind(now, userId).run();
}

export default app;
