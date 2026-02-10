// Admin API endpoints

import { Hono } from 'hono';
import { createMiddleware } from 'hono/factory';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';
import { getUserById } from '../services/database';
import { generateLoginToken, generateOpaqueId } from '../utils/ids';
import { hashToken } from '../utils/crypto';
import { encryptSecret } from './oidc-auth';
import { fetchOIDCDiscovery } from '../services/oidc';

const app = new Hono<AppEnv>();

// Admin authentication middleware
const requireAdmin = createMiddleware<AppEnv>(async (c, next) => {
  const userId = c.get('userId');
  if (!userId) {
    return Errors.unauthorized('Admin access required').toResponse();
  }

  const user = await getUserById(c.env.DB, userId);
  if (!user || !user.admin) {
    return Errors.forbidden('Admin privileges required').toResponse();
  }

  return next();
});

// Helper to get AdminDurableObject instance
function getAdminDO(env: import('../types').Env) {
  const id = env.ADMIN.idFromName('global');
  return env.ADMIN.get(id);
}

// Invalidate stats cache after data-modifying operations
async function invalidateStatsCache(env: import('../types').Env) {
  const adminDO = getAdminDO(env);
  await adminDO.fetch('http://internal/invalidate-cache');
}

// GET /admin/api/stats - Server statistics (via AdminDurableObject for caching)
app.get('/admin/api/stats', requireAuth(), requireAdmin, async (c) => {
  const refresh = c.req.query('refresh') === 'true';
  const adminDO = getAdminDO(c.env);

  const url = new URL('/stats', 'http://internal');
  if (refresh) {
    url.searchParams.set('refresh', 'true');
  }

  const response = await adminDO.fetch(url.toString());
  const stats = await response.json() as Record<string, unknown>;

  // Add server info
  return c.json({
    ...stats,
    server: {
      name: c.env.SERVER_NAME,
      version: c.env.SERVER_VERSION,
    },
  });
});

// GET /admin/api/stats/history - Time-series statistics for dashboard charts
app.get('/admin/api/stats/history', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const period = c.req.query('period') || '7d';

  // Parse period and calculate date range
  let days: number;
  if (period === '30d') {
    days = 30;
  } else {
    days = 7; // Default to 7d
  }

  const now = Date.now();
  const startTime = now - days * 24 * 60 * 60 * 1000;

  // Generate array of dates for the period (to fill in gaps with zeros)
  const dateKeys: string[] = [];
  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(now - i * 24 * 60 * 60 * 1000);
    dateKeys.push(date.toISOString().split('T')[0]); // YYYY-MM-DD format
  }

  // Query events grouped by day
  // D1/SQLite: divide by 86400000 (ms per day) to get day buckets
  const eventsQuery = await db.prepare(`
    SELECT DATE(origin_server_ts / 1000, 'unixepoch') as date, COUNT(*) as count
    FROM events
    WHERE origin_server_ts >= ?
    GROUP BY DATE(origin_server_ts / 1000, 'unixepoch')
    ORDER BY date
  `).bind(startTime).all<{ date: string; count: number }>();

  // Query user registrations grouped by day
  const registrationsQuery = await db.prepare(`
    SELECT DATE(created_at / 1000, 'unixepoch') as date, COUNT(*) as count
    FROM users
    WHERE created_at >= ?
    GROUP BY DATE(created_at / 1000, 'unixepoch')
    ORDER BY date
  `).bind(startTime).all<{ date: string; count: number }>();

  // Convert query results to maps for easy lookup
  const eventsMap = new Map<string, number>();
  for (const row of eventsQuery.results) {
    eventsMap.set(row.date, row.count);
  }

  const registrationsMap = new Map<string, number>();
  for (const row of registrationsQuery.results) {
    registrationsMap.set(row.date, row.count);
  }

  // Build the response data array, filling in zeros for missing dates
  const data = dateKeys.map(date => ({
    date,
    events: eventsMap.get(date) || 0,
    registrations: registrationsMap.get(date) || 0,
  }));

  return c.json({
    period: period === '30d' ? '30d' : '7d',
    data,
  });
});

// GET /admin/api/users - List all users
app.get('/admin/api/users', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const offset = parseInt(c.req.query('offset') || '0');
  const search = c.req.query('search');

  let query = `
    SELECT user_id, localpart, display_name, avatar_url, is_guest, is_deactivated, admin, created_at
    FROM users
  `;
  const params: any[] = [];

  if (search) {
    query += ' WHERE localpart LIKE ? OR display_name LIKE ?';
    params.push(`%${search}%`, `%${search}%`);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  const users = await db.prepare(query).bind(...params).all();

  // Get total count
  let countQuery = 'SELECT COUNT(*) as count FROM users';
  if (search) {
    countQuery += ' WHERE localpart LIKE ? OR display_name LIKE ?';
  }
  const total = search
    ? await db.prepare(countQuery).bind(`%${search}%`, `%${search}%`).first<{ count: number }>()
    : await db.prepare(countQuery).first<{ count: number }>();

  return c.json({
    users: users.results,
    total: total?.count || 0,
    limit,
    offset,
  });
});

// GET /admin/api/users/:userId - Get user details
app.get('/admin/api/users/:userId', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  const user = await db.prepare(`
    SELECT user_id, localpart, display_name, avatar_url, is_guest, is_deactivated, admin, created_at, updated_at
    FROM users WHERE user_id = ?
  `).bind(userId).first();

  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Get user's devices
  const devices = await db.prepare(
    'SELECT device_id, display_name, last_seen_ts, last_seen_ip FROM devices WHERE user_id = ?'
  ).bind(userId).all();

  // Get user's rooms
  const rooms = await db.prepare(`
    SELECT rm.room_id, rm.membership, r.room_id as room_exists
    FROM room_memberships rm
    LEFT JOIN rooms r ON rm.room_id = r.room_id
    WHERE rm.user_id = ?
  `).bind(userId).all();

  return c.json({
    ...user,
    devices: devices.results,
    rooms: rooms.results,
  });
});

// PUT /admin/api/users/:userId - Update user
app.put('/admin/api/users/:userId', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { display_name, admin, deactivated } = body;

  // Build update query
  const updates: string[] = [];
  const params: any[] = [];

  if (display_name !== undefined) {
    updates.push('display_name = ?');
    params.push(display_name);
  }
  if (admin !== undefined) {
    updates.push('admin = ?');
    params.push(admin ? 1 : 0);
  }
  if (deactivated !== undefined) {
    updates.push('is_deactivated = ?');
    params.push(deactivated ? 1 : 0);
  }

  if (updates.length === 0) {
    return Errors.missingParam('No fields to update').toResponse();
  }

  updates.push('updated_at = ?');
  params.push(Date.now());
  params.push(userId);

  await db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE user_id = ?`).bind(...params).run();

  return c.json({ success: true });
});

// DELETE /admin/api/users/:userId - Deactivate user
app.delete('/admin/api/users/:userId', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  // Deactivate instead of delete (preserve history)
  await db.prepare(
    'UPDATE users SET is_deactivated = 1, updated_at = ? WHERE user_id = ?'
  ).bind(Date.now(), userId).run();

  // Revoke all access tokens
  await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true });
});

// POST /admin/api/users/:userId/reset-password - Reset user password
app.post('/admin/api/users/:userId/reset-password', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { password } = body;
  if (!password) {
    return Errors.missingParam('password').toResponse();
  }

  // Import hash function
  const { hashPassword } = await import('../utils/crypto');
  const passwordHash = await hashPassword(password);

  await db.prepare(
    'UPDATE users SET password_hash = ?, updated_at = ? WHERE user_id = ?'
  ).bind(passwordHash, Date.now(), userId).run();

  // Revoke all access tokens to force re-login
  await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();

  return c.json({ success: true });
});

// GET /admin/api/rooms - List all rooms
app.get('/admin/api/rooms', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const offset = parseInt(c.req.query('offset') || '0');

  const rooms = await db.prepare(`
    SELECT r.room_id, r.room_version, r.is_public, r.creator_id, r.created_at,
           (SELECT COUNT(*) FROM room_memberships WHERE room_id = r.room_id AND membership = 'join') as member_count,
           (SELECT COUNT(*) FROM events WHERE room_id = r.room_id) as event_count
    FROM rooms r
    ORDER BY r.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(limit, offset).all();

  // Get room names
  const roomsWithNames = await Promise.all(rooms.results.map(async (room: any) => {
    const nameEvent = await db.prepare(`
      SELECT e.content FROM room_state rs
      JOIN events e ON rs.event_id = e.event_id
      WHERE rs.room_id = ? AND rs.event_type = 'm.room.name'
    `).bind(room.room_id).first<{ content: string }>();

    return {
      ...room,
      name: nameEvent ? JSON.parse(nameEvent.content).name : null,
    };
  }));

  const total = await db.prepare('SELECT COUNT(*) as count FROM rooms').first<{ count: number }>();

  return c.json({
    rooms: roomsWithNames,
    total: total?.count || 0,
    limit,
    offset,
  });
});

// GET /admin/api/rooms/:roomId - Get room details
app.get('/admin/api/rooms/:roomId', requireAuth(), requireAdmin, async (c) => {
  const roomId = decodeURIComponent(c.req.param('roomId'));
  const db = c.env.DB;

  const room = await db.prepare(`
    SELECT room_id, room_version, is_public, creator_id, created_at
    FROM rooms WHERE room_id = ?
  `).bind(roomId).first();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get room state
  const state = await db.prepare(`
    SELECT e.event_type, e.state_key, e.content, e.sender, e.origin_server_ts
    FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ?
  `).bind(roomId).all();

  // Get members
  const members = await db.prepare(`
    SELECT user_id, membership, display_name, avatar_url
    FROM room_memberships WHERE room_id = ?
  `).bind(roomId).all();

  // Get aliases
  const aliases = await db.prepare(
    'SELECT alias FROM room_aliases WHERE room_id = ?'
  ).bind(roomId).all();

  // Parse state
  const stateMap: Record<string, any> = {};
  for (const s of state.results as any[]) {
    stateMap[`${s.event_type}|${s.state_key}`] = {
      type: s.event_type,
      state_key: s.state_key,
      content: JSON.parse(s.content),
      sender: s.sender,
    };
  }

  return c.json({
    ...room,
    name: stateMap['m.room.name|']?.content?.name,
    topic: stateMap['m.room.topic|']?.content?.topic,
    avatar_url: stateMap['m.room.avatar|']?.content?.url,
    join_rule: stateMap['m.room.join_rules|']?.content?.join_rule,
    members: members.results,
    member_count: members.results.length,
    aliases: aliases.results.map((a: any) => a.alias),
    state: state.results.map((s: any) => ({
      ...s,
      content: JSON.parse(s.content),
    })),
  });
});

// DELETE /admin/api/rooms/:roomId - Delete room
app.delete('/admin/api/rooms/:roomId', requireAuth(), requireAdmin, async (c) => {
  const roomId = decodeURIComponent(c.req.param('roomId'));
  const db = c.env.DB;

  // Delete in order (foreign key constraints)
  await db.prepare('DELETE FROM room_aliases WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM room_memberships WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM room_state WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM events WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM rooms WHERE room_id = ?').bind(roomId).run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true });
});

// GET /admin/api/federation/status - Get federation status
app.get('/admin/api/federation/status', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const serverName = c.env.SERVER_NAME;

  // Get known servers count
  const serversCount = await db.prepare('SELECT COUNT(*) as count FROM servers').first<{ count: number }>();

  // Get signing key info
  let signingKeyId = null;
  try {
    const keyData = await c.env.CACHE.get('server_signing_key');
    if (keyData) {
      const parsed = JSON.parse(keyData);
      signingKeyId = parsed.keyId || `ed25519:${serverName.split('.')[0]}`;
    }
  } catch (e) {
    // Key might not be cached
  }

  return c.json({
    server_name: serverName,
    federation_enabled: true,
    signing_key_id: signingKeyId || `ed25519:a_${serverName.replace(/\./g, '_').substring(0, 4)}`,
    known_servers_count: serversCount?.count || 0,
  });
});

// GET /admin/api/federation/test - Run federation self-tests
app.get('/admin/api/federation/test', requireAuth(), requireAdmin, async (c) => {
  const serverName = c.env.SERVER_NAME;
  const tests: Array<{ name: string; passed: boolean; message: string }> = [];

  // Test 1: Check .well-known/matrix/server
  try {
    const wellKnownUrl = `https://${serverName}/.well-known/matrix/server`;
    const resp = await fetch(wellKnownUrl);
    if (resp.ok) {
      const data = await resp.json() as any;
      tests.push({
        name: '.well-known/matrix/server',
        passed: true,
        message: `Delegates to ${data['m.server'] || serverName}`,
      });
    } else {
      tests.push({
        name: '.well-known/matrix/server',
        passed: false,
        message: `HTTP ${resp.status}`,
      });
    }
  } catch (e: any) {
    tests.push({
      name: '.well-known/matrix/server',
      passed: false,
      message: e.message || 'Failed to fetch',
    });
  }

  // Test 2: Check /_matrix/key/v2/server
  try {
    const keysUrl = `https://${serverName}/_matrix/key/v2/server`;
    const resp = await fetch(keysUrl);
    if (resp.ok) {
      const data = await resp.json() as any;
      const hasSigningKeys = data.verify_keys && Object.keys(data.verify_keys).length > 0;
      tests.push({
        name: 'Server signing keys',
        passed: hasSigningKeys,
        message: hasSigningKeys ? `${Object.keys(data.verify_keys).length} key(s) published` : 'No signing keys found',
      });
    } else {
      tests.push({
        name: 'Server signing keys',
        passed: false,
        message: `HTTP ${resp.status}`,
      });
    }
  } catch (e: any) {
    tests.push({
      name: 'Server signing keys',
      passed: false,
      message: e.message || 'Failed to fetch',
    });
  }

  // Test 3: Check /_matrix/federation/v1/version
  try {
    const versionUrl = `https://${serverName}/_matrix/federation/v1/version`;
    const resp = await fetch(versionUrl);
    if (resp.ok) {
      const data = await resp.json() as any;
      tests.push({
        name: 'Federation API',
        passed: true,
        message: `Server: ${data.server?.name || 'Unknown'} ${data.server?.version || ''}`,
      });
    } else {
      tests.push({
        name: 'Federation API',
        passed: false,
        message: `HTTP ${resp.status}`,
      });
    }
  } catch (e: any) {
    tests.push({
      name: 'Federation API',
      passed: false,
      message: e.message || 'Failed to fetch',
    });
  }

  // Test 4: Check .well-known/matrix/client
  try {
    const clientWellKnown = `https://${serverName}/.well-known/matrix/client`;
    const resp = await fetch(clientWellKnown);
    if (resp.ok) {
      const data = await resp.json() as any;
      tests.push({
        name: '.well-known/matrix/client',
        passed: true,
        message: `Homeserver: ${data['m.homeserver']?.base_url || 'configured'}`,
      });
    } else {
      tests.push({
        name: '.well-known/matrix/client',
        passed: false,
        message: `HTTP ${resp.status}`,
      });
    }
  } catch (e: any) {
    tests.push({
      name: '.well-known/matrix/client',
      passed: false,
      message: e.message || 'Failed to fetch',
    });
  }

  const allPassed = tests.every(t => t.passed);

  return c.json({
    success: allPassed,
    server_name: serverName,
    tests,
  });
});

// GET /admin/api/federation/servers - List known federation servers
app.get('/admin/api/federation/servers', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;

  const servers = await db.prepare(`
    SELECT server_name, valid_until_ts, last_successful_fetch, retry_count
    FROM servers
    ORDER BY last_successful_fetch DESC
  `).all();

  return c.json({ servers: servers.results });
});

// GET /admin/api/media - List media files
app.get('/admin/api/media', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const offset = parseInt(c.req.query('offset') || '0');

  const media = await db.prepare(`
    SELECT media_id, user_id, content_type, content_length, filename, created_at, quarantined
    FROM media
    ORDER BY created_at DESC
    LIMIT ? OFFSET ?
  `).bind(limit, offset).all();

  const total = await db.prepare('SELECT COUNT(*) as count FROM media').first<{ count: number }>();

  return c.json({
    media: media.results,
    total: total?.count || 0,
    limit,
    offset,
  });
});

// DELETE /admin/api/media/:mediaId - Delete media
app.delete('/admin/api/media/:mediaId', requireAuth(), requireAdmin, async (c) => {
  const mediaId = c.req.param('mediaId');
  const db = c.env.DB;

  // Delete from R2
  await c.env.MEDIA.delete(mediaId);

  // Delete thumbnails
  const thumbnails = await db.prepare(
    'SELECT width, height, method FROM thumbnails WHERE media_id = ?'
  ).bind(mediaId).all();

  for (const thumb of thumbnails.results as any[]) {
    await c.env.MEDIA.delete(`thumb_${mediaId}_${thumb.width}x${thumb.height}_${thumb.method}`);
  }

  // Delete from database
  await db.prepare('DELETE FROM thumbnails WHERE media_id = ?').bind(mediaId).run();
  await db.prepare('DELETE FROM media WHERE media_id = ?').bind(mediaId).run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true });
});

// POST /admin/api/media/:mediaId/quarantine - Quarantine media
app.post('/admin/api/media/:mediaId/quarantine', requireAuth(), requireAdmin, async (c) => {
  const mediaId = c.req.param('mediaId');
  const db = c.env.DB;

  await db.prepare(
    'UPDATE media SET quarantined = 1 WHERE media_id = ?'
  ).bind(mediaId).run();

  return c.json({ success: true });
});

// GET /admin/api/config - Get server configuration
app.get('/admin/api/config', requireAuth(), requireAdmin, async (c) => {
  return c.json({
    server_name: c.env.SERVER_NAME,
    version: c.env.SERVER_VERSION,
    features: {
      registration: true,
      federation: true,
      media_upload: true,
      voip: true,
    },
    limits: {
      max_upload_size: 50 * 1024 * 1024,
    },
  });
});

// POST /admin/api/make-admin - Make a user an admin
app.post('/admin/api/make-admin', requireAuth(), requireAdmin, async (c) => {
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { user_id } = body;
  if (!user_id) {
    return Errors.missingParam('user_id').toResponse();
  }

  await c.env.DB.prepare(
    'UPDATE users SET admin = 1, updated_at = ? WHERE user_id = ?'
  ).bind(Date.now(), user_id).run();

  return c.json({ success: true });
});

// POST /admin/api/remove-admin - Remove admin privileges
app.post('/admin/api/remove-admin', requireAuth(), requireAdmin, async (c) => {
  const currentUserId = c.get('userId');
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { user_id } = body;
  if (!user_id) {
    return Errors.missingParam('user_id').toResponse();
  }

  // Prevent self-demotion
  if (user_id === currentUserId) {
    return Errors.forbidden('Cannot remove your own admin privileges').toResponse();
  }

  await c.env.DB.prepare(
    'UPDATE users SET admin = 0, updated_at = ? WHERE user_id = ?'
  ).bind(Date.now(), user_id).run();

  return c.json({ success: true });
});

// DELETE /admin/api/users/:userId/purge - Completely delete user and all data
app.delete('/admin/api/users/:userId/purge', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;
  const currentUserId = c.get('userId');

  // Prevent self-deletion
  if (userId === currentUserId) {
    return Errors.forbidden('Cannot delete your own account').toResponse();
  }

  // Get devices BEFORE deleting them (for KV cleanup)
  const devices = await db.prepare('SELECT device_id FROM devices WHERE user_id = ?').bind(userId).all<{ device_id: string }>();

  // Get and delete media BEFORE deleting user (FK constraint without CASCADE)
  const media = await db.prepare('SELECT media_id FROM media WHERE user_id = ?').bind(userId).all<{ media_id: string }>();
  for (const m of media.results) {
    // Delete from R2
    await c.env.MEDIA.delete(m.media_id);
    // Delete thumbnails
    const thumbs = await db.prepare('SELECT width, height, method FROM thumbnails WHERE media_id = ?').bind(m.media_id).all<{ width: number; height: number; method: string }>();
    for (const t of thumbs.results) {
      await c.env.MEDIA.delete(`thumb_${m.media_id}_${t.width}x${t.height}_${t.method}`);
    }
  }
  await db.prepare('DELETE FROM thumbnails WHERE media_id IN (SELECT media_id FROM media WHERE user_id = ?)').bind(userId).run();
  await db.prepare('DELETE FROM media WHERE user_id = ?').bind(userId).run();

  // Delete all user data in order (respecting foreign key constraints)
  // Account & profile data
  await db.prepare('DELETE FROM account_data WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM account_data_changes WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM presence WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM push_rules WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM sync_tokens WHERE user_id = ?').bind(userId).run();
  
  // E2EE & device keys
  await db.prepare('DELETE FROM cross_signing_keys WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM cross_signing_signatures WHERE user_id = ? OR signer_user_id = ?').bind(userId, userId).run();
  await db.prepare('DELETE FROM one_time_keys WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM fallback_keys WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM device_key_changes WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM key_backup_keys WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM key_backup_versions WHERE user_id = ?').bind(userId).run();
  
  // Messaging
  await db.prepare('DELETE FROM to_device_messages WHERE recipient_user_id = ? OR sender_user_id = ?').bind(userId, userId).run();
  await db.prepare('DELETE FROM pushers WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM notification_queue WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM transaction_ids WHERE user_id = ?').bind(userId).run();
  
  // Room participation
  await db.prepare('DELETE FROM receipts WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM typing WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM room_memberships WHERE user_id = ?').bind(userId).run();
  
  // Identity & auth
  await db.prepare('DELETE FROM user_threepids WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM idp_user_links WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM devices WHERE user_id = ?').bind(userId).run();
  
  // Finally delete the user
  await db.prepare('DELETE FROM users WHERE user_id = ?').bind(userId).run();

  // Delete device keys from KV
  for (const device of devices.results) {
    await c.env.DEVICE_KEYS.delete(`device:${userId}:${device.device_id}`);
  }

  // Clean up cross-signing keys from KV (stored as user:{userId} in keys.ts)
  await c.env.CROSS_SIGNING_KEYS.delete(`user:${userId}`);

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true });
});

// POST /admin/api/users/bulk-delete - Delete multiple users
app.post('/admin/api/users/bulk-delete', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const currentUserId = c.get('userId');

  let body: { user_ids: string[]; preserve_admin?: boolean };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  let { user_ids, preserve_admin } = body;
  if (!user_ids || !Array.isArray(user_ids) || user_ids.length === 0) {
    return Errors.missingParam('user_ids array required').toResponse();
  }

  // Always remove current user from deletion list
  user_ids = user_ids.filter(id => id !== currentUserId);

  // Optionally filter out admins
  if (preserve_admin) {
    const admins = await db.prepare(`
      SELECT user_id FROM users WHERE admin = 1
    `).all<{ user_id: string }>();
    const adminIds = new Set(admins.results.map(a => a.user_id));
    user_ids = user_ids.filter(id => !adminIds.has(id));
  }

  if (user_ids.length === 0) {
    return c.json({ success: true, deleted: 0 });
  }

  // Delete all user data for each user
  let deleted = 0;
  for (const userId of user_ids) {
    // Get devices BEFORE deleting (for KV cleanup)
    const devices = await db.prepare('SELECT device_id FROM devices WHERE user_id = ?').bind(userId).all<{ device_id: string }>();
    
    // Delete media BEFORE user (FK constraint without CASCADE)
    const media = await db.prepare('SELECT media_id FROM media WHERE user_id = ?').bind(userId).all<{ media_id: string }>();
    for (const m of media.results) {
      await c.env.MEDIA.delete(m.media_id);
      const thumbs = await db.prepare('SELECT width, height, method FROM thumbnails WHERE media_id = ?').bind(m.media_id).all<{ width: number; height: number; method: string }>();
      for (const t of thumbs.results) {
        await c.env.MEDIA.delete(`thumb_${m.media_id}_${t.width}x${t.height}_${t.method}`);
      }
    }
    await db.prepare('DELETE FROM thumbnails WHERE media_id IN (SELECT media_id FROM media WHERE user_id = ?)').bind(userId).run();
    await db.prepare('DELETE FROM media WHERE user_id = ?').bind(userId).run();
    
    // Account & profile data
    await db.prepare('DELETE FROM account_data WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM account_data_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM presence WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM push_rules WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM sync_tokens WHERE user_id = ?').bind(userId).run();
    
    // E2EE & device keys
    await db.prepare('DELETE FROM cross_signing_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM cross_signing_signatures WHERE user_id = ? OR signer_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM one_time_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM fallback_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM device_key_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM key_backup_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM key_backup_versions WHERE user_id = ?').bind(userId).run();
    
    // Messaging
    await db.prepare('DELETE FROM to_device_messages WHERE recipient_user_id = ? OR sender_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM pushers WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM notification_queue WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM transaction_ids WHERE user_id = ?').bind(userId).run();
    
    // Room participation
    await db.prepare('DELETE FROM receipts WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM typing WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM room_memberships WHERE user_id = ?').bind(userId).run();
    
    // Identity & auth
    await db.prepare('DELETE FROM user_threepids WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM idp_user_links WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM devices WHERE user_id = ?').bind(userId).run();
    
    // Finally delete the user
    await db.prepare('DELETE FROM users WHERE user_id = ?').bind(userId).run();

    // Clean up KV data
    for (const device of devices.results) {
      await c.env.DEVICE_KEYS.delete(`device:${userId}:${device.device_id}`);
    }
    // Cross-signing keys stored as user:{userId} in keys.ts
    await c.env.CROSS_SIGNING_KEYS.delete(`user:${userId}`);
    
    deleted++;
  }

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true, deleted });
});

// POST /admin/api/cleanup - Clean up all data except admin users
app.post('/admin/api/cleanup', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;

  // Get all non-admin users
  const users = await db.prepare(`
    SELECT user_id FROM users WHERE admin = 0
  `).all<{ user_id: string }>();
  const userIds = users.results.map(u => u.user_id);

  // Get all devices for KV cleanup
  const allDevices = await db.prepare(`
    SELECT user_id, device_id FROM devices WHERE user_id IN (SELECT user_id FROM users WHERE admin = 0)
  `).all<{ user_id: string; device_id: string }>();

  // Delete user-related data for each non-admin user
  for (const userId of userIds) {
    // Account & profile data
    await db.prepare('DELETE FROM account_data WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM account_data_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM presence WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM push_rules WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM sync_tokens WHERE user_id = ?').bind(userId).run();
    
    // E2EE & device keys
    await db.prepare('DELETE FROM cross_signing_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM cross_signing_signatures WHERE user_id = ? OR signer_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM one_time_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM fallback_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM device_key_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM key_backup_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM key_backup_versions WHERE user_id = ?').bind(userId).run();
    
    // Messaging
    await db.prepare('DELETE FROM to_device_messages WHERE recipient_user_id = ? OR sender_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM pushers WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM notification_queue WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM transaction_ids WHERE user_id = ?').bind(userId).run();
    
    // Room participation
    await db.prepare('DELETE FROM receipts WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM typing WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM room_memberships WHERE user_id = ?').bind(userId).run();
    
    // Identity & auth
    await db.prepare('DELETE FROM user_threepids WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM idp_user_links WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM devices WHERE user_id = ?').bind(userId).run();
    
    // Finally delete the user
    await db.prepare('DELETE FROM users WHERE user_id = ?').bind(userId).run();

    // Clean up KV cross-signing keys (stored as user:{userId} in keys.ts)
    await c.env.CROSS_SIGNING_KEYS.delete(`user:${userId}`);
  }

  // Clean up device keys from KV
  for (const device of allDevices.results) {
    await c.env.DEVICE_KEYS.delete(`device:${device.user_id}:${device.device_id}`);
  }

  // Delete all rooms, events, and related data
  await db.prepare('DELETE FROM event_relations').run();
  await db.prepare('DELETE FROM room_state').run();
  await db.prepare('DELETE FROM room_aliases').run();
  await db.prepare('DELETE FROM room_knocks').run();
  await db.prepare('DELETE FROM content_reports').run();
  await db.prepare('DELETE FROM events').run();
  await db.prepare('DELETE FROM rooms').run();

  // Clean up media (delete from R2 and database)
  const media = await db.prepare('SELECT media_id FROM media').all<{ media_id: string }>();
  for (const m of media.results) {
    await c.env.MEDIA.delete(m.media_id);
  }
  await db.prepare('DELETE FROM thumbnails').run();
  await db.prepare('DELETE FROM media').run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ 
    success: true, 
    users_deleted: userIds.length,
    rooms_deleted: true,
    media_deleted: media.results.length
  });
});

// POST /admin/api/users/:userId/reactivate - Reactivate a deactivated user
app.post('/admin/api/users/:userId/reactivate', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  await db.prepare(
    'UPDATE users SET is_deactivated = 0, updated_at = ? WHERE user_id = ?'
  ).bind(Date.now(), userId).run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true });
});

// POST /admin/api/users/create - Create a new user
app.post('/admin/api/users/create', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { username, password, display_name, admin } = body;
  if (!username || !password) {
    return Errors.missingParam('username and password required').toResponse();
  }

  // Validate username
  if (!/^[a-z0-9._=-]+$/i.test(username)) {
    return c.json({ errcode: 'M_INVALID_USERNAME', error: 'Invalid username format' }, 400);
  }

  // Get server name from env
  const serverName = c.env.SERVER_NAME;
  const userId = `@${username}:${serverName}`;

  // Check if user exists
  const existing = await db.prepare(
    'SELECT user_id FROM users WHERE user_id = ?'
  ).bind(userId).first();

  if (existing) {
    return c.json({ errcode: 'M_USER_IN_USE', error: 'Username already taken' }, 400);
  }

  // Hash password
  const { hashPassword } = await import('../utils/crypto');
  const passwordHash = await hashPassword(password);

  // Create user
  await db.prepare(`
    INSERT INTO users (user_id, localpart, password_hash, display_name, admin, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(userId, username, passwordHash, display_name || null, admin ? 1 : 0, Date.now(), Date.now()).run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true, user_id: userId });
});

// GET /admin/api/users/:userId/sessions - Get user sessions/tokens
app.get('/admin/api/users/:userId/sessions', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  const sessions = await db.prepare(`
    SELECT token_id as id, device_id, created_at
    FROM access_tokens
    WHERE user_id = ?
    ORDER BY created_at DESC
  `).bind(userId).all();

  return c.json({ sessions: sessions.results });
});

// DELETE /admin/api/users/:userId/sessions - Revoke all user sessions
app.delete('/admin/api/users/:userId/sessions', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  const result = await db.prepare(
    'DELETE FROM access_tokens WHERE user_id = ?'
  ).bind(userId).run();

  return c.json({ success: true, revoked: result.meta.changes || 0 });
});

// DELETE /admin/api/sessions/:sessionId - Revoke specific session
app.delete('/admin/api/sessions/:sessionId', requireAuth(), requireAdmin, async (c) => {
  const sessionId = c.req.param('sessionId');
  const db = c.env.DB;

  await db.prepare(
    'DELETE FROM access_tokens WHERE token_id = ?'
  ).bind(sessionId).run();

  return c.json({ success: true });
});

// GET /admin/api/rooms/:roomId/events - Browse room events
app.get('/admin/api/rooms/:roomId/events', requireAuth(), requireAdmin, async (c) => {
  const roomId = decodeURIComponent(c.req.param('roomId'));
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const before = c.req.query('before');

  let query = `
    SELECT event_id, event_type, state_key, sender, content, origin_server_ts, stream_position
    FROM events
    WHERE room_id = ?
  `;
  const params: any[] = [roomId];

  if (before) {
    query += ` AND stream_position < ?`;
    params.push(parseInt(before));
  }

  query += ` ORDER BY stream_position DESC LIMIT ?`;
  params.push(limit);

  const events = await db.prepare(query).bind(...params).all();

  return c.json({
    events: events.results.map((e: any) => ({
      ...e,
      content: JSON.parse(e.content),
    })),
  });
});

// GET /admin/api/reports - Get content reports (proxy to existing endpoint format)
app.get('/admin/api/reports', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const offset = parseInt(c.req.query('offset') || '0');
  const resolved = c.req.query('resolved');

  let query = `
    SELECT cr.*, e.sender as reported_user_id, e.event_type, e.content
    FROM content_reports cr
    LEFT JOIN events e ON cr.event_id = e.event_id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (resolved === 'true') {
    query += ` AND cr.resolved = 1`;
  } else if (resolved === 'false') {
    query += ` AND cr.resolved = 0`;
  }

  query += ` ORDER BY cr.created_at DESC LIMIT ? OFFSET ?`;
  params.push(limit, offset);

  const reports = await db.prepare(query).bind(...params).all();

  // Get total count
  let countQuery = 'SELECT COUNT(*) as count FROM content_reports WHERE 1=1';
  if (resolved === 'true') {
    countQuery += ` AND resolved = 1`;
  } else if (resolved === 'false') {
    countQuery += ` AND resolved = 0`;
  }
  const total = await db.prepare(countQuery).first<{ count: number }>();

  return c.json({
    reports: reports.results.map((r: any) => ({
      id: r.id,
      reporter_user_id: r.reporter_user_id,
      reported_user_id: r.reported_user_id,
      room_id: r.room_id,
      event_id: r.event_id,
      event_type: r.event_type,
      event_content: r.content ? JSON.parse(r.content) : null,
      reason: r.reason,
      score: r.score,
      created_at: r.created_at,
      resolved: r.resolved,
      resolved_by: r.resolved_by,
      resolved_at: r.resolved_at,
      resolution_note: r.resolution_note,
    })),
    total: total?.count || 0,
    limit,
    offset,
  });
});

// POST /admin/api/reports/:reportId/resolve - Resolve a report
app.post('/admin/api/reports/:reportId/resolve', requireAuth(), requireAdmin, async (c) => {
  const userId = c.get('userId');
  const reportId = c.req.param('reportId');
  const db = c.env.DB;

  let body: { note?: string };
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  const result = await db.prepare(`
    UPDATE content_reports
    SET resolved = 1, resolved_by = ?, resolved_at = ?, resolution_note = ?
    WHERE id = ?
  `).bind(userId, Date.now(), body.note || null, parseInt(reportId)).run();

  if (result.meta.changes === 0) {
    return Errors.notFound('Report not found').toResponse();
  }

  // Invalidate stats cache (affects unresolved reports count)
  await invalidateStatsCache(c.env);

  return c.json({ success: true });
});

// POST /admin/api/reports/:reportId/unresolve - Unresolve a report
app.post('/admin/api/reports/:reportId/unresolve', requireAuth(), requireAdmin, async (c) => {
  const reportId = c.req.param('reportId');
  const db = c.env.DB;

  const result = await db.prepare(`
    UPDATE content_reports
    SET resolved = 0, resolved_by = NULL, resolved_at = NULL, resolution_note = NULL
    WHERE id = ?
  `).bind(parseInt(reportId)).run();

  if (result.meta.changes === 0) {
    return Errors.notFound('Report not found').toResponse();
  }

  // Invalidate stats cache (affects unresolved reports count)
  await invalidateStatsCache(c.env);

  return c.json({ success: true });
});

// POST /admin/api/server-notice - Send server notice to user
app.post('/admin/api/server-notice', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { user_id, message } = body;
  if (!user_id || !message) {
    return Errors.missingParam('user_id and message required').toResponse();
  }

  // Create server notice as to-device message
  const serverName = c.env.SERVER_NAME;
  const serverUserId = `@server:${serverName}`;
  const messageId = `notice_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  // Get all devices for user
  const devices = await db.prepare(`
    SELECT device_id FROM devices WHERE user_id = ?
  `).bind(user_id).all<{ device_id: string }>();

  // Get next stream position
  await db.prepare(`
    UPDATE stream_positions SET position = position + 1 WHERE stream_name = 'to_device'
  `).run();
  const posResult = await db.prepare(`
    SELECT position FROM stream_positions WHERE stream_name = 'to_device'
  `).first<{ position: number }>();
  const streamPosition = posResult?.position || 1;

  // Send to each device
  for (const device of devices.results) {
    await db.prepare(`
      INSERT INTO to_device_messages (
        recipient_user_id, recipient_device_id, sender_user_id,
        event_type, content, message_id, stream_position
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(
      user_id,
      device.device_id,
      serverUserId,
      'm.server_notice',
      JSON.stringify({
        msgtype: 'm.server_notice',
        body: message,
        admin_contact: `@admin:${serverName}`,
      }),
      messageId,
      streamPosition
    ).run();
  }

  return c.json({ success: true, devices_notified: devices.results.length });
});

// GET /admin/api/registration - Get registration status (via AdminDurableObject)
app.get('/admin/api/registration', requireAuth(), requireAdmin, async (c) => {
  const adminDO = getAdminDO(c.env);
  const response = await adminDO.fetch('http://internal/config');
  const config = await response.json() as { registration_enabled: boolean };

  return c.json({
    enabled: config.registration_enabled,
  });
});

// PUT /admin/api/registration - Toggle registration (via AdminDurableObject)
app.put('/admin/api/registration', requireAuth(), requireAdmin, async (c) => {
  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { enabled } = body;
  if (typeof enabled !== 'boolean') {
    return Errors.missingParam('enabled (boolean) required').toResponse();
  }

  const adminDO = getAdminDO(c.env);
  const response = await adminDO.fetch('http://internal/config', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ registration_enabled: enabled }),
  });

  if (!response.ok) {
    return new Response('Failed to update config', { status: 500 });
  }

  return c.json({ success: true, enabled });
});

// POST /admin/api/users/:userId/login-token - Generate a one-time login token for QR code auth
app.post('/admin/api/users/:userId/login-token', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  // Verify user exists and is not deactivated
  const user = await getUserById(db, userId);
  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }
  if (user.is_deactivated) {
    return c.json({ errcode: 'M_USER_DEACTIVATED', error: 'User is deactivated' }, 400);
  }

  // Parse optional TTL from request body (default 10 minutes)
  let ttlMinutes = 10;
  try {
    const body = await c.req.json();
    if (body.ttl_minutes && typeof body.ttl_minutes === 'number') {
      ttlMinutes = Math.min(Math.max(body.ttl_minutes, 1), 60); // 1-60 minutes
    }
  } catch {
    // No body or invalid JSON, use defaults
  }

  // Generate login token
  const loginToken = await generateLoginToken();
  const tokenHash = await hashToken(loginToken);
  const expiresAt = Date.now() + ttlMinutes * 60 * 1000;

  // Store in KV with TTL
  await c.env.SESSIONS.put(
    `login_token:${tokenHash}`,
    JSON.stringify({
      user_id: userId,
      expires_at: expiresAt,
    }),
    {
      expirationTtl: ttlMinutes * 60, // KV TTL in seconds
    }
  );

  // Build the QR URL that users will scan
  const protocol = c.req.url.startsWith('https') ? 'https' : 'https'; // Always use https for production
  const host = c.req.header('host') || c.env.SERVER_NAME;
  const qrUrl = `${protocol}://${host}/login/qr/${loginToken}`;

  return c.json({
    success: true,
    token: loginToken,
    qr_url: qrUrl,
    expires_at: expiresAt,
    ttl_seconds: ttlMinutes * 60,
    user_id: userId,
    homeserver: c.env.SERVER_NAME,
  });
});

// ============================================
// Identity Provider (IdP) Management Endpoints
// ============================================

interface IdPProvider {
  id: string;
  name: string;
  issuer_url: string;
  client_id: string;
  client_secret_encrypted: string;
  scopes: string;
  enabled: number;
  auto_create_users: number;
  username_claim: string;
  display_order: number;
  icon_url: string | null;
  created_at: number;
  updated_at: number;
}

// GET /admin/api/idp/providers - List all IdP providers
app.get('/admin/api/idp/providers', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;

  const result = await db.prepare(`
    SELECT id, name, issuer_url, client_id, scopes, enabled, auto_create_users,
           username_claim, display_order, icon_url, created_at, updated_at
    FROM idp_providers
    ORDER BY display_order ASC, name ASC
  `).all<Omit<IdPProvider, 'client_secret_encrypted'>>();

  // Get user counts for each provider
  const providers = await Promise.all(result.results.map(async (p) => {
    const countResult = await db.prepare(`
      SELECT COUNT(*) as count FROM idp_user_links WHERE provider_id = ?
    `).bind(p.id).first<{ count: number }>();

    return {
      ...p,
      enabled: p.enabled === 1,
      auto_create_users: p.auto_create_users === 1,
      linked_users: countResult?.count || 0,
    };
  }));

  return c.json({ providers });
});

// POST /admin/api/idp/providers - Create new IdP provider
app.post('/admin/api/idp/providers', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  let body: any;

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { name, issuer_url, client_id, client_secret, scopes, auto_create_users, username_claim, icon_url } = body;

  // Validate required fields
  if (!name || !issuer_url || !client_id || !client_secret) {
    return Errors.missingParam('name, issuer_url, client_id, and client_secret are required').toResponse();
  }

  // Validate issuer URL by fetching discovery document
  try {
    await fetchOIDCDiscovery(issuer_url);
  } catch (err) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: `Failed to fetch OIDC discovery from issuer: ${err}`,
    }, 400);
  }

  // Generate ID and encrypt secret
  const id = await generateOpaqueId(12);
  const encryptedSecret = await encryptSecret(client_secret, c.env);

  try {
    await db.prepare(`
      INSERT INTO idp_providers (id, name, issuer_url, client_id, client_secret_encrypted, scopes,
                                  enabled, auto_create_users, username_claim, icon_url, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)
    `).bind(
      id,
      name,
      issuer_url.replace(/\/$/, ''), // Normalize URL
      client_id,
      encryptedSecret,
      scopes || 'openid profile email',
      auto_create_users !== false ? 1 : 0,
      username_claim || 'email',
      icon_url || null,
      Date.now(),
      Date.now()
    ).run();

    return c.json({
      success: true,
      id,
      message: 'Identity provider created successfully',
    });
  } catch (err) {
    console.error('Failed to create IdP:', err);
    return c.json({ errcode: 'M_UNKNOWN', error: 'Failed to create identity provider' }, 500);
  }
});

// GET /admin/api/idp/providers/:id - Get IdP provider details
app.get('/admin/api/idp/providers/:id', requireAuth(), requireAdmin, async (c) => {
  const id = c.req.param('id');
  const db = c.env.DB;

  const provider = await db.prepare(`
    SELECT id, name, issuer_url, client_id, scopes, enabled, auto_create_users,
           username_claim, display_order, icon_url, created_at, updated_at
    FROM idp_providers WHERE id = ?
  `).bind(id).first<Omit<IdPProvider, 'client_secret_encrypted'>>();

  if (!provider) {
    return Errors.notFound('Identity provider not found').toResponse();
  }

  // Get linked users
  const links = await db.prepare(`
    SELECT l.id, l.external_id, l.user_id, l.external_email, l.external_name, l.created_at, l.last_login_at
    FROM idp_user_links l
    WHERE l.provider_id = ?
    ORDER BY l.last_login_at DESC
    LIMIT 100
  `).bind(id).all<{
    id: number;
    external_id: string;
    user_id: string;
    external_email: string | null;
    external_name: string | null;
    created_at: number;
    last_login_at: number | null;
  }>();

  return c.json({
    ...provider,
    enabled: provider.enabled === 1,
    auto_create_users: provider.auto_create_users === 1,
    linked_users: links.results,
  });
});

// PUT /admin/api/idp/providers/:id - Update IdP provider
app.put('/admin/api/idp/providers/:id', requireAuth(), requireAdmin, async (c) => {
  const id = c.req.param('id');
  const db = c.env.DB;
  let body: any;

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Check provider exists
  const existing = await db.prepare('SELECT id FROM idp_providers WHERE id = ?').bind(id).first();
  if (!existing) {
    return Errors.notFound('Identity provider not found').toResponse();
  }

  const updates: string[] = [];
  const values: any[] = [];

  if (body.name !== undefined) {
    updates.push('name = ?');
    values.push(body.name);
  }
  if (body.issuer_url !== undefined) {
    // Validate new issuer URL
    try {
      await fetchOIDCDiscovery(body.issuer_url);
    } catch (err) {
      return c.json({
        errcode: 'M_INVALID_PARAM',
        error: `Failed to fetch OIDC discovery from issuer: ${err}`,
      }, 400);
    }
    updates.push('issuer_url = ?');
    values.push(body.issuer_url.replace(/\/$/, ''));
  }
  if (body.client_id !== undefined) {
    updates.push('client_id = ?');
    values.push(body.client_id);
  }
  if (body.client_secret !== undefined) {
    const encryptedSecret = await encryptSecret(body.client_secret, c.env);
    updates.push('client_secret_encrypted = ?');
    values.push(encryptedSecret);
  }
  if (body.scopes !== undefined) {
    updates.push('scopes = ?');
    values.push(body.scopes);
  }
  if (body.enabled !== undefined) {
    updates.push('enabled = ?');
    values.push(body.enabled ? 1 : 0);
  }
  if (body.auto_create_users !== undefined) {
    updates.push('auto_create_users = ?');
    values.push(body.auto_create_users ? 1 : 0);
  }
  if (body.username_claim !== undefined) {
    updates.push('username_claim = ?');
    values.push(body.username_claim);
  }
  if (body.display_order !== undefined) {
    updates.push('display_order = ?');
    values.push(body.display_order);
  }
  if (body.icon_url !== undefined) {
    updates.push('icon_url = ?');
    values.push(body.icon_url || null);
  }

  if (updates.length === 0) {
    return c.json({ success: true, message: 'No changes' });
  }

  updates.push('updated_at = ?');
  values.push(Date.now());
  values.push(id);

  await db.prepare(`
    UPDATE idp_providers SET ${updates.join(', ')} WHERE id = ?
  `).bind(...values).run();

  return c.json({ success: true, message: 'Identity provider updated' });
});

// DELETE /admin/api/idp/providers/:id - Delete IdP provider
app.delete('/admin/api/idp/providers/:id', requireAuth(), requireAdmin, async (c) => {
  const id = c.req.param('id');
  const db = c.env.DB;

  // Check provider exists
  const existing = await db.prepare('SELECT id FROM idp_providers WHERE id = ?').bind(id).first();
  if (!existing) {
    return Errors.notFound('Identity provider not found').toResponse();
  }

  // Delete provider (cascades to user links)
  await db.prepare('DELETE FROM idp_providers WHERE id = ?').bind(id).run();

  return c.json({ success: true, message: 'Identity provider deleted' });
});

// DELETE /admin/api/idp/providers/:id/links/:linkId - Remove a user link
app.delete('/admin/api/idp/providers/:id/links/:linkId', requireAuth(), requireAdmin, async (c) => {
  const providerId = c.req.param('id');
  const linkId = c.req.param('linkId');
  const db = c.env.DB;

  await db.prepare(`
    DELETE FROM idp_user_links WHERE id = ? AND provider_id = ?
  `).bind(linkId, providerId).run();

  return c.json({ success: true, message: 'User link removed' });
});

// POST /admin/api/idp/providers/:id/test - Test IdP connection
app.post('/admin/api/idp/providers/:id/test', requireAuth(), requireAdmin, async (c) => {
  const id = c.req.param('id');
  const db = c.env.DB;

  const provider = await db.prepare(`
    SELECT issuer_url FROM idp_providers WHERE id = ?
  `).bind(id).first<{ issuer_url: string }>();

  if (!provider) {
    return Errors.notFound('Identity provider not found').toResponse();
  }

  try {
    const discovery = await fetchOIDCDiscovery(provider.issuer_url);
    return c.json({
      success: true,
      message: 'Connection successful',
      discovery: {
        issuer: discovery.issuer,
        authorization_endpoint: discovery.authorization_endpoint,
        token_endpoint: discovery.token_endpoint,
        userinfo_endpoint: discovery.userinfo_endpoint,
        jwks_uri: discovery.jwks_uri,
      },
    });
  } catch (err) {
    return c.json({
      success: false,
      error: String(err),
    }, 400);
  }
});

// ============================================
// E2EE Key Debug Endpoint (Admin Only)
// ============================================

// GET /admin/api/users/:userId/keys - Debug E2EE key state for a user
app.get('/admin/api/users/:userId/keys', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  // Get cross-signing keys from D1
  const crossSigningKeys = await db.prepare(`
    SELECT key_type, key_id, key_data FROM cross_signing_keys WHERE user_id = ?
  `).bind(userId).all<{ key_type: string; key_id: string; key_data: string }>();

  // Get signatures from D1
  const signatures = await db.prepare(`
    SELECT key_id, signer_user_id, signer_key_id, signature FROM cross_signing_signatures WHERE user_id = ?
  `).bind(userId).all<{ key_id: string; signer_user_id: string; signer_key_id: string; signature: string }>();

  // Get devices
  const devices = await db.prepare(`
    SELECT device_id, display_name FROM devices WHERE user_id = ?
  `).bind(userId).all<{ device_id: string; display_name: string | null }>();

  // Get device keys from KV
  const deviceKeys: Record<string, any> = {};
  for (const device of devices.results) {
    const keyData = await c.env.DEVICE_KEYS.get(`device:${userId}:${device.device_id}`);
    if (keyData) {
      deviceKeys[device.device_id] = JSON.parse(keyData);
    }
  }

  // Parse cross-signing keys
  const parsedCSKeys: Record<string, any> = {};
  for (const key of crossSigningKeys.results) {
    parsedCSKeys[key.key_type] = {
      key_id: key.key_id,
      data: JSON.parse(key.key_data),
    };
  }

  // Verification status check
  const selfSigningKeyId = parsedCSKeys.self_signing?.key_id;
  const verificationStatus: Record<string, { verified: boolean; reason: string }> = {};
  
  for (const device of devices.results) {
    const deviceId = device.device_id;
    const hasSelfSigningSignature = signatures.results.some(
      s => s.key_id === deviceId && s.signer_key_id === selfSigningKeyId
    );
    const deviceKey = deviceKeys[deviceId];
    const hasSignatureInDeviceKey = deviceKey?.signatures?.[userId]?.[selfSigningKeyId] !== undefined;
    
    verificationStatus[deviceId] = {
      verified: hasSelfSigningSignature && hasSignatureInDeviceKey,
      reason: !selfSigningKeyId 
        ? 'No self-signing key' 
        : !hasSelfSigningSignature 
          ? 'No signature in DB' 
          : !hasSignatureInDeviceKey 
            ? 'Signature not in device key object'
            : 'Verified',
    };
  }

  return c.json({
    user_id: userId,
    cross_signing_keys: parsedCSKeys,
    signatures: signatures.results,
    devices: devices.results,
    device_keys: deviceKeys,
    verification_status: verificationStatus,
  });
});

// ============================================
// Matrix Client-Server Admin API Endpoints
// ============================================

// GET /_matrix/client/v3/admin/whois/:userId - Get information about a user's sessions
// Per Matrix spec: admin users can query any user, non-admin users can only query themselves
app.get('/_matrix/client/v3/admin/whois/:userId', requireAuth(), async (c) => {
  const requestingUserId = c.get('userId');
  const targetUserId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  // Check if requesting user is admin
  const requestingUser = await getUserById(db, requestingUserId);
  const isAdmin = Boolean(requestingUser?.admin);

  // Non-admin users can only query themselves
  if (!isAdmin && requestingUserId !== targetUserId) {
    return Errors.forbidden('Admin privileges required to query other users').toResponse();
  }

  // Check if target user exists
  const targetUser = await db.prepare(`
    SELECT user_id FROM users WHERE user_id = ?
  `).bind(targetUserId).first<{ user_id: string }>();

  if (!targetUser) {
    return Errors.notFound('User not found').toResponse();
  }

  // Get user's devices with session info
  const devices = await db.prepare(`
    SELECT d.device_id, d.display_name, d.last_seen_ts, d.last_seen_ip,
           a.created_at as session_created_at
    FROM devices d
    LEFT JOIN access_tokens a ON d.user_id = a.user_id AND d.device_id = a.device_id
    WHERE d.user_id = ?
  `).bind(targetUserId).all<{
    device_id: string;
    display_name: string | null;
    last_seen_ts: number | null;
    last_seen_ip: string | null;
    session_created_at: number | null;
  }>();

  // Build devices map in Matrix spec format
  const devicesMap: Record<string, { sessions: Array<{
    connections: Array<{
      ip: string | null;
      last_seen: number | null;
      user_agent?: string;
    }>;
  }> }> = {};

  for (const device of devices.results) {
    devicesMap[device.device_id] = {
      sessions: [{
        connections: [{
          ip: device.last_seen_ip || null,
          last_seen: device.last_seen_ts || null,
        }],
      }],
    };
  }

  return c.json({
    user_id: targetUserId,
    devices: devicesMap,
  });
});

// ============================================
// Synapse-Compatible Admin API Routes
// These routes provide compatibility with Synapse admin tools
// ============================================

// GET /_synapse/admin/v1/server_version - Server version info (Synapse format)
app.get('/_synapse/admin/v1/server_version', requireAuth(), requireAdmin, async (c) => {
  return c.json({
    server_version: c.env.SERVER_VERSION,
    python_version: 'N/A (Cloudflare Workers)',
  });
});

// GET /_synapse/admin/v2/users - List users (Synapse format)
app.get('/_synapse/admin/v2/users', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 1000);
  const from = parseInt(c.req.query('from') || '0');
  const guests = c.req.query('guests') !== 'false';
  const deactivated = c.req.query('deactivated') === 'true';
  const name = c.req.query('name'); // Search by name

  let query = `
    SELECT user_id as name, display_name as displayname, is_guest, is_deactivated as deactivated, admin, created_at as creation_ts
    FROM users WHERE 1=1
  `;
  const params: any[] = [];

  if (!guests) {
    query += ' AND is_guest = 0';
  }
  if (deactivated) {
    query += ' AND is_deactivated = 1';
  }
  if (name) {
    query += ' AND (localpart LIKE ? OR display_name LIKE ?)';
    params.push(`%${name}%`, `%${name}%`);
  }

  query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
  params.push(limit, from);

  const users = await db.prepare(query).bind(...params).all();
  const total = await db.prepare('SELECT COUNT(*) as count FROM users').first<{ count: number }>();

  return c.json({
    users: users.results,
    next_token: from + limit < (total?.count || 0) ? String(from + limit) : undefined,
    total: total?.count || 0,
  });
});

// GET /_synapse/admin/v2/users/:userId - User details (Synapse format)
app.get('/_synapse/admin/v2/users/:userId', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  const user = await db.prepare(`
    SELECT user_id as name, display_name as displayname, avatar_url, is_guest, is_deactivated as deactivated, admin, created_at as creation_ts
    FROM users WHERE user_id = ?
  `).bind(userId).first();

  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Get user's threepids (email addresses, phone numbers)
  // Note: We may not have a full threepid table, returning empty for now
  const threepids: any[] = [];

  return c.json({
    ...user,
    threepids,
    consent_version: null,
    consent_server_notice_sent: null,
    appservice_id: null,
    consent_ts: null,
    user_type: null,
    is_shadow_banned: false,
    locked: false,
  });
});

// POST /_synapse/admin/v1/deactivate/:userId - Deactivate user (Synapse format)
app.post('/_synapse/admin/v1/deactivate/:userId', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  // Check user exists
  const user = await db.prepare('SELECT user_id FROM users WHERE user_id = ?').bind(userId).first();
  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Deactivate user
  await db.prepare('UPDATE users SET is_deactivated = 1, updated_at = ? WHERE user_id = ?')
    .bind(Date.now(), userId).run();

  // Revoke all access tokens
  await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ id_server_unbind_result: 'success' });
});

// POST /_synapse/admin/v1/reset_password/:userId - Reset password (Synapse format)
app.post('/_synapse/admin/v1/reset_password/:userId', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { new_password, logout_devices } = body;
  if (!new_password) {
    return Errors.missingParam('new_password').toResponse();
  }

  // Check user exists
  const user = await db.prepare('SELECT user_id FROM users WHERE user_id = ?').bind(userId).first();
  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Hash and update password
  const { hashPassword } = await import('../utils/crypto');
  const passwordHash = await hashPassword(new_password);

  await db.prepare(
    'UPDATE users SET password_hash = ?, updated_at = ? WHERE user_id = ?'
  ).bind(passwordHash, Date.now(), userId).run();

  // Optionally revoke all access tokens (default: true per Synapse behavior)
  if (logout_devices !== false) {
    await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();
  }

  return c.json({});
});

// GET /_synapse/admin/v1/rooms - List rooms (Synapse format)
app.get('/_synapse/admin/v1/rooms', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 1000);
  const from = parseInt(c.req.query('from') || '0');
  const orderBy = c.req.query('order_by') || 'name';
  const dir = c.req.query('dir') === 'b' ? 'DESC' : 'ASC';
  const searchTerm = c.req.query('search_term');

  // Build query
  let query = `
    SELECT r.room_id, r.room_version, r.is_public as public, r.creator_id as creator, r.created_at,
           (SELECT COUNT(*) FROM room_memberships WHERE room_id = r.room_id AND membership = 'join') as joined_members,
           (SELECT COUNT(*) FROM room_memberships WHERE room_id = r.room_id) as joined_local_members,
           (SELECT COUNT(*) FROM events WHERE room_id = r.room_id) as state_events
    FROM rooms r
  `;
  const params: any[] = [];

  if (searchTerm) {
    query += ` WHERE r.room_id LIKE ?`;
    params.push(`%${searchTerm}%`);
  }

  // Order by (simplified)
  const orderColumn = orderBy === 'joined_members' ? 'joined_members' : 'r.created_at';
  query += ` ORDER BY ${orderColumn} ${dir} LIMIT ? OFFSET ?`;
  params.push(limit, from);

  const rooms = await db.prepare(query).bind(...params).all();

  // Get room names and other metadata
  const roomsWithDetails = await Promise.all(rooms.results.map(async (room: any) => {
    const nameEvent = await db.prepare(`
      SELECT e.content FROM room_state rs
      JOIN events e ON rs.event_id = e.event_id
      WHERE rs.room_id = ? AND rs.event_type = 'm.room.name'
    `).bind(room.room_id).first<{ content: string }>();

    const canonicalAliasEvent = await db.prepare(`
      SELECT e.content FROM room_state rs
      JOIN events e ON rs.event_id = e.event_id
      WHERE rs.room_id = ? AND rs.event_type = 'm.room.canonical_alias'
    `).bind(room.room_id).first<{ content: string }>();

    const topicEvent = await db.prepare(`
      SELECT e.content FROM room_state rs
      JOIN events e ON rs.event_id = e.event_id
      WHERE rs.room_id = ? AND rs.event_type = 'm.room.topic'
    `).bind(room.room_id).first<{ content: string }>();

    const avatarEvent = await db.prepare(`
      SELECT e.content FROM room_state rs
      JOIN events e ON rs.event_id = e.event_id
      WHERE rs.room_id = ? AND rs.event_type = 'm.room.avatar'
    `).bind(room.room_id).first<{ content: string }>();

    return {
      room_id: room.room_id,
      name: nameEvent ? JSON.parse(nameEvent.content).name : null,
      canonical_alias: canonicalAliasEvent ? JSON.parse(canonicalAliasEvent.content).alias : null,
      topic: topicEvent ? JSON.parse(topicEvent.content).topic : null,
      avatar: avatarEvent ? JSON.parse(avatarEvent.content).url : null,
      joined_members: room.joined_members || 0,
      joined_local_members: room.joined_local_members || 0,
      version: room.room_version,
      creator: room.creator,
      encryption: null, // Would need to check m.room.encryption state
      federatable: true,
      public: Boolean(room.public),
      join_rules: null, // Would need to check m.room.join_rules state
      guest_access: null, // Would need to check m.room.guest_access state
      history_visibility: null, // Would need to check m.room.history_visibility state
      state_events: room.state_events || 0,
    };
  }));

  const total = await db.prepare('SELECT COUNT(*) as count FROM rooms').first<{ count: number }>();

  return c.json({
    rooms: roomsWithDetails,
    offset: from,
    total_rooms: total?.count || 0,
    next_batch: from + limit < (total?.count || 0) ? from + limit : undefined,
    prev_batch: from > 0 ? Math.max(0, from - limit) : undefined,
  });
});

// GET /_synapse/admin/v1/rooms/:roomId - Room details (Synapse format)
app.get('/_synapse/admin/v1/rooms/:roomId', requireAuth(), requireAdmin, async (c) => {
  const roomId = decodeURIComponent(c.req.param('roomId'));
  const db = c.env.DB;

  const room = await db.prepare(`
    SELECT room_id, room_version, is_public, creator_id, created_at
    FROM rooms WHERE room_id = ?
  `).bind(roomId).first();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get room state
  const nameEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.name'
  `).bind(roomId).first<{ content: string }>();

  const topicEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.topic'
  `).bind(roomId).first<{ content: string }>();

  const canonicalAliasEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.canonical_alias'
  `).bind(roomId).first<{ content: string }>();

  const avatarEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.avatar'
  `).bind(roomId).first<{ content: string }>();

  const joinRulesEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'
  `).bind(roomId).first<{ content: string }>();

  // Get member count
  const memberCount = await db.prepare(`
    SELECT COUNT(*) as count FROM room_memberships WHERE room_id = ? AND membership = 'join'
  `).bind(roomId).first<{ count: number }>();

  // Get state event count
  const stateCount = await db.prepare(`
    SELECT COUNT(*) as count FROM room_state WHERE room_id = ?
  `).bind(roomId).first<{ count: number }>();

  return c.json({
    room_id: roomId,
    name: nameEvent ? JSON.parse(nameEvent.content).name : null,
    topic: topicEvent ? JSON.parse(topicEvent.content).topic : null,
    canonical_alias: canonicalAliasEvent ? JSON.parse(canonicalAliasEvent.content).alias : null,
    avatar: avatarEvent ? JSON.parse(avatarEvent.content).url : null,
    joined_members: memberCount?.count || 0,
    joined_local_members: memberCount?.count || 0,
    version: (room as any).room_version,
    creator: (room as any).creator_id,
    public: Boolean((room as any).is_public),
    join_rules: joinRulesEvent ? JSON.parse(joinRulesEvent.content).join_rule : null,
    state_events: stateCount?.count || 0,
    federatable: true,
  });
});

// GET /_synapse/admin/v1/federation/destinations - Federation destinations (Synapse format)
app.get('/_synapse/admin/v1/federation/destinations', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 1000);
  const from = parseInt(c.req.query('from') || '0');

  const servers = await db.prepare(`
    SELECT server_name as destination, valid_until_ts, last_successful_fetch as last_successful_stream_ordering,
           retry_count as failure_ts, retry_count
    FROM servers
    ORDER BY last_successful_fetch DESC
    LIMIT ? OFFSET ?
  `).bind(limit, from).all();

  const total = await db.prepare('SELECT COUNT(*) as count FROM servers').first<{ count: number }>();

  return c.json({
    destinations: servers.results.map((s: any) => ({
      destination: s.destination,
      retry_last_ts: s.failure_ts ? Date.now() - 60000 * s.retry_count : 0,
      retry_interval: s.retry_count * 60000,
      failure_ts: s.failure_ts > 0 ? Date.now() - 60000 * s.retry_count : null,
      last_successful_stream_ordering: s.last_successful_stream_ordering,
    })),
    total: total?.count || 0,
    next_token: from + limit < (total?.count || 0) ? String(from + limit) : undefined,
  });
});

// GET /_synapse/admin/v1/event_reports - Event reports (Synapse format)
app.get('/_synapse/admin/v1/event_reports', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 1000);
  const from = parseInt(c.req.query('from') || '0');
  const dir = c.req.query('dir') === 'f' ? 'ASC' : 'DESC';
  const roomId = c.req.query('room_id');
  const userId = c.req.query('user_id');

  let query = `
    SELECT cr.id, cr.reporter_user_id as user_id, cr.room_id, cr.event_id,
           cr.reason, cr.score, cr.created_at as received_ts,
           e.sender as sender, e.content
    FROM content_reports cr
    LEFT JOIN events e ON cr.event_id = e.event_id
    WHERE 1=1
  `;
  const params: any[] = [];

  if (roomId) {
    query += ' AND cr.room_id = ?';
    params.push(roomId);
  }
  if (userId) {
    query += ' AND cr.reporter_user_id = ?';
    params.push(userId);
  }

  query += ` ORDER BY cr.created_at ${dir} LIMIT ? OFFSET ?`;
  params.push(limit, from);

  const reports = await db.prepare(query).bind(...params).all();

  const total = await db.prepare('SELECT COUNT(*) as count FROM content_reports').first<{ count: number }>();

  return c.json({
    event_reports: reports.results.map((r: any) => ({
      id: r.id,
      received_ts: r.received_ts,
      room_id: r.room_id,
      user_id: r.user_id,
      reason: r.reason,
      score: r.score,
      sender: r.sender,
      event_id: r.event_id,
      event_json: r.content ? { content: JSON.parse(r.content) } : null,
    })),
    total: total?.count || 0,
    next_token: from + limit < (total?.count || 0) ? String(from + limit) : undefined,
  });
});

// DELETE /_synapse/admin/v1/rooms/:roomId - Delete room (Synapse format)
app.delete('/_synapse/admin/v1/rooms/:roomId', requireAuth(), requireAdmin, async (c) => {
  const roomId = decodeURIComponent(c.req.param('roomId'));
  const db = c.env.DB;

  // Check room exists
  const room = await db.prepare('SELECT room_id FROM rooms WHERE room_id = ?').bind(roomId).first();
  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Delete in order (foreign key constraints)
  await db.prepare('DELETE FROM room_aliases WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM room_memberships WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM room_state WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM events WHERE room_id = ?').bind(roomId).run();
  await db.prepare('DELETE FROM rooms WHERE room_id = ?').bind(roomId).run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({
    kicked_users: [],
    failed_to_kick_users: [],
    local_aliases: [],
    new_room_id: null,
  });
});

// PUT /_synapse/admin/v2/users/:userId - Create or modify user (Synapse format)
app.put('/_synapse/admin/v2/users/:userId', requireAuth(), requireAdmin, async (c) => {
  const userId = decodeURIComponent(c.req.param('userId'));
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { password, displayname, admin, deactivated, avatar_url } = body;

  // Check if user exists
  const existingUser = await db.prepare('SELECT user_id FROM users WHERE user_id = ?').bind(userId).first();

  if (existingUser) {
    // Update existing user
    const updates: string[] = [];
    const params: any[] = [];

    if (displayname !== undefined) {
      updates.push('display_name = ?');
      params.push(displayname);
    }
    if (admin !== undefined) {
      updates.push('admin = ?');
      params.push(admin ? 1 : 0);
    }
    if (deactivated !== undefined) {
      updates.push('is_deactivated = ?');
      params.push(deactivated ? 1 : 0);
    }
    if (avatar_url !== undefined) {
      updates.push('avatar_url = ?');
      params.push(avatar_url);
    }
    if (password !== undefined) {
      const { hashPassword } = await import('../utils/crypto');
      const passwordHash = await hashPassword(password);
      updates.push('password_hash = ?');
      params.push(passwordHash);
    }

    if (updates.length > 0) {
      updates.push('updated_at = ?');
      params.push(Date.now());
      params.push(userId);

      await db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE user_id = ?`).bind(...params).run();
    }

    return c.json({
      name: userId,
      displayname,
      admin: admin !== undefined ? admin : null,
      deactivated: deactivated !== undefined ? deactivated : null,
    });
  } else {
    // Create new user
    if (!password) {
      return Errors.missingParam('password required for new user').toResponse();
    }

    // Extract localpart from user_id
    const match = userId.match(/^@([^:]+):/);
    if (!match) {
      return c.json({ errcode: 'M_INVALID_USERNAME', error: 'Invalid user ID format' }, 400);
    }
    const localpart = match[1];

    const { hashPassword } = await import('../utils/crypto');
    const passwordHash = await hashPassword(password);

    await db.prepare(`
      INSERT INTO users (user_id, localpart, password_hash, display_name, avatar_url, admin, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      userId,
      localpart,
      passwordHash,
      displayname || null,
      avatar_url || null,
      admin ? 1 : 0,
      Date.now(),
      Date.now()
    ).run();

    // Invalidate stats cache
    await invalidateStatsCache(c.env);

    return c.json({
      name: userId,
      displayname: displayname || null,
      admin: admin || false,
      deactivated: false,
    });
  }
});

// ============================================
// Analytics Engine Query Endpoints
// ============================================

// Get request metrics from Analytics Engine
app.get('/_matrix/client/v3/admin/analytics/requests', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const period = c.req.query('period') || '1h';

  // Calculate time range
  const now = Date.now();
  const periodMs: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
  };
  const rangeMs = periodMs[period] || periodMs['1h'];
  const since = now - rangeMs;

  // Query from D1 events as a proxy for request activity
  const totalRequests = await db.prepare(`
    SELECT COUNT(*) as count FROM events WHERE origin_server_ts > ?
  `).bind(since).first<{ count: number }>();

  const byType = await db.prepare(`
    SELECT event_type, COUNT(*) as count FROM events
    WHERE origin_server_ts > ?
    GROUP BY event_type ORDER BY count DESC LIMIT 20
  `).bind(since).all<{ event_type: string; count: number }>();

  const activeUsers = await db.prepare(`
    SELECT COUNT(DISTINCT sender) as count FROM events WHERE origin_server_ts > ?
  `).bind(since).first<{ count: number }>();

  const activeRooms = await db.prepare(`
    SELECT COUNT(DISTINCT room_id) as count FROM events WHERE origin_server_ts > ?
  `).bind(since).first<{ count: number }>();

  return c.json({
    period,
    since: new Date(since).toISOString(),
    total_events: totalRequests?.count || 0,
    active_users: activeUsers?.count || 0,
    active_rooms: activeRooms?.count || 0,
    events_by_type: byType.results,
  });
});

// Get federation metrics
app.get('/_matrix/client/v3/admin/analytics/federation', requireAuth(), requireAdmin, async (c) => {
  const db = c.env.DB;
  const period = c.req.query('period') || '24h';

  const now = Date.now();
  const periodMs: Record<string, number> = {
    '1h': 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
  };
  const rangeMs = periodMs[period] || periodMs['24h'];
  const since = now - rangeMs;

  // Get federation event counts (events from remote servers)
  const inboundEvents = await db.prepare(`
    SELECT COUNT(*) as count FROM events
    WHERE origin_server_ts > ? AND sender NOT LIKE ?
  `).bind(since, `%:${c.env.SERVER_NAME}`).first<{ count: number }>();

  const outboundEvents = await db.prepare(`
    SELECT COUNT(*) as count FROM events
    WHERE origin_server_ts > ? AND sender LIKE ?
  `).bind(since, `%:${c.env.SERVER_NAME}`).first<{ count: number }>();

  // Get unique remote servers
  const remoteServers = await db.prepare(`
    SELECT COUNT(DISTINCT server_name) as count FROM known_servers
  `).first<{ count: number }>();

  return c.json({
    period,
    since: new Date(since).toISOString(),
    inbound_events: inboundEvents?.count || 0,
    outbound_events: outboundEvents?.count || 0,
    known_servers: remoteServers?.count || 0,
  });
});

export default app;
