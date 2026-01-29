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

  // Delete all user data in order (foreign key constraints)
  await db.prepare('DELETE FROM account_data WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM account_data_changes WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM cross_signing_keys WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM cross_signing_signatures WHERE user_id = ? OR signer_user_id = ?').bind(userId, userId).run();
  await db.prepare('DELETE FROM one_time_keys WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM fallback_keys WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM device_key_changes WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM to_device_messages WHERE recipient_user_id = ? OR sender_user_id = ?').bind(userId, userId).run();
  await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM devices WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM room_memberships WHERE user_id = ?').bind(userId).run();
  await db.prepare('DELETE FROM users WHERE user_id = ?').bind(userId).run();

  // Delete device keys from KV
  const devices = await db.prepare('SELECT device_id FROM devices WHERE user_id = ?').bind(userId).all<{ device_id: string }>();
  for (const device of devices.results) {
    await c.env.DEVICE_KEYS.delete(`device:${userId}:${device.device_id}`);
  }

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
    await db.prepare('DELETE FROM account_data WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM account_data_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM cross_signing_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM cross_signing_signatures WHERE user_id = ? OR signer_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM one_time_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM fallback_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM device_key_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM to_device_messages WHERE recipient_user_id = ? OR sender_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM devices WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM room_memberships WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM users WHERE user_id = ?').bind(userId).run();
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

  // Delete user-related data
  for (const userId of userIds) {
    await db.prepare('DELETE FROM account_data WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM account_data_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM cross_signing_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM cross_signing_signatures WHERE user_id = ? OR signer_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM one_time_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM fallback_keys WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM device_key_changes WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM to_device_messages WHERE recipient_user_id = ? OR sender_user_id = ?').bind(userId, userId).run();
    await db.prepare('DELETE FROM access_tokens WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM devices WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM room_memberships WHERE user_id = ?').bind(userId).run();
    await db.prepare('DELETE FROM users WHERE user_id = ?').bind(userId).run();
  }

  // Delete all rooms and events
  await db.prepare('DELETE FROM room_state').run();
  await db.prepare('DELETE FROM room_aliases').run();
  await db.prepare('DELETE FROM events').run();
  await db.prepare('DELETE FROM rooms').run();

  // Invalidate stats cache
  await invalidateStatsCache(c.env);

  return c.json({ success: true, users_deleted: userIds.length });
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
    SELECT id, device_id, created_at
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
    'DELETE FROM access_tokens WHERE id = ?'
  ).bind(parseInt(sessionId)).run();

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

export default app;
