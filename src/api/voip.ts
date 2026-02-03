// Matrix VoIP endpoints (TURN server credentials)

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { requireAuth } from '../middleware/auth';
import { getMatrixTurnCredentials, getStunServers, isTurnConfigured, TurnError } from '../services/turn';
import { notifyUsersOfEvent } from '../services/database';

const app = new Hono<AppEnv>();

// GET /_matrix/client/v3/voip/turnServer - Get TURN server credentials
// Spec: https://spec.matrix.org/v1.12/client-server-api/#get_matrixclientv3voipturnserver
app.get('/_matrix/client/v3/voip/turnServer', requireAuth(), async (c) => {
  const userId = c.get('userId');

  // Check if TURN is configured
  if (!isTurnConfigured(c.env)) {
    // Return STUN-only servers when TURN is not configured
    // This still helps with NAT traversal for direct connections
    return c.json(getStunServers());
  }

  try {
    // Get credentials with 1 hour TTL (good balance of security and usability)
    // Pass userId for per-user rate limiting
    const creds = await getMatrixTurnCredentials(c.env, 3600, userId);
    // Don't log credentials - they are sensitive
    console.log('[voip] TURN credentials generated successfully');
    return c.json(creds);
  } catch (error) {
    if (error instanceof TurnError) {
      console.error(`TURN error [${error.code}]: ${error.message}`);

      // For per-user rate limiting, return 429 with retry info
      if (error.code === 'USER_RATE_LIMITED') {
        return c.json({
          errcode: 'M_LIMIT_EXCEEDED',
          error: 'Too many TURN credential requests. Please try again later.',
          retry_after_ms: error.retryAfterMs || 60000,
        }, 429);
      }

      // For Cloudflare API rate limiting, return 429 to client
      if (error.code === 'RATE_LIMITED') {
        return c.json({
          errcode: 'M_LIMIT_EXCEEDED',
          error: 'TURN credential requests are rate limited. Please try again later.',
          retry_after_ms: 60000,
        }, 429);
      }

      // For other errors, return STUN-only (graceful degradation)
      // Clients will work without TURN, just may have connectivity issues behind NAT
      return c.json(getStunServers());
    }

    // Unexpected error - still return STUN servers
    console.error('Unexpected TURN error:', error);
    return c.json(getStunServers());
  }
});

// ============================================
// MatrixRTC / Element Call endpoints
// ============================================

// Note: Full MatrixRTC support requires:
// 1. Handling m.call.member state events in rooms
// 2. SFU (Selective Forwarding Unit) integration
// 3. Call membership tracking
//
// For now, we support 1:1 calls via TURN credentials above.
// Group calls via Element Call require additional infrastructure.

// GET /_matrix/client/v1/rooms/:roomId/call - Get active call in room
// Returns active call members by reading m.call.member state events
app.get('/_matrix/client/v1/rooms/:roomId/call', requireAuth(), async (c) => {
  const roomId = c.req.param('roomId');
  const userId = c.get('userId');
  const db = c.env.DB;

  // Verify user is in the room
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!membership || membership.membership !== 'join') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'You are not a member of this room',
    }, 403);
  }

  // Get all m.call.member state events for the room
  const memberEvents = await db.prepare(`
    SELECT state_key, content FROM room_state
    WHERE room_id = ? AND type = 'm.call.member'
  `).bind(roomId).all<{ state_key: string; content: string }>();

  // Find active memberships (not expired)
  const now = Date.now();
  const activeMembers: Array<{
    user_id: string;
    device_id: string;
    application?: string;
    call_id?: string;
    expires_ts?: number;
    foci_active?: Array<{ type: string; livekit_alias?: string }>;
    focus_active?: { type: string; livekit_alias?: string };
  }> = [];

  for (const event of memberEvents.results) {
    try {
      const content = JSON.parse(event.content);
      const memberships = content.memberships || [];

      for (const membership of memberships) {
        // Check if membership is still valid (not expired)
        if (!membership.expires_ts || membership.expires_ts > now) {
          activeMembers.push({
            user_id: event.state_key,
            device_id: membership.device_id,
            application: membership.application,
            call_id: membership.call_id || '',
            expires_ts: membership.expires_ts,
            foci_active: membership.foci_active,
            focus_active: membership.focus_active,
          });
        }
      }
    } catch (e) {
      console.error('[voip] Failed to parse m.call.member content:', e);
    }
  }

  if (activeMembers.length === 0) {
    return c.json({
      errcode: 'M_NOT_FOUND',
      error: 'No active call in this room',
    }, 404);
  }

  return c.json({
    call_id: '', // MatrixRTC uses empty call_id
    members: activeMembers,
  });
});

// PUT /_matrix/client/v1/rooms/:roomId/call - Join/update call membership
// Adds or updates the user's call membership via m.call.member state event
app.put('/_matrix/client/v1/rooms/:roomId/call', requireAuth(), async (c) => {
  const roomId = c.req.param('roomId');
  const userId = c.get('userId');
  const deviceId = c.get('deviceId');
  const db = c.env.DB;

  // Verify user is in the room
  const roomMembership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!roomMembership || roomMembership.membership !== 'join') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'You are not a member of this room',
    }, 403);
  }

  let body: {
    device_id?: string;
    application?: string;
    call_id?: string;
    expires_ts?: number;
    foci_active?: Array<{ type: string; livekit_alias?: string }>;
    focus_active?: { type: string; livekit_alias?: string };
  };

  try {
    body = await c.req.json();
  } catch {
    return c.json({
      errcode: 'M_NOT_JSON',
      error: 'Request body is not valid JSON',
    }, 400);
  }

  const targetDeviceId = body.device_id || deviceId;
  if (!targetDeviceId) {
    return c.json({
      errcode: 'M_MISSING_PARAM',
      error: 'device_id is required',
    }, 400);
  }

  // Get current m.call.member state for this user
  const existing = await db.prepare(`
    SELECT content FROM room_state
    WHERE room_id = ? AND type = 'm.call.member' AND state_key = ?
  `).bind(roomId, userId).first<{ content: string }>();

  let memberships: Array<{
    device_id: string;
    application?: string;
    call_id?: string;
    expires_ts?: number;
    foci_active?: Array<{ type: string; livekit_alias?: string }>;
    focus_active?: { type: string; livekit_alias?: string };
  }> = [];

  if (existing) {
    try {
      const content = JSON.parse(existing.content);
      memberships = content.memberships || [];
    } catch (e) {
      console.error('[voip] Failed to parse existing m.call.member:', e);
    }
  }

  // Create new membership entry
  const newMembership = {
    application: body.application || 'm.call',
    call_id: body.call_id || '',
    device_id: targetDeviceId,
    expires_ts: body.expires_ts || (Date.now() + 3600000), // Default 1 hour
    foci_active: body.foci_active,
    focus_active: body.focus_active,
  };

  // Update or add membership for this device
  const deviceIndex = memberships.findIndex(m => m.device_id === targetDeviceId);
  if (deviceIndex >= 0) {
    memberships[deviceIndex] = newMembership;
  } else {
    memberships.push(newMembership);
  }

  // Store the updated m.call.member state event
  const eventId = `$${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  const content = { memberships };
  const now = Date.now();

  // Insert or update room_state
  await db.prepare(`
    INSERT INTO room_state (room_id, type, state_key, event_id, content, sender, origin_server_ts)
    VALUES (?, 'm.call.member', ?, ?, ?, ?, ?)
    ON CONFLICT (room_id, type, state_key) DO UPDATE SET
      event_id = excluded.event_id,
      content = excluded.content,
      sender = excluded.sender,
      origin_server_ts = excluded.origin_server_ts
  `).bind(roomId, userId, eventId, JSON.stringify(content), userId, now).run();

  // Insert into events table for sync
  await db.prepare(`
    INSERT INTO events (event_id, room_id, type, sender, content, state_key, origin_server_ts)
    VALUES (?, ?, 'm.call.member', ?, ?, ?, ?)
  `).bind(eventId, roomId, userId, JSON.stringify(content), userId, now).run();

  console.log('[voip] User', userId, 'device', targetDeviceId, 'joined call in room', roomId);

  // Notify room members about the call state change (wakes up long-polling syncs)
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.call.member');

  return c.json({
    event_id: eventId,
  });
});

// DELETE /_matrix/client/v1/rooms/:roomId/call - Leave call
// Removes the user's call membership for the current device
app.delete('/_matrix/client/v1/rooms/:roomId/call', requireAuth(), async (c) => {
  const roomId = c.req.param('roomId');
  const userId = c.get('userId');
  const deviceId = c.get('deviceId');
  const db = c.env.DB;

  // Get device_id from query param or use current device
  const targetDeviceId = c.req.query('device_id') || deviceId;

  if (!targetDeviceId) {
    return c.json({
      errcode: 'M_MISSING_PARAM',
      error: 'device_id is required',
    }, 400);
  }

  // Get current m.call.member state for this user
  const existing = await db.prepare(`
    SELECT content FROM room_state
    WHERE room_id = ? AND type = 'm.call.member' AND state_key = ?
  `).bind(roomId, userId).first<{ content: string }>();

  if (!existing) {
    // No call membership exists, nothing to do
    return c.json({});
  }

  let memberships: Array<{
    device_id: string;
    application?: string;
    call_id?: string;
    expires_ts?: number;
    foci_active?: Array<{ type: string; livekit_alias?: string }>;
    focus_active?: { type: string; livekit_alias?: string };
  }> = [];

  try {
    const content = JSON.parse(existing.content);
    memberships = content.memberships || [];
  } catch (e) {
    console.error('[voip] Failed to parse existing m.call.member:', e);
    return c.json({});
  }

  // Remove membership for this device
  const newMemberships = memberships.filter(m => m.device_id !== targetDeviceId);

  // Store the updated m.call.member state event (with empty or reduced memberships)
  const eventId = `$${Date.now()}_${Math.random().toString(36).substring(2, 15)}`;
  const content = { memberships: newMemberships };
  const now = Date.now();

  // Update room_state
  await db.prepare(`
    UPDATE room_state
    SET event_id = ?, content = ?, sender = ?, origin_server_ts = ?
    WHERE room_id = ? AND type = 'm.call.member' AND state_key = ?
  `).bind(eventId, JSON.stringify(content), userId, now, roomId, userId).run();

  // Insert into events table for sync
  await db.prepare(`
    INSERT INTO events (event_id, room_id, type, sender, content, state_key, origin_server_ts)
    VALUES (?, ?, 'm.call.member', ?, ?, ?, ?)
  `).bind(eventId, roomId, userId, JSON.stringify(content), userId, now).run();

  console.log('[voip] User', userId, 'device', targetDeviceId, 'left call in room', roomId);

  return c.json({
    event_id: eventId,
  });
});

export default app;
