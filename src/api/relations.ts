// Relations and Threads API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#aggregations-of-child-events
//
// Relations allow events to reference other events (replies, reactions, threads, edits)

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';

const app = new Hono<AppEnv>();

// ============================================
// Types
// ============================================

// RelationEvent structure for event relations
export interface RelationEvent {
  event_id: string;
  type: string;
  sender: string;
  origin_server_ts: number;
  content: Record<string, any>;
}

// ============================================
// Endpoints
// ============================================

// GET /_matrix/client/v1/rooms/:roomId/relations/:eventId - Get all relations
app.get('/_matrix/client/v1/rooms/:roomId/relations/:eventId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');
  const db = c.env.DB;

  // Check membership
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!membership || !['join', 'leave'].includes(membership.membership)) {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Get pagination params
  const from = c.req.query('from');
  // Note: 'to' pagination param reserved for future use
  void c.req.query('to');
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const dir = c.req.query('dir') || 'b'; // backwards by default

  // Query relations
  let query = `
    SELECT e.event_id, e.event_type, e.sender, e.origin_server_ts, e.content
    FROM events e
    JOIN event_relations er ON er.event_id = e.event_id
    WHERE e.room_id = ? AND er.relates_to_id = ?
  `;
  const params: any[] = [roomId, eventId];

  if (from) {
    if (dir === 'b') {
      query += ` AND e.origin_server_ts < ?`;
    } else {
      query += ` AND e.origin_server_ts > ?`;
    }
    params.push(parseInt(from));
  }

  query += ` ORDER BY e.origin_server_ts ${dir === 'b' ? 'DESC' : 'ASC'} LIMIT ?`;
  params.push(limit + 1);

  const results = await db.prepare(query).bind(...params).all<{
    event_id: string;
    event_type: string;
    sender: string;
    origin_server_ts: number;
    content: string;
  }>();

  const hasMore = results.results.length > limit;
  const events = results.results.slice(0, limit).map(e => ({
    event_id: e.event_id,
    type: e.event_type,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    content: JSON.parse(e.content),
    room_id: roomId,
  }));

  const response: any = {
    chunk: events,
  };

  if (hasMore && events.length > 0) {
    response.next_batch = events[events.length - 1].origin_server_ts.toString();
  }

  return c.json(response);
});

// GET /_matrix/client/v1/rooms/:roomId/relations/:eventId/:relType - Get relations by type
app.get('/_matrix/client/v1/rooms/:roomId/relations/:eventId/:relType', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');
  const relType = c.req.param('relType');
  const db = c.env.DB;

  // Check membership
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!membership || !['join', 'leave'].includes(membership.membership)) {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Get pagination params
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const dir = c.req.query('dir') || 'b';

  // Query relations by type
  const results = await db.prepare(`
    SELECT e.event_id, e.event_type, e.sender, e.origin_server_ts, e.content
    FROM events e
    JOIN event_relations er ON er.event_id = e.event_id
    WHERE e.room_id = ? AND er.relates_to_id = ? AND er.relation_type = ?
    ORDER BY e.origin_server_ts ${dir === 'b' ? 'DESC' : 'ASC'}
    LIMIT ?
  `).bind(roomId, eventId, relType, limit + 1).all<{
    event_id: string;
    event_type: string;
    sender: string;
    origin_server_ts: number;
    content: string;
  }>();

  const hasMore = results.results.length > limit;
  const events = results.results.slice(0, limit).map(e => ({
    event_id: e.event_id,
    type: e.event_type,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    content: JSON.parse(e.content),
    room_id: roomId,
  }));

  const response: any = {
    chunk: events,
  };

  if (hasMore && events.length > 0) {
    response.next_batch = events[events.length - 1].origin_server_ts.toString();
  }

  return c.json(response);
});

// GET /_matrix/client/v1/rooms/:roomId/relations/:eventId/:relType/:eventType - Get relations by type and event type
app.get('/_matrix/client/v1/rooms/:roomId/relations/:eventId/:relType/:eventType', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');
  const relType = c.req.param('relType');
  const eventType = c.req.param('eventType');
  const db = c.env.DB;

  // Check membership
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!membership || !['join', 'leave'].includes(membership.membership)) {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const dir = c.req.query('dir') || 'b';

  // Query relations by type and event type
  const results = await db.prepare(`
    SELECT e.event_id, e.event_type, e.sender, e.origin_server_ts, e.content
    FROM events e
    JOIN event_relations er ON er.event_id = e.event_id
    WHERE e.room_id = ? AND er.relates_to_id = ? AND er.relation_type = ? AND e.event_type = ?
    ORDER BY e.origin_server_ts ${dir === 'b' ? 'DESC' : 'ASC'}
    LIMIT ?
  `).bind(roomId, eventId, relType, eventType, limit + 1).all<{
    event_id: string;
    event_type: string;
    sender: string;
    origin_server_ts: number;
    content: string;
  }>();

  const hasMore = results.results.length > limit;
  const events = results.results.slice(0, limit).map(e => ({
    event_id: e.event_id,
    type: e.event_type,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    content: JSON.parse(e.content),
    room_id: roomId,
  }));

  const response: any = {
    chunk: events,
  };

  if (hasMore && events.length > 0) {
    response.next_batch = events[events.length - 1].origin_server_ts.toString();
  }

  return c.json(response);
});

// GET /_matrix/client/v1/rooms/:roomId/threads - List threads in room
app.get('/_matrix/client/v1/rooms/:roomId/threads', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  // Check membership
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!membership || !['join', 'leave'].includes(membership.membership)) {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const include = c.req.query('include') || 'all'; // 'all' or 'participated'

  // Find thread roots (events that have replies with m.thread relation)
  let query = `
    SELECT DISTINCT e.event_id, e.event_type, e.sender, e.origin_server_ts, e.content
    FROM events e
    WHERE e.room_id = ? AND e.event_id IN (
      SELECT DISTINCT er.relates_to_id
      FROM event_relations er
      JOIN events child ON child.event_id = er.event_id
      WHERE child.room_id = ? AND er.relation_type = 'm.thread'
    )
  `;
  const params: any[] = [roomId, roomId];

  if (include === 'participated') {
    query += ` AND (e.sender = ? OR EXISTS (
      SELECT 1
      FROM event_relations er2
      JOIN events r ON r.event_id = er2.event_id
      WHERE er2.relates_to_id = e.event_id
        AND er2.relation_type = 'm.thread'
        AND r.sender = ?
    ))`;
    params.push(userId, userId);
  }

  query += ` ORDER BY e.origin_server_ts DESC LIMIT ?`;
  params.push(limit);

  const results = await db.prepare(query).bind(...params).all<{
    event_id: string;
    event_type: string;
    sender: string;
    origin_server_ts: number;
    content: string;
  }>();

  const threads = results.results.map(e => ({
    event_id: e.event_id,
    type: e.event_type,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    content: JSON.parse(e.content),
    room_id: roomId,
  }));

  return c.json({
    chunk: threads,
  });
});

export default app;
