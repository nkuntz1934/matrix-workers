// Content Reporting API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#reporting-content
//
// Allows users to report inappropriate content to server admins

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';

const app = new Hono<AppEnv>();

// ============================================
// Types
// ============================================

interface ContentReport {
  id: number;
  reporter_user_id: string;
  room_id: string;
  event_id: string;
  reason: string;
  score: number;
  created_at: number;
  resolved: boolean;
  resolved_by?: string;
  resolved_at?: number;
  resolution_note?: string;
}

// ============================================
// Endpoints
// ============================================

// POST /_matrix/client/v3/rooms/:roomId/report/:eventId - Report content
app.post('/_matrix/client/v3/rooms/:roomId/report/:eventId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');
  const db = c.env.DB;

  let body: { reason?: string; score?: number };
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  const reason = body.reason || '';
  const score = typeof body.score === 'number' ? Math.max(-100, Math.min(0, body.score)) : -100;

  // Check if user is a member of the room
  const membership = await db.prepare(`
    SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).first<{ membership: string }>();

  if (!membership || !['join', 'leave'].includes(membership.membership)) {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check if event exists
  const event = await db.prepare(`
    SELECT event_id FROM events WHERE event_id = ? AND room_id = ?
  `).bind(eventId, roomId).first();

  if (!event) {
    return Errors.notFound('Event not found').toResponse();
  }

  // Check for duplicate report
  const existing = await db.prepare(`
    SELECT id FROM content_reports
    WHERE reporter_user_id = ? AND room_id = ? AND event_id = ?
  `).bind(userId, roomId, eventId).first();

  if (existing) {
    // Update existing report
    await db.prepare(`
      UPDATE content_reports SET reason = ?, score = ?, created_at = ?
      WHERE reporter_user_id = ? AND room_id = ? AND event_id = ?
    `).bind(reason, score, Date.now(), userId, roomId, eventId).run();
  } else {
    // Create new report
    await db.prepare(`
      INSERT INTO content_reports (reporter_user_id, room_id, event_id, reason, score, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(userId, roomId, eventId, reason, score, Date.now()).run();
  }

  return c.json({});
});

// POST /_matrix/client/v3/rooms/:roomId/report - Report a room
app.post('/_matrix/client/v3/rooms/:roomId/report', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  let body: { reason?: string; score?: number };
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  const reason = body.reason || '';
  const score = typeof body.score === 'number' ? Math.max(-100, Math.min(0, body.score)) : -100;

  // Check if room exists
  const room = await db.prepare(`
    SELECT room_id FROM rooms WHERE room_id = ?
  `).bind(roomId).first();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check for duplicate report (using NULL event_id for room reports)
  const existing = await db.prepare(`
    SELECT id FROM content_reports
    WHERE reporter_user_id = ? AND room_id = ? AND event_id IS NULL AND report_type = 'room'
  `).bind(userId, roomId).first();

  if (existing) {
    // Update existing report
    await db.prepare(`
      UPDATE content_reports SET reason = ?, score = ?, created_at = ?
      WHERE reporter_user_id = ? AND room_id = ? AND event_id IS NULL AND report_type = 'room'
    `).bind(reason, score, Date.now(), userId, roomId).run();
  } else {
    // Create new report
    await db.prepare(`
      INSERT INTO content_reports (reporter_user_id, room_id, event_id, reason, score, created_at, report_type)
      VALUES (?, ?, NULL, ?, ?, ?, 'room')
    `).bind(userId, roomId, reason, score, Date.now()).run();
  }

  return c.json({});
});

// POST /_matrix/client/v3/users/:reportedUserId/report - Report a user
app.post('/_matrix/client/v3/users/:reportedUserId/report', requireAuth(), async (c) => {
  const reporterId = c.get('userId');
  const reportedUserId = decodeURIComponent(c.req.param('reportedUserId'));
  const db = c.env.DB;

  let body: { reason?: string };
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  const reason = body.reason || '';

  // Check if reported user exists
  const user = await db.prepare(`
    SELECT user_id FROM users WHERE user_id = ?
  `).bind(reportedUserId).first();

  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Check for duplicate report
  const existing = await db.prepare(`
    SELECT id FROM content_reports
    WHERE reporter_user_id = ? AND reported_user_id = ? AND report_type = 'user'
  `).bind(reporterId, reportedUserId).first();

  if (existing) {
    // Update existing report
    await db.prepare(`
      UPDATE content_reports SET reason = ?, created_at = ?
      WHERE reporter_user_id = ? AND reported_user_id = ? AND report_type = 'user'
    `).bind(reason, Date.now(), reporterId, reportedUserId).run();
  } else {
    // Create new report
    await db.prepare(`
      INSERT INTO content_reports (reporter_user_id, room_id, event_id, reason, score, created_at, report_type, reported_user_id)
      VALUES (?, NULL, NULL, ?, -100, ?, 'user', ?)
    `).bind(reporterId, reason, Date.now(), reportedUserId).run();
  }

  return c.json({});
});

// ============================================
// Admin Endpoints for Managing Reports
// ============================================

// GET /_matrix/client/v3/admin/reports - List reports (admin only)
app.get('/_matrix/client/v3/admin/reports', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  // Check if user is admin
  const user = await db.prepare(`
    SELECT admin FROM users WHERE user_id = ?
  `).bind(userId).first<{ admin: number }>();

  if (!user || user.admin !== 1) {
    return Errors.forbidden('Admin access required').toResponse();
  }

  const from = c.req.query('from');
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
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

  if (from) {
    query += ` AND cr.id < ?`;
    params.push(parseInt(from));
  }

  query += ` ORDER BY cr.created_at DESC LIMIT ?`;
  params.push(limit + 1);

  const reports = await db.prepare(query).bind(...params).all<ContentReport & {
    reported_user_id: string;
    event_type: string;
    content: string;
  }>();

  const hasMore = reports.results.length > limit;
  const results = reports.results.slice(0, limit);

  const response: any = {
    reports: results.map(r => ({
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
  };

  if (hasMore && results.length > 0) {
    response.next_token = String(results[results.length - 1].id);
  }

  return c.json(response);
});

// GET /_matrix/client/v3/admin/reports/:reportId - Get specific report
app.get('/_matrix/client/v3/admin/reports/:reportId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const reportId = c.req.param('reportId');
  const db = c.env.DB;

  // Check if user is admin
  const user = await db.prepare(`
    SELECT admin FROM users WHERE user_id = ?
  `).bind(userId).first<{ admin: number }>();

  if (!user || user.admin !== 1) {
    return Errors.forbidden('Admin access required').toResponse();
  }

  const report = await db.prepare(`
    SELECT cr.*, e.sender as reported_user_id, e.event_type, e.content
    FROM content_reports cr
    LEFT JOIN events e ON cr.event_id = e.event_id
    WHERE cr.id = ?
  `).bind(parseInt(reportId)).first<ContentReport & {
    reported_user_id: string;
    event_type: string;
    content: string;
  }>();

  if (!report) {
    return Errors.notFound('Report not found').toResponse();
  }

  return c.json({
    id: report.id,
    reporter_user_id: report.reporter_user_id,
    reported_user_id: report.reported_user_id,
    room_id: report.room_id,
    event_id: report.event_id,
    event_type: report.event_type,
    event_content: report.content ? JSON.parse(report.content) : null,
    reason: report.reason,
    score: report.score,
    created_at: report.created_at,
    resolved: report.resolved,
    resolved_by: report.resolved_by,
    resolved_at: report.resolved_at,
    resolution_note: report.resolution_note,
  });
});

// POST /_matrix/client/v3/admin/reports/:reportId/resolve - Resolve a report
app.post('/_matrix/client/v3/admin/reports/:reportId/resolve', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const reportId = c.req.param('reportId');
  const db = c.env.DB;

  // Check if user is admin
  const user = await db.prepare(`
    SELECT admin FROM users WHERE user_id = ?
  `).bind(userId).first<{ admin: number }>();

  if (!user || user.admin !== 1) {
    return Errors.forbidden('Admin access required').toResponse();
  }

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

  return c.json({});
});

export default app;
