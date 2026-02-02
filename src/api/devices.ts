// Device Management API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#device-management
//
// Manages user devices for E2EE and session management.

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';
import { verifyPassword } from '../utils/crypto';
import {
  createUiaSession,
  getUiaSession,
  deleteUiaSession,
  completeUiaStage,
  isUiaComplete,
  buildUiaResponse,
  StandardFlows,
} from '../services/uia';

const app = new Hono<AppEnv>();

// ============================================
// Endpoints
// ============================================

// GET /_matrix/client/v3/devices - List all devices
app.get('/_matrix/client/v3/devices', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  const devices = await db.prepare(`
    SELECT device_id, display_name, last_seen_ts, last_seen_ip
    FROM devices
    WHERE user_id = ?
  `).bind(userId).all<{
    device_id: string;
    display_name: string | null;
    last_seen_ts: number | null;
    last_seen_ip: string | null;
  }>();

  return c.json({
    devices: devices.results.map(d => ({
      device_id: d.device_id,
      display_name: d.display_name || undefined,
      last_seen_ts: d.last_seen_ts || undefined,
      last_seen_ip: d.last_seen_ip || undefined,
    })),
  });
});

// GET /_matrix/client/v3/devices/:deviceId - Get a specific device
app.get('/_matrix/client/v3/devices/:deviceId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('deviceId');
  const db = c.env.DB;

  const device = await db.prepare(`
    SELECT device_id, display_name, last_seen_ts, last_seen_ip
    FROM devices
    WHERE user_id = ? AND device_id = ?
  `).bind(userId, deviceId).first<{
    device_id: string;
    display_name: string | null;
    last_seen_ts: number | null;
    last_seen_ip: string | null;
  }>();

  if (!device) {
    return Errors.notFound('Device not found').toResponse();
  }

  return c.json({
    device_id: device.device_id,
    display_name: device.display_name || undefined,
    last_seen_ts: device.last_seen_ts || undefined,
    last_seen_ip: device.last_seen_ip || undefined,
  });
});

// PUT /_matrix/client/v3/devices/:deviceId - Update device info
app.put('/_matrix/client/v3/devices/:deviceId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('deviceId');
  const db = c.env.DB;

  let body: { display_name?: string };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Check device exists and belongs to user
  const device = await db.prepare(`
    SELECT device_id FROM devices WHERE user_id = ? AND device_id = ?
  `).bind(userId, deviceId).first();

  if (!device) {
    return Errors.notFound('Device not found').toResponse();
  }

  // Update display name if provided
  if (body.display_name !== undefined) {
    await db.prepare(`
      UPDATE devices SET display_name = ? WHERE user_id = ? AND device_id = ?
    `).bind(body.display_name, userId, deviceId).run();
  }

  return c.json({});
});

// DELETE /_matrix/client/v3/devices/:deviceId - Delete a device
app.delete('/_matrix/client/v3/devices/:deviceId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const deviceId = c.req.param('deviceId');
  // Note: currentDeviceId could be used to prevent self-deletion in future
  void c.get('deviceId');
  const db = c.env.DB;

  // Check device exists and belongs to user
  const device = await db.prepare(`
    SELECT device_id FROM devices WHERE user_id = ? AND device_id = ?
  `).bind(userId, deviceId).first();

  if (!device) {
    return Errors.notFound('Device not found').toResponse();
  }

  // Try to get auth from body for UIA
  let auth: { type?: string; password?: string; session?: string } | undefined;
  try {
    const body = await c.req.json();
    auth = body.auth;
  } catch {
    // No auth provided
  }

  // No auth provided - create UIA session
  if (!auth) {
    const session = await createUiaSession(
      c.env.CACHE,
      'device_deletion',
      StandardFlows.passwordRequired,
      {},
      userId,
      { device_id: deviceId }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get or validate session
  const sessionId = auth.session;
  if (!sessionId) {
    const session = await createUiaSession(
      c.env.CACHE,
      'device_deletion',
      StandardFlows.passwordRequired,
      {},
      userId,
      { device_id: deviceId }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get the session
  const session = await getUiaSession(c.env.CACHE, sessionId);
  if (!session) {
    const newSession = await createUiaSession(
      c.env.CACHE,
      'device_deletion',
      StandardFlows.passwordRequired,
      {},
      userId,
      { device_id: deviceId }
    );
    return c.json({
      ...buildUiaResponse(newSession),
      error: 'Session expired, please retry',
      errcode: 'M_UNKNOWN',
    }, 401);
  }

  // Validate session belongs to this user
  if (session.user_id && session.user_id !== userId) {
    return Errors.forbidden('Session user mismatch').toResponse();
  }

  // Validate session type
  if (session.type !== 'device_deletion') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Invalid session type for device deletion',
    }, 403);
  }

  // Process auth stage
  if (auth.type === 'm.login.password') {
    const user = await db.prepare(`
      SELECT password_hash FROM users WHERE user_id = ?
    `).bind(userId).first<{ password_hash: string }>();

    if (!user) {
      return Errors.forbidden('User not found').toResponse();
    }

    if (!auth.password) {
      return Errors.missingParam('auth.password').toResponse();
    }

    const valid = await verifyPassword(auth.password, user.password_hash);
    if (!valid) {
      return c.json({
        ...buildUiaResponse(session),
        error: 'Invalid password',
        errcode: 'M_FORBIDDEN',
      }, 401);
    }

    // Password verified - mark stage complete
    await completeUiaStage(c.env.CACHE, sessionId, 'm.login.password');
  } else if (auth.type) {
    return c.json({
      errcode: 'M_UNRECOGNIZED',
      error: `Unknown auth type: ${auth.type}`,
    }, 400);
  }

  // Check if UIA is complete
  const updatedSession = await getUiaSession(c.env.CACHE, sessionId);
  if (!updatedSession || !isUiaComplete(updatedSession)) {
    return c.json(buildUiaResponse(updatedSession || session), 401);
  }

  // UIA complete - clean up session
  await deleteUiaSession(c.env.CACHE, sessionId);

  // Delete the device and its access tokens
  await db.prepare(`
    DELETE FROM access_tokens WHERE user_id = ? AND device_id = ?
  `).bind(userId, deviceId).run();

  await db.prepare(`
    DELETE FROM device_keys WHERE user_id = ? AND device_id = ?
  `).bind(userId, deviceId).run();

  await db.prepare(`
    DELETE FROM devices WHERE user_id = ? AND device_id = ?
  `).bind(userId, deviceId).run();

  return c.json({});
});

// POST /_matrix/client/v3/delete_devices - Delete multiple devices
app.post('/_matrix/client/v3/delete_devices', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  let body: { devices: string[]; auth?: { type?: string; password?: string; session?: string } };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  if (!body.devices || !Array.isArray(body.devices)) {
    return Errors.missingParam('devices').toResponse();
  }

  const auth = body.auth;

  // No auth provided - create UIA session
  if (!auth) {
    const session = await createUiaSession(
      c.env.CACHE,
      'device_deletion',
      StandardFlows.passwordRequired,
      {},
      userId,
      { devices: body.devices }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get or validate session
  const sessionId = auth.session;
  if (!sessionId) {
    const session = await createUiaSession(
      c.env.CACHE,
      'device_deletion',
      StandardFlows.passwordRequired,
      {},
      userId,
      { devices: body.devices }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get the session
  const session = await getUiaSession(c.env.CACHE, sessionId);
  if (!session) {
    const newSession = await createUiaSession(
      c.env.CACHE,
      'device_deletion',
      StandardFlows.passwordRequired,
      {},
      userId,
      { devices: body.devices }
    );
    return c.json({
      ...buildUiaResponse(newSession),
      error: 'Session expired, please retry',
      errcode: 'M_UNKNOWN',
    }, 401);
  }

  // Validate session belongs to this user
  if (session.user_id && session.user_id !== userId) {
    return Errors.forbidden('Session user mismatch').toResponse();
  }

  // Validate session type
  if (session.type !== 'device_deletion') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Invalid session type for device deletion',
    }, 403);
  }

  // Process auth stage
  if (auth.type === 'm.login.password') {
    const user = await db.prepare(`
      SELECT password_hash FROM users WHERE user_id = ?
    `).bind(userId).first<{ password_hash: string }>();

    if (!user) {
      return Errors.forbidden('User not found').toResponse();
    }

    if (!auth.password) {
      return Errors.missingParam('auth.password').toResponse();
    }

    const valid = await verifyPassword(auth.password, user.password_hash);
    if (!valid) {
      return c.json({
        ...buildUiaResponse(session),
        error: 'Invalid password',
        errcode: 'M_FORBIDDEN',
      }, 401);
    }

    // Password verified - mark stage complete
    await completeUiaStage(c.env.CACHE, sessionId, 'm.login.password');
  } else if (auth.type) {
    return c.json({
      errcode: 'M_UNRECOGNIZED',
      error: `Unknown auth type: ${auth.type}`,
    }, 400);
  }

  // Check if UIA is complete
  const updatedSession = await getUiaSession(c.env.CACHE, sessionId);
  if (!updatedSession || !isUiaComplete(updatedSession)) {
    return c.json(buildUiaResponse(updatedSession || session), 401);
  }

  // UIA complete - clean up session
  await deleteUiaSession(c.env.CACHE, sessionId);

  // Delete each device
  for (const deviceId of body.devices) {
    await db.prepare(`
      DELETE FROM access_tokens WHERE user_id = ? AND device_id = ?
    `).bind(userId, deviceId).run();

    await db.prepare(`
      DELETE FROM device_keys WHERE user_id = ? AND device_id = ?
    `).bind(userId, deviceId).run();

    await db.prepare(`
      DELETE FROM devices WHERE user_id = ? AND device_id = ?
    `).bind(userId, deviceId).run();
  }

  return c.json({});
});

export default app;
