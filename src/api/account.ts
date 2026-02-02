// Account Management API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#account-management
//
// Password changes, account deactivation, 3PIDs (email/phone)

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';
import { hashPassword, verifyPassword } from '../utils/crypto';
import { getPasswordHash, deleteAllUserTokens } from '../services/database';
import {
  sendVerificationEmail,
  createVerificationSession,
  validateEmailToken,
  getValidatedSession,
} from '../services/email';
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
// Password Management
// ============================================

// POST /_matrix/client/v3/account/password - Change password
app.post('/_matrix/client/v3/account/password', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  let body: {
    new_password: string;
    logout_devices?: boolean;
    auth?: { type: string; session?: string; password?: string };
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { new_password, logout_devices = true, auth } = body;

  if (!new_password) {
    return Errors.missingParam('new_password').toResponse();
  }

  // No auth provided - create UIA session
  if (!auth) {
    const session = await createUiaSession(
      c.env.CACHE,
      'password_change',
      StandardFlows.passwordRequired,
      {},
      userId
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get or validate session
  const sessionId = auth.session;
  if (!sessionId) {
    // No session - create one
    const session = await createUiaSession(
      c.env.CACHE,
      'password_change',
      StandardFlows.passwordRequired,
      {},
      userId
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get the session
  const session = await getUiaSession(c.env.CACHE, sessionId);
  if (!session) {
    // Session expired - create new one
    const newSession = await createUiaSession(
      c.env.CACHE,
      'password_change',
      StandardFlows.passwordRequired,
      {},
      userId
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
  if (session.type !== 'password_change') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Invalid session type for password change',
    }, 403);
  }

  // Process auth stage
  if (auth.type === 'm.login.password') {
    // Verify current password
    const storedHash = await getPasswordHash(db, userId);
    if (!storedHash) {
      return Errors.forbidden('No password set for user').toResponse();
    }

    if (!auth.password) {
      return Errors.missingParam('auth.password').toResponse();
    }

    const valid = await verifyPassword(auth.password, storedHash);
    if (!valid) {
      // Return UIA response with error
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

  // Hash new password
  const newHash = await hashPassword(new_password);

  // Update password
  await db.prepare(`
    UPDATE users SET password_hash = ? WHERE user_id = ?
  `).bind(newHash, userId).run();

  // Logout all devices if requested
  if (logout_devices) {
    await deleteAllUserTokens(db, userId);
  }

  return c.json({});
});

// POST /_matrix/client/v3/account/password/email/requestToken - Request password reset via email
app.post('/_matrix/client/v3/account/password/email/requestToken', async (c) => {
  // Email-based password reset not supported
  return c.json({
    errcode: 'M_THREEPID_NOT_FOUND',
    error: 'Email-based password reset is not supported',
  }, 400);
});

// POST /_matrix/client/v3/account/password/msisdn/requestToken - Request password reset via phone
app.post('/_matrix/client/v3/account/password/msisdn/requestToken', async (c) => {
  // Phone-based password reset not supported
  return c.json({
    errcode: 'M_THREEPID_NOT_FOUND',
    error: 'Phone-based password reset is not supported',
  }, 400);
});

// ============================================
// Account Deactivation
// ============================================

// POST /_matrix/client/v3/account/deactivate - Deactivate account
app.post('/_matrix/client/v3/account/deactivate', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  let body: {
    id_server?: string;
    erase?: boolean;
    auth?: { type: string; session?: string; password?: string };
  };

  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  const { erase = false, auth } = body;

  // No auth provided - create UIA session
  if (!auth) {
    const session = await createUiaSession(
      c.env.CACHE,
      'account_deactivation',
      StandardFlows.passwordRequired,
      {},
      userId,
      { erase }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get or validate session
  const sessionId = auth.session;
  if (!sessionId) {
    const session = await createUiaSession(
      c.env.CACHE,
      'account_deactivation',
      StandardFlows.passwordRequired,
      {},
      userId,
      { erase }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get the session
  const session = await getUiaSession(c.env.CACHE, sessionId);
  if (!session) {
    const newSession = await createUiaSession(
      c.env.CACHE,
      'account_deactivation',
      StandardFlows.passwordRequired,
      {},
      userId,
      { erase }
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
  if (session.type !== 'account_deactivation') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Invalid session type for account deactivation',
    }, 403);
  }

  // Process auth stage
  if (auth.type === 'm.login.password') {
    const storedHash = await getPasswordHash(db, userId);
    if (storedHash) {
      if (!auth.password) {
        return Errors.missingParam('auth.password').toResponse();
      }

      const valid = await verifyPassword(auth.password, storedHash);
      if (!valid) {
        return c.json({
          ...buildUiaResponse(session),
          error: 'Invalid password',
          errcode: 'M_FORBIDDEN',
        }, 401);
      }
    }

    // Password verified (or no password set) - mark stage complete
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

  // Mark user as deactivated
  await db.prepare(`
    UPDATE users SET is_deactivated = 1 WHERE user_id = ?
  `).bind(userId).run();

  // Delete all access tokens
  await deleteAllUserTokens(db, userId);

  // If erase is true, remove personal data
  if (erase) {
    // Clear display name and avatar
    await db.prepare(`
      UPDATE users SET display_name = NULL, avatar_url = NULL WHERE user_id = ?
    `).bind(userId).run();

    // Leave all rooms
    const rooms = await db.prepare(`
      SELECT room_id FROM room_memberships WHERE user_id = ? AND membership = 'join'
    `).bind(userId).all<{ room_id: string }>();

    for (const room of rooms.results) {
      await db.prepare(`
        UPDATE room_memberships SET membership = 'leave' WHERE room_id = ? AND user_id = ?
      `).bind(room.room_id, userId).run();
    }
  }

  return c.json({
    id_server_unbind_result: 'no-support',
  });
});

// ============================================
// Third-Party Identifiers (3PIDs)
// ============================================

// GET /_matrix/client/v3/account/3pid - Get 3PIDs
app.get('/_matrix/client/v3/account/3pid', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  // Get user's 3PIDs from database
  const threepids = await db.prepare(`
    SELECT medium, address, validated_at, added_at
    FROM user_threepids
    WHERE user_id = ?
  `).bind(userId).all<{
    medium: string;
    address: string;
    validated_at: number;
    added_at: number;
  }>();

  return c.json({
    threepids: threepids.results.map(t => ({
      medium: t.medium,
      address: t.address,
      validated_at: t.validated_at,
      added_at: t.added_at,
    })),
  });
});

// POST /_matrix/client/v3/account/3pid/add - Add 3PID (with UIA)
app.post('/_matrix/client/v3/account/3pid/add', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  let body: {
    client_secret: string;
    sid: string;
    auth?: { type: string; session?: string; password?: string };
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { client_secret, sid, auth } = body;

  if (!client_secret || !sid) {
    return Errors.missingParam('client_secret and sid are required').toResponse();
  }

  // No auth provided - create UIA session
  if (!auth) {
    const session = await createUiaSession(
      c.env.CACHE,
      'threepid_add',
      StandardFlows.passwordRequired,
      {},
      userId,
      { client_secret, sid }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get or validate session
  const uiaSessionId = auth.session;
  if (!uiaSessionId) {
    const session = await createUiaSession(
      c.env.CACHE,
      'threepid_add',
      StandardFlows.passwordRequired,
      {},
      userId,
      { client_secret, sid }
    );
    return c.json(buildUiaResponse(session), 401);
  }

  // Get the UIA session
  const uiaSession = await getUiaSession(c.env.CACHE, uiaSessionId);
  if (!uiaSession) {
    const newSession = await createUiaSession(
      c.env.CACHE,
      'threepid_add',
      StandardFlows.passwordRequired,
      {},
      userId,
      { client_secret, sid }
    );
    return c.json({
      ...buildUiaResponse(newSession),
      error: 'Session expired, please retry',
      errcode: 'M_UNKNOWN',
    }, 401);
  }

  // Validate session belongs to this user
  if (uiaSession.user_id && uiaSession.user_id !== userId) {
    return Errors.forbidden('Session user mismatch').toResponse();
  }

  // Validate session type
  if (uiaSession.type !== 'threepid_add') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Invalid session type for adding 3PID',
    }, 403);
  }

  // Process auth stage
  if (auth.type === 'm.login.password') {
    const storedHash = await getPasswordHash(db, userId);
    if (storedHash) {
      if (!auth.password) {
        return Errors.missingParam('auth.password').toResponse();
      }

      const valid = await verifyPassword(auth.password, storedHash);
      if (!valid) {
        return c.json({
          ...buildUiaResponse(uiaSession),
          error: 'Invalid password',
          errcode: 'M_FORBIDDEN',
        }, 401);
      }
    }

    // Password verified - mark stage complete
    await completeUiaStage(c.env.CACHE, uiaSessionId, 'm.login.password');
  } else if (auth.type) {
    return c.json({
      errcode: 'M_UNRECOGNIZED',
      error: `Unknown auth type: ${auth.type}`,
    }, 400);
  }

  // Check if UIA is complete
  const updatedSession = await getUiaSession(c.env.CACHE, uiaSessionId);
  if (!updatedSession || !isUiaComplete(updatedSession)) {
    return c.json(buildUiaResponse(updatedSession || uiaSession), 401);
  }

  // UIA complete - clean up session
  await deleteUiaSession(c.env.CACHE, uiaSessionId);

  // Verify the email verification session is validated
  const validatedSession = await getValidatedSession(db, sid, client_secret);
  if (!validatedSession) {
    return c.json({
      errcode: 'M_THREEPID_AUTH_FAILED',
      error: 'Email verification not completed or session expired',
    }, 400);
  }

  // Check if this email is already bound to another user
  const existingBinding = await db.prepare(`
    SELECT user_id FROM user_threepids
    WHERE medium = 'email' AND address = ?
  `).bind(validatedSession.email).first<{ user_id: string }>();

  if (existingBinding && existingBinding.user_id !== userId) {
    return c.json({
      errcode: 'M_THREEPID_IN_USE',
      error: 'This email is already associated with another account',
    }, 400);
  }

  // Add the 3PID to the user's account
  const now = Date.now();
  await db.prepare(`
    INSERT OR REPLACE INTO user_threepids (user_id, medium, address, validated_at, added_at)
    VALUES (?, 'email', ?, ?, ?)
  `).bind(userId, validatedSession.email, now, now).run();

  // Clean up the verification session
  await db.prepare(`
    DELETE FROM email_verification_sessions WHERE session_id = ?
  `).bind(sid).run();

  return c.json({});
});

// POST /_matrix/client/v3/account/3pid/bind - Bind 3PID to identity server
app.post('/_matrix/client/v3/account/3pid/bind', requireAuth(), async (c) => {
  return c.json({
    errcode: 'M_THREEPID_AUTH_FAILED',
    error: 'Identity server binding is not supported',
  }, 400);
});

// POST /_matrix/client/v3/account/3pid/delete - Delete 3PID
app.post('/_matrix/client/v3/account/3pid/delete', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  let body: { medium: string; address: string; id_server?: string };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { medium, address } = body;

  if (!medium || !address) {
    return Errors.missingParam('medium or address').toResponse();
  }

  await db.prepare(`
    DELETE FROM user_threepids WHERE user_id = ? AND medium = ? AND address = ?
  `).bind(userId, medium, address).run();

  return c.json({
    id_server_unbind_result: 'no-support',
  });
});

// POST /_matrix/client/v3/account/3pid/unbind - Unbind 3PID from identity server
app.post('/_matrix/client/v3/account/3pid/unbind', requireAuth(), async (c) => {
  return c.json({
    id_server_unbind_result: 'no-support',
  });
});

// POST /_matrix/client/v3/account/3pid/email/requestToken - Request email verification
app.post('/_matrix/client/v3/account/3pid/email/requestToken', async (c) => {
  const db = c.env.DB;

  let body: {
    client_secret: string;
    email: string;
    send_attempt: number;
    next_link?: string;
    id_server?: string;
    id_access_token?: string;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { client_secret, email, send_attempt } = body;

  if (!client_secret) {
    return Errors.missingParam('client_secret').toResponse();
  }
  if (!email) {
    return Errors.missingParam('email').toResponse();
  }
  if (send_attempt === undefined) {
    return Errors.missingParam('send_attempt').toResponse();
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return c.json({
      errcode: 'M_INVALID_EMAIL',
      error: 'Invalid email address format',
    }, 400);
  }

  // Check if email is already bound to an account (for account 3PID addition)
  const existingBinding = await db.prepare(`
    SELECT user_id FROM user_threepids
    WHERE medium = 'email' AND address = ?
  `).bind(email).first<{ user_id: string }>();

  if (existingBinding) {
    return c.json({
      errcode: 'M_THREEPID_IN_USE',
      error: 'This email is already associated with an account',
    }, 400);
  }

  // Create verification session
  const result = await createVerificationSession(db, email, client_secret, send_attempt);

  if ('error' in result) {
    return c.json({
      errcode: 'M_THREEPID_DENIED',
      error: result.error,
    }, 400);
  }

  // If token is empty, it's a retry of an existing session
  if (result.token) {
    // Send verification email
    const emailResult = await sendVerificationEmail(
      c.env,
      email,
      result.token,
      c.env.SERVER_NAME
    );

    if (!emailResult.success) {
      // Clean up session on email failure
      await db.prepare(`
        DELETE FROM email_verification_sessions WHERE session_id = ?
      `).bind(result.sessionId).run();

      return c.json({
        errcode: 'M_THREEPID_DENIED',
        error: emailResult.error || 'Failed to send verification email',
      }, 500);
    }
  }

  return c.json({
    sid: result.sessionId,
  });
});

// POST /_matrix/client/v3/account/3pid/submit_token - Submit verification code (unofficial but widely used)
// Some clients may also use GET for this endpoint
app.post('/_matrix/client/v3/account/3pid/submit_token', async (c) => {
  const db = c.env.DB;

  let body: {
    sid: string;
    client_secret: string;
    token: string;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { sid, client_secret, token } = body;

  if (!sid) {
    return Errors.missingParam('sid').toResponse();
  }
  if (!client_secret) {
    return Errors.missingParam('client_secret').toResponse();
  }
  if (!token) {
    return Errors.missingParam('token').toResponse();
  }

  const result = await validateEmailToken(db, sid, client_secret, token);

  if (!result.success) {
    return c.json({
      errcode: 'M_THREEPID_AUTH_FAILED',
      error: result.error || 'Verification failed',
    }, 400);
  }

  return c.json({
    success: true,
  });
});

// GET /_matrix/client/v3/account/3pid/submit_token - Submit verification code (GET version)
app.get('/_matrix/client/v3/account/3pid/submit_token', async (c) => {
  const db = c.env.DB;

  const sid = c.req.query('sid');
  const client_secret = c.req.query('client_secret');
  const token = c.req.query('token');

  if (!sid) {
    return Errors.missingParam('sid').toResponse();
  }
  if (!client_secret) {
    return Errors.missingParam('client_secret').toResponse();
  }
  if (!token) {
    return Errors.missingParam('token').toResponse();
  }

  const result = await validateEmailToken(db, sid, client_secret, token);

  if (!result.success) {
    return c.json({
      errcode: 'M_THREEPID_AUTH_FAILED',
      error: result.error || 'Verification failed',
    }, 400);
  }

  return c.json({
    success: true,
  });
});

// POST /_matrix/client/v3/account/3pid/msisdn/requestToken - Request phone verification
app.post('/_matrix/client/v3/account/3pid/msisdn/requestToken', async (c) => {
  return c.json({
    errcode: 'M_THREEPID_DENIED',
    error: 'Phone verification is not supported',
  }, 403);
});

// ============================================
// Registration Token
// ============================================

// GET /_matrix/client/v1/register/m.login.registration_token/validity - Check registration token
app.get('/_matrix/client/v1/register/m.login.registration_token/validity', async (c) => {
  const token = c.req.query('token');

  if (!token) {
    return Errors.missingParam('token').toResponse();
  }

  // Registration tokens not supported - always invalid
  return c.json({ valid: false });
});

// ============================================
// OpenID Token (for third-party services like Element Call/LiveKit)
// ============================================

// POST /_matrix/client/v3/user/:userId/openid/request_token
// Generates a short-lived token that third-party services can use to verify the user's identity
// Spec: https://spec.matrix.org/v1.12/client-server-api/#post_matrixclientv3useruseridopenidrequest_token
app.post('/_matrix/client/v3/user/:userId/openid/request_token', requireAuth(), async (c) => {
  const requestingUserId = c.get('userId');
  const targetUserId = decodeURIComponent(c.req.param('userId'));
  const serverName = c.env.SERVER_NAME;

  // Users can only request tokens for themselves
  if (requestingUserId !== targetUserId) {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Cannot request OpenID token for another user',
    }, 403);
  }

  // Generate a short-lived access token for OpenID
  // This token can be exchanged with third-party services to prove identity
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const accessToken = btoa(String.fromCharCode(...tokenBytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  // Token expires in 1 hour (3600 seconds)
  const expiresIn = 3600;

  // Store the OpenID token in KV for verification by third-party services
  // The token maps to the user ID so services can verify who the token belongs to
  const tokenData = {
    user_id: requestingUserId,
    created_at: Date.now(),
    expires_at: Date.now() + (expiresIn * 1000),
  };

  await c.env.CACHE.put(
    `openid_token:${accessToken}`,
    JSON.stringify(tokenData),
    { expirationTtl: expiresIn }
  );

  return c.json({
    access_token: accessToken,
    token_type: 'Bearer',
    matrix_server_name: serverName,
    expires_in: expiresIn,
  });
});

export default app;
