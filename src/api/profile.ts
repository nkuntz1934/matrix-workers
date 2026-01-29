// Matrix profile endpoints

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth, optionalAuth } from '../middleware/auth';
import { getUserById, updateUserProfile } from '../services/database';
import { parseUserId, isLocalServerName } from '../utils/ids';

const app = new Hono<AppEnv>();

// GET /_matrix/client/v3/profile/:userId - Get user profile
app.get('/_matrix/client/v3/profile/:userId', optionalAuth(), async (c) => {
  const targetUserId = decodeURIComponent(c.req.param('userId'));

  // Check if this is a local user
  const parsed = parseUserId(targetUserId);
  if (!parsed) {
    return Errors.invalidParam('user_id', 'Invalid user ID format').toResponse();
  }

  if (!isLocalServerName(parsed.serverName, c.env.SERVER_NAME)) {
    // Remote user - would need federation lookup
    return Errors.notFound('User not found').toResponse();
  }

  const user = await getUserById(c.env.DB, targetUserId);
  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  console.log('[profile] Fetching profile for:', targetUserId, {
    hasDisplayName: !!user.display_name,
    hasAvatar: !!user.avatar_url,
  });

  // Always return both fields (even if null) to indicate user exists
  // Element X uses this to verify users from directory search
  return c.json({
    displayname: user.display_name || null,
    avatar_url: user.avatar_url || null,
  });
});

// GET /_matrix/client/v3/profile/:userId/displayname - Get display name
app.get('/_matrix/client/v3/profile/:userId/displayname', optionalAuth(), async (c) => {
  const targetUserId = decodeURIComponent(c.req.param('userId'));

  const parsed = parseUserId(targetUserId);
  if (!parsed) {
    return Errors.invalidParam('user_id', 'Invalid user ID format').toResponse();
  }

  if (!isLocalServerName(parsed.serverName, c.env.SERVER_NAME)) {
    return Errors.notFound('User not found').toResponse();
  }

  const user = await getUserById(c.env.DB, targetUserId);
  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  return c.json({
    displayname: user.display_name || null,
  });
});

// PUT /_matrix/client/v3/profile/:userId/displayname - Set display name
app.put('/_matrix/client/v3/profile/:userId/displayname', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const targetUserId = decodeURIComponent(c.req.param('userId'));

  // Can only change own profile
  if (userId !== targetUserId) {
    return Errors.forbidden('Cannot modify another user\'s profile').toResponse();
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { displayname } = body;

  await updateUserProfile(c.env.DB, userId, displayname);

  return c.json({});
});

// GET /_matrix/client/v3/profile/:userId/avatar_url - Get avatar URL
app.get('/_matrix/client/v3/profile/:userId/avatar_url', optionalAuth(), async (c) => {
  const targetUserId = decodeURIComponent(c.req.param('userId'));

  const parsed = parseUserId(targetUserId);
  if (!parsed) {
    return Errors.invalidParam('user_id', 'Invalid user ID format').toResponse();
  }

  if (!isLocalServerName(parsed.serverName, c.env.SERVER_NAME)) {
    return Errors.notFound('User not found').toResponse();
  }

  const user = await getUserById(c.env.DB, targetUserId);
  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  return c.json({
    avatar_url: user.avatar_url || null,
  });
});

// PUT /_matrix/client/v3/profile/:userId/avatar_url - Set avatar URL
app.put('/_matrix/client/v3/profile/:userId/avatar_url', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const targetUserId = decodeURIComponent(c.req.param('userId'));

  // Can only change own profile
  if (userId !== targetUserId) {
    return Errors.forbidden('Cannot modify another user\'s profile').toResponse();
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { avatar_url } = body;

  await updateUserProfile(c.env.DB, userId, undefined, avatar_url);

  return c.json({});
});

// ============================================
// Custom Profile Keys (Matrix v1.17 Extension)
// ============================================

// GET /_matrix/client/v3/profile/:userId/:keyName - Get custom profile key
app.get('/_matrix/client/v3/profile/:userId/:keyName', optionalAuth(), async (c) => {
  const targetUserId = decodeURIComponent(c.req.param('userId'));
  const keyName = c.req.param('keyName');

  // These are handled by the specific endpoints above
  if (keyName === 'displayname' || keyName === 'avatar_url') {
    // Let Hono route to the correct handler
    // This shouldn't be reached due to route ordering, but defensive coding
    return c.json({ errcode: 'M_UNRECOGNIZED', error: 'Use specific endpoint' }, 400);
  }

  const parsed = parseUserId(targetUserId);
  if (!parsed) {
    return Errors.invalidParam('user_id', 'Invalid user ID format').toResponse();
  }

  if (!isLocalServerName(parsed.serverName, c.env.SERVER_NAME)) {
    return Errors.notFound('User not found').toResponse();
  }

  const user = await getUserById(c.env.DB, targetUserId);
  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Get custom profile data from KV
  const profileJson = await c.env.CACHE.get(`profile:${targetUserId}:custom`);
  const profileData = profileJson ? JSON.parse(profileJson) : {};

  if (!(keyName in profileData)) {
    return Errors.notFound(`Profile key '${keyName}' not found`).toResponse();
  }

  return c.json({ [keyName]: profileData[keyName] });
});

// PUT /_matrix/client/v3/profile/:userId/:keyName - Set custom profile key
app.put('/_matrix/client/v3/profile/:userId/:keyName', requireAuth(), async (c) => {
  const authUserId = c.get('userId');
  const targetUserId = decodeURIComponent(c.req.param('userId'));
  const keyName = c.req.param('keyName');

  // Cannot modify another user's profile
  if (authUserId !== targetUserId) {
    return Errors.forbidden('Cannot modify another user\'s profile').toResponse();
  }

  // Standard keys are handled by specific endpoints
  if (keyName === 'displayname' || keyName === 'avatar_url') {
    return c.json({ errcode: 'M_UNRECOGNIZED', error: 'Use specific endpoint' }, 400);
  }

  let body: Record<string, unknown>;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const value = body[keyName];
  if (value === undefined) {
    return c.json({ errcode: 'M_MISSING_PARAM', error: `Missing '${keyName}' in request body` }, 400);
  }

  // Get current profile data from KV
  const profileJson = await c.env.CACHE.get(`profile:${targetUserId}:custom`);
  const profileData = profileJson ? JSON.parse(profileJson) : {};

  // Update the key
  profileData[keyName] = value;

  // Store back in KV with 1-year TTL
  await c.env.CACHE.put(
    `profile:${targetUserId}:custom`,
    JSON.stringify(profileData),
    { expirationTtl: 365 * 24 * 60 * 60 }
  );

  return c.json({});
});

// DELETE /_matrix/client/v3/profile/:userId/:keyName - Delete custom profile key
app.delete('/_matrix/client/v3/profile/:userId/:keyName', requireAuth(), async (c) => {
  const authUserId = c.get('userId');
  const targetUserId = decodeURIComponent(c.req.param('userId'));
  const keyName = c.req.param('keyName');

  // Cannot modify another user's profile
  if (authUserId !== targetUserId) {
    return Errors.forbidden('Cannot modify another user\'s profile').toResponse();
  }

  // Cannot delete standard keys
  if (keyName === 'displayname' || keyName === 'avatar_url') {
    return Errors.forbidden('Cannot delete standard profile keys').toResponse();
  }

  // Get current profile data from KV
  const profileJson = await c.env.CACHE.get(`profile:${targetUserId}:custom`);
  const profileData = profileJson ? JSON.parse(profileJson) : {};

  // Remove the key
  delete profileData[keyName];

  // Store back in KV
  await c.env.CACHE.put(
    `profile:${targetUserId}:custom`,
    JSON.stringify(profileData),
    { expirationTtl: 365 * 24 * 60 * 60 }
  );

  return c.json({});
});

export default app;
