// Matrix key management endpoints (E2EE)
// Implements: https://spec.matrix.org/v1.12/client-server-api/#end-to-end-encryption
//
// This module handles:
// - Device key upload/query
// - One-time key management
// - Cross-signing keys (master, self-signing, user-signing)
// - Key change tracking
//
// IMPORTANT: Cross-signing keys use Durable Objects for strong consistency.
// Per the Cloudflare blog: "Some operations can't tolerate eventual consistency"
// D1 has eventual consistency across read replicas, which breaks E2EE bootstrap.

import { Hono } from 'hono';
import type { AppEnv, Env } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';
import { verifyPassword } from '../utils/crypto';
import { generateOpaqueId } from '../utils/ids';
import { getPasswordHash } from '../services/database';

const app = new Hono<AppEnv>();

// Helper to get the UserKeys Durable Object stub for a user
function getUserKeysDO(env: Env, userId: string): DurableObjectStub {
  const id = env.USER_KEYS.idFromName(userId);
  return env.USER_KEYS.get(id);
}

// Fetch cross-signing keys from Durable Object (strongly consistent)
async function getCrossSigningKeysFromDO(env: Env, userId: string): Promise<{
  master?: any;
  self_signing?: any;
  user_signing?: any;
}> {
  const stub = getUserKeysDO(env, userId);
  const response = await stub.fetch(new Request('http://internal/cross-signing/get'));

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'unknown error');
    console.error('[keys] DO cross-signing get failed:', response.status, errorText);
    throw new Error(`DO cross-signing get failed: ${response.status} - ${errorText}`);
  }

  return await response.json();
}

// Store cross-signing keys in Durable Object (strongly consistent)
async function putCrossSigningKeysToDO(env: Env, userId: string, keys: {
  master?: any;
  self_signing?: any;
  user_signing?: any;
}): Promise<void> {
  const stub = getUserKeysDO(env, userId);
  const response = await stub.fetch(new Request('http://internal/cross-signing/put', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(keys),
  }));

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'unknown error');
    console.error('[keys] DO cross-signing put failed:', response.status, errorText);
    throw new Error(`DO cross-signing put failed: ${response.status} - ${errorText}`);
  }
}

// Fetch device keys from Durable Object (strongly consistent)
async function getDeviceKeysFromDO(env: Env, userId: string, deviceId?: string): Promise<any> {
  const stub = getUserKeysDO(env, userId);
  const url = deviceId
    ? `http://internal/device-keys/get?device_id=${encodeURIComponent(deviceId)}`
    : 'http://internal/device-keys/get';
  const response = await stub.fetch(new Request(url));

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'unknown error');
    console.error('[keys] DO device-keys get failed:', response.status, errorText, 'deviceId:', deviceId);
    throw new Error(`DO device-keys get failed: ${response.status} - ${errorText}`);
  }

  return await response.json();
}

// Store device keys in Durable Object (strongly consistent)
async function putDeviceKeysToDO(env: Env, userId: string, deviceId: string, keys: any): Promise<void> {
  const stub = getUserKeysDO(env, userId);
  const response = await stub.fetch(new Request('http://internal/device-keys/put', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_id: deviceId, keys }),
  }));

  if (!response.ok) {
    const errorText = await response.text().catch(() => 'unknown error');
    console.error('[keys] DO device-keys put failed:', response.status, errorText, 'deviceId:', deviceId);
    throw new Error(`DO device-keys put failed: ${response.status} - ${errorText}`);
  }
}


// ============================================
// Helper Functions
// ============================================

async function getNextStreamPosition(db: D1Database, streamName: string): Promise<number> {
  await db.prepare(`
    UPDATE stream_positions SET position = position + 1 WHERE stream_name = ?
  `).bind(streamName).run();

  const result = await db.prepare(`
    SELECT position FROM stream_positions WHERE stream_name = ?
  `).bind(streamName).first<{ position: number }>();

  return result?.position || 1;
}

async function recordKeyChange(db: D1Database, userId: string, deviceId: string | null, changeType: string): Promise<void> {
  const streamPosition = await getNextStreamPosition(db, 'device_keys');

  await db.prepare(`
    INSERT INTO device_key_changes (user_id, device_id, change_type, stream_position)
    VALUES (?, ?, ?, ?)
  `).bind(userId, deviceId, changeType, streamPosition).run();
}

// ============================================
// Device Keys
// ============================================

// POST /_matrix/client/v3/keys/upload - Upload device keys and one-time keys
app.post('/_matrix/client/v3/keys/upload', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const deviceId = c.get('deviceId');
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { device_keys, one_time_keys, fallback_keys } = body;

  // Store device keys with strong consistency
  if (device_keys) {
    // Validate device_keys structure
    console.log('[keys/upload] Validating device_keys:', {
      authUserId: userId,
      authDeviceId: deviceId,
      bodyUserId: device_keys.user_id,
      bodyDeviceId: device_keys.device_id,
      userMatch: device_keys.user_id === userId,
      deviceMatch: device_keys.device_id === deviceId,
    });
    
    if (device_keys.user_id !== userId || device_keys.device_id !== deviceId) {
      console.log('[keys/upload] MISMATCH - returning 400');
      return c.json({
        errcode: 'M_INVALID_PARAM',
        error: `device_keys.user_id and device_keys.device_id must match authenticated user. Got user_id=${device_keys.user_id} (expected ${userId}), device_id=${device_keys.device_id} (expected ${deviceId})`,
      }, 400);
    }

    // Write to Durable Object first (primary - strongly consistent)
    // This is critical for E2EE bootstrap where client uploads then immediately queries
    await putDeviceKeysToDO(c.env, userId, deviceId!, device_keys);

    // Also write to KV as backup/cache
    await c.env.DEVICE_KEYS.put(
      `device:${userId}:${deviceId}`,
      JSON.stringify(device_keys)
    );

    // Record key change for /keys/changes
    await recordKeyChange(db, userId, deviceId, 'update');

    // Queue outbound m.device_list_update EDUs to federated servers
    try {
      const { getServersInRoomsWithUser } = await import('../services/database');
      const remoteServers = await getServersInRoomsWithUser(db, userId);
      const localServer = c.env.SERVER_NAME;
      const uniqueServers = [...new Set(remoteServers)].filter(s => s !== localServer);

      for (const server of uniqueServers) {
        const fedDO = c.env.FEDERATION.get(c.env.FEDERATION.idFromName(server));
        await fedDO.fetch(new Request('http://internal/send-edu', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            destination: server,
            edu_type: 'm.device_list_update',
            content: {
              user_id: userId,
              device_id: deviceId,
              device_display_name: device_keys.unsigned?.device_display_name,
              stream_id: Date.now(),
              keys: device_keys,
              deleted: false,
            },
          }),
        }));
      }
    } catch (fedErr) {
      console.warn('[keys] Failed to queue device list EDUs:', fedErr);
    }
  }

  // Store one-time keys in KV for fast access
  const oneTimeKeyCounts: Record<string, number> = {};

  if (one_time_keys) {
    // Get existing keys from KV
    const existingKeys = await c.env.ONE_TIME_KEYS.get(
      `otk:${userId}:${deviceId}`,
      'json'
    ) as Record<string, { keyId: string; keyData: any; claimed: boolean }[]> | null || {};

    for (const [keyId, keyData] of Object.entries(one_time_keys)) {
      const [algorithm] = keyId.split(':');

      if (!existingKeys[algorithm]) {
        existingKeys[algorithm] = [];
      }

      // Check if key already exists
      const existingIndex = existingKeys[algorithm].findIndex(k => k.keyId === keyId);
      if (existingIndex >= 0) {
        existingKeys[algorithm][existingIndex] = { keyId, keyData, claimed: false };
      } else {
        existingKeys[algorithm].push({ keyId, keyData, claimed: false });
      }

      // Also write to D1 as backup
      await db.prepare(`
        INSERT INTO one_time_keys (user_id, device_id, algorithm, key_id, key_data)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (user_id, device_id, algorithm, key_id) DO UPDATE SET
          key_data = excluded.key_data
      `).bind(
        userId,
        deviceId,
        algorithm,
        keyId,
        JSON.stringify(keyData)
      ).run();
    }

    // Save back to KV
    await c.env.ONE_TIME_KEYS.put(
      `otk:${userId}:${deviceId}`,
      JSON.stringify(existingKeys)
    );

    // Count unclaimed keys
    for (const [algorithm, keys] of Object.entries(existingKeys)) {
      oneTimeKeyCounts[algorithm] = keys.filter(k => !k.claimed).length;
    }
  } else {
    // Just get counts from KV
    const existingKeys = await c.env.ONE_TIME_KEYS.get(
      `otk:${userId}:${deviceId}`,
      'json'
    ) as Record<string, { keyId: string; keyData: any; claimed: boolean }[]> | null;

    if (existingKeys) {
      for (const [algorithm, keys] of Object.entries(existingKeys)) {
        oneTimeKeyCounts[algorithm] = keys.filter(k => !k.claimed).length;
      }
    }
  }

  // Store fallback keys
  if (fallback_keys) {
    for (const [keyId, keyData] of Object.entries(fallback_keys)) {
      const [algorithm] = keyId.split(':');

      await db.prepare(`
        INSERT INTO fallback_keys (user_id, device_id, algorithm, key_id, key_data)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT (user_id, device_id, algorithm) DO UPDATE SET
          key_id = excluded.key_id,
          key_data = excluded.key_data,
          used = 0
      `).bind(userId, deviceId, algorithm, keyId, JSON.stringify(keyData)).run();
    }
  }

  return c.json({
    one_time_key_counts: oneTimeKeyCounts,
  });
});

// POST /_matrix/client/v3/keys/query - Query device keys for users
app.post('/_matrix/client/v3/keys/query', requireAuth(), async (c) => {
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { device_keys: requestedKeys } = body;

  const deviceKeys: Record<string, Record<string, any>> = {};
  const masterKeys: Record<string, any> = {};
  const selfSigningKeys: Record<string, any> = {};
  const userSigningKeys: Record<string, any> = {};
  const failures: Record<string, any> = {};

  // Helper function to merge signatures from DB into device keys
  async function mergeSignaturesForDevice(userId: string, deviceId: string, deviceKey: any): Promise<any> {
    // Get any additional signatures from the database
    const dbSignatures = await db.prepare(`
      SELECT signer_user_id, signer_key_id, signature
      FROM cross_signing_signatures
      WHERE user_id = ? AND key_id = ?
    `).bind(userId, deviceId).all<{
      signer_user_id: string;
      signer_key_id: string;
      signature: string;
    }>();

    if (dbSignatures.results.length > 0) {
      deviceKey.signatures = deviceKey.signatures || {};
      for (const sig of dbSignatures.results) {
        deviceKey.signatures[sig.signer_user_id] = deviceKey.signatures[sig.signer_user_id] || {};
        deviceKey.signatures[sig.signer_user_id][sig.signer_key_id] = sig.signature;
      }
    }

    return deviceKey;
  }

  if (requestedKeys) {
    for (const [userId, devices] of Object.entries(requestedKeys)) {
      deviceKeys[userId] = {};

      // Get device keys from Durable Object (strongly consistent)
      // Critical for E2EE bootstrap where client uploads then immediately queries
      const requestedDevices = Array.isArray(devices) && devices.length > 0 ? devices : null;

      if (requestedDevices === null || requestedDevices.length === 0) {
        // Get all devices for this user from Durable Object
        const allDeviceKeys = await getDeviceKeysFromDO(c.env, userId);
        for (const [deviceId, keys] of Object.entries(allDeviceKeys)) {
          if (keys) {
            // Merge any DB signatures into the device keys
            deviceKeys[userId][deviceId] = await mergeSignaturesForDevice(userId, deviceId, keys);
          }
        }
      } else {
        // Get specific devices from Durable Object
        for (const deviceId of requestedDevices) {
          const keys = await getDeviceKeysFromDO(c.env, userId, deviceId);
          if (keys) {
            // Merge any DB signatures into the device keys
            deviceKeys[userId][deviceId] = await mergeSignaturesForDevice(userId, deviceId, keys);
          }
        }
      }

      // Get cross-signing keys from Durable Object (strongly consistent)
      // Per Cloudflare blog: D1 has eventual consistency across read replicas.
      // Durable Objects provide single-threaded, atomic storage - critical for
      // E2EE bootstrap where client uploads then immediately queries keys.
      const requestingUserId = c.get('userId');

      const csKeys = await getCrossSigningKeysFromDO(c.env, userId);

      if (csKeys.master) {
        masterKeys[userId] = csKeys.master;
      }
      if (csKeys.self_signing) {
        selfSigningKeys[userId] = csKeys.self_signing;
      }
      // Only return user_signing key if querying own keys
      if (csKeys.user_signing && userId === requestingUserId) {
        userSigningKeys[userId] = csKeys.user_signing;
      }
    }
  }

  return c.json({
    device_keys: deviceKeys,
    master_keys: masterKeys,
    self_signing_keys: selfSigningKeys,
    user_signing_keys: userSigningKeys,
    failures,
  });
});

// POST /_matrix/client/v3/keys/claim - Claim one-time keys for establishing sessions
app.post('/_matrix/client/v3/keys/claim', requireAuth(), async (c) => {
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { one_time_keys: requestedKeys } = body;

  const oneTimeKeys: Record<string, Record<string, Record<string, any>>> = {};
  const failures: Record<string, any> = {};

  if (requestedKeys) {
    for (const [userId, devices] of Object.entries(requestedKeys)) {
      oneTimeKeys[userId] = {};

      for (const [deviceId, algorithm] of Object.entries(devices as Record<string, string>)) {
        // Try to claim a one-time key from KV first
        const existingKeys = await c.env.ONE_TIME_KEYS.get(
          `otk:${userId}:${deviceId}`,
          'json'
        ) as Record<string, { keyId: string; keyData: any; claimed: boolean }[]> | null;

        let foundKey = false;

        if (existingKeys && existingKeys[algorithm]) {
          // Find first unclaimed key
          const keyIndex = existingKeys[algorithm].findIndex(k => !k.claimed);
          if (keyIndex >= 0) {
            const key = existingKeys[algorithm][keyIndex];
            // Mark as claimed
            existingKeys[algorithm][keyIndex].claimed = true;

            // Save back to KV
            await c.env.ONE_TIME_KEYS.put(
              `otk:${userId}:${deviceId}`,
              JSON.stringify(existingKeys)
            );

            // Also mark in D1
            await db.prepare(`
              UPDATE one_time_keys SET claimed = 1, claimed_at = ?
              WHERE user_id = ? AND device_id = ? AND key_id = ?
            `).bind(Date.now(), userId, deviceId, key.keyId).run();

            oneTimeKeys[userId][deviceId] = {
              [key.keyId]: key.keyData,
            };
            foundKey = true;
          }
        }

        if (!foundKey) {
          // Fallback to D1 for legacy keys
          const otk = await db.prepare(`
            SELECT id, key_id, key_data FROM one_time_keys
            WHERE user_id = ? AND device_id = ? AND algorithm = ? AND claimed = 0
            LIMIT 1
          `).bind(userId, deviceId, algorithm).first<{
            id: number;
            key_id: string;
            key_data: string;
          }>();

          if (otk) {
            // Mark as claimed
            await db.prepare(`
              UPDATE one_time_keys SET claimed = 1, claimed_at = ? WHERE id = ?
            `).bind(Date.now(), otk.id).run();

            oneTimeKeys[userId][deviceId] = {
              [otk.key_id]: JSON.parse(otk.key_data),
            };
            foundKey = true;
          }
        }

        if (!foundKey) {
          // Try fallback key
          const fallback = await db.prepare(`
            SELECT key_id, key_data, used FROM fallback_keys
            WHERE user_id = ? AND device_id = ? AND algorithm = ?
          `).bind(userId, deviceId, algorithm).first<{
            key_id: string;
            key_data: string;
            used: number;
          }>();

          if (fallback) {
            // Mark fallback as used
            await db.prepare(`
              UPDATE fallback_keys SET used = 1 WHERE user_id = ? AND device_id = ? AND algorithm = ?
            `).bind(userId, deviceId, algorithm).run();

            const keyData = JSON.parse(fallback.key_data);
            oneTimeKeys[userId][deviceId] = {
              [fallback.key_id]: {
                ...keyData,
                fallback: true,
              },
            };
          }
        }
      }
    }
  }

  return c.json({
    one_time_keys: oneTimeKeys,
    failures,
  });
});

// GET /_matrix/client/v3/keys/changes - Get users whose keys have changed
app.get('/_matrix/client/v3/keys/changes', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const from = c.req.query('from');
  const to = c.req.query('to');
  const db = c.env.DB;

  if (!from || !to) {
    return Errors.missingParam('from and to required').toResponse();
  }

  const fromPosition = parseInt(from, 10) || 0;
  const toPosition = parseInt(to, 10) || Number.MAX_SAFE_INTEGER;

  // Get users whose keys changed in this range
  // Only return users that share rooms with the requesting user
  const changes = await db.prepare(`
    SELECT DISTINCT dkc.user_id, dkc.change_type
    FROM device_key_changes dkc
    WHERE dkc.stream_position > ? AND dkc.stream_position <= ?
      AND dkc.user_id IN (
        SELECT DISTINCT rm2.user_id
        FROM room_memberships rm1
        JOIN room_memberships rm2 ON rm1.room_id = rm2.room_id
        WHERE rm1.user_id = ? AND rm1.membership = 'join' AND rm2.membership = 'join'
      )
  `).bind(fromPosition, toPosition, userId).all<{
    user_id: string;
    change_type: string;
  }>();

  const changed: string[] = [];
  const left: string[] = [];

  for (const change of changes.results) {
    if (change.change_type === 'delete') {
      left.push(change.user_id);
    } else {
      changed.push(change.user_id);
    }
  }

  return c.json({
    changed: [...new Set(changed)],
    left: [...new Set(left)],
  });
});

// ============================================
// Cross-Signing Keys
// ============================================

// Helper: Check if user has OIDC/SSO link (logged in via external IdP)
async function isOIDCUser(db: D1Database, userId: string): Promise<boolean> {
  const result = await db.prepare(`
    SELECT COUNT(*) as count FROM idp_user_links WHERE user_id = ?
  `).bind(userId).first<{ count: number }>();
  return (result?.count || 0) > 0;
}

// Helper: Check if user has password set
async function hasPassword(db: D1Database, userId: string): Promise<boolean> {
  const hash = await getPasswordHash(db, userId);
  return hash !== null && hash.length > 0;
}

// POST /_matrix/client/v3/keys/device_signing/upload - Upload cross-signing keys
// Spec: https://spec.matrix.org/v1.12/client-server-api/#post_matrixclientv3keysdevice_signingupload
// This endpoint requires UIA (User-Interactive Authentication)
// 
// For OIDC users (users linked to external IdP), we support:
// - m.login.sso: Redirect to OAuth authorize for re-authentication
// - m.login.token: Token-based authentication (fallback)
// For password users, we support:
// - m.login.password: Password-based authentication
app.post('/_matrix/client/v3/keys/device_signing/upload', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { master_key, self_signing_key, user_signing_key, auth } = body;

  // Debug logging for cross-signing key uploads
  console.log('[keys] Cross-signing upload for user:', userId);
  console.log('[keys] Auth provided:', auth ? JSON.stringify(auth) : 'none');
  if (master_key) console.log('[keys] Master key:', JSON.stringify(master_key));
  if (self_signing_key) console.log('[keys] Self-signing key:', JSON.stringify(self_signing_key));
  if (user_signing_key) console.log('[keys] User-signing key:', JSON.stringify(user_signing_key));

  // Check if user already has cross-signing keys set up
  const existingKeys = await db.prepare(`
    SELECT COUNT(*) as count FROM cross_signing_keys WHERE user_id = ?
  `).bind(userId).first<{ count: number }>();

  const hasExistingKeys = (existingKeys?.count || 0) > 0;
  console.log('[keys] User has existing keys:', hasExistingKeys);

  // Check user's authentication capabilities
  const userIsOIDC = await isOIDCUser(db, userId);
  const userHasPassword = await hasPassword(db, userId);
  // Log auth method type without exposing sensitive details
  console.log('[keys] User auth method: OIDC=' + (userIsOIDC ? 'yes' : 'no') + ', password=' + (userHasPassword ? 'yes' : 'no'));

  // MSC3967: Do not require UIA when first uploading cross-signing keys
  // Per Matrix spec v1.11+, if user has NO existing cross-signing keys, skip UIA for first-time setup
  // If user HAS existing keys, require authentication
  if (!hasExistingKeys) {
    // First-time cross-signing setup - skip UIA per MSC3967
    console.log('[keys] First-time cross-signing setup - skipping UIA per MSC3967');
  } else if (!auth) {
    // User has existing keys but no auth provided - return UIA challenge
    const sessionId = await generateOpaqueId(16);

    // Build available flows based on user's authentication method
    const flows: Array<{ stages: string[] }> = [];
    const serverName = c.env.SERVER_NAME;
    const baseUrl = `https://${serverName}`;
    const params: Record<string, any> = {};
    
    if (userIsOIDC) {
      // OIDC users: Use org.matrix.cross_signing_reset per MSC4312
      // This is the unstable identifier; stable is m.oauth
      // Per MSC4312: "To prevent breaking clients that have implemented the unstable identifier,
      // servers SHOULD offer two flows (one with each of m.oauth and org.matrix.cross_signing_reset)"
      const unstableStage = 'org.matrix.cross_signing_reset';
      const stableStage = 'm.oauth';
      
      // Offer both flows for compatibility during migration
      flows.push({ stages: [unstableStage] });
      flows.push({ stages: [stableStage] });
      
      // The URL points to authorization server's account management UI
      // where the user can approve the cross-signing reset
      const approvalUrl = `${baseUrl}/oauth/authorize/uia?session=${sessionId}&action=org.matrix.cross_signing_reset`;
      
      // Both stages use the same params with 'url' pointing to approval page
      params[unstableStage] = { url: approvalUrl };
      params[stableStage] = { url: approvalUrl };
    }
    
    if (userHasPassword) {
      // Password users: Offer password flow
      flows.push({ stages: ['m.login.password'] });
    }
    
    // Fallback: If user has neither (shouldn't happen), offer password flow
    if (flows.length === 0) {
      flows.push({ stages: ['m.login.password'] });
    }

    // Store session in KV for validation
    await c.env.CACHE.put(
      `uia_session:${sessionId}`,
      JSON.stringify({
        user_id: userId,
        created_at: Date.now(),
        type: 'device_signing_upload',
        completed_stages: [],
        is_oidc_user: userIsOIDC,
        has_password: userHasPassword,
      }),
      { expirationTtl: 300 } // 5 minute session
    );

    console.log('[keys] UIA required (existing keys), returning challenge with session:', sessionId, 'flows:', flows);

    // Return UIA challenge
    return c.json({
      flows,
      params,
      session: sessionId,
    }, 401);
  } else {
    // Auth provided for key replacement - validate it
    console.log('[keys] Auth type:', auth.type);

    if (auth.type === 'm.login.password') {
      // Validate password
      const storedHash = await getPasswordHash(db, userId);
      if (!storedHash) {
        console.log('[keys] No password hash found for user');
        return Errors.forbidden('No password set for user').toResponse();
      }

      if (!auth.password) {
        console.log('[keys] No password in auth object');
        return Errors.missingParam('auth.password').toResponse();
      }

      const valid = await verifyPassword(auth.password, storedHash);
      if (!valid) {
        console.log('[keys] Invalid password');
        return Errors.forbidden('Invalid password').toResponse();
      }

      console.log('[keys] Password validated successfully');
    } else if (auth.type === 'org.matrix.cross_signing_reset' || auth.type === 'm.oauth' ||
               auth.type === 'm.login.oauth' || auth.type === 'm.login.sso' || auth.type === 'm.login.token' ||
               !auth.type) {
      // MSC4312 cross-signing reset flow for OIDC users
      // Supports:
      // - org.matrix.cross_signing_reset (unstable per MSC4312)
      // - m.oauth (stable per MSC4312)
      // - m.login.oauth, m.login.sso, m.login.token (legacy compatibility)
      // - No type at all (per MSC4312: client just sends session)
      
      const sessionId = auth.session;
      if (!sessionId) {
        console.log('[keys] No session ID in OAuth/cross-signing auth');
        return Errors.missingParam('auth.session').toResponse();
      }

      const sessionJson = await c.env.CACHE.get(`uia_session:${sessionId}`);
      if (!sessionJson) {
        console.log('[keys] UIA session not found or expired');
        return c.json({
          errcode: 'M_UNKNOWN',
          error: 'UIA session not found or expired',
        }, 401);
      }

      const session = JSON.parse(sessionJson);
      
      // Check if session belongs to this user
      if (session.user_id !== userId) {
        console.log('[keys] UIA session user mismatch');
        return Errors.forbidden('Session user mismatch').toResponse();
      }

      // Check if the cross-signing reset has been approved via OAuth flow
      // Accept any of the stage names that indicate completion
      const completedStages = session.completed_stages || [];
      const hasOAuthApproval = completedStages.includes('org.matrix.cross_signing_reset') ||
                              completedStages.includes('m.oauth') ||
                              completedStages.includes('m.login.oauth') ||
                              completedStages.includes('m.login.sso') ||
                              completedStages.includes('m.login.token');
      
      if (!hasOAuthApproval) {
        console.log('[keys] Cross-signing reset not approved for this session');
        return c.json({
          errcode: 'M_UNAUTHORIZED',
          error: 'Cross-signing reset not approved. Please approve the request at the provided URL.',
        }, 401);
      }

      console.log('[keys] Cross-signing reset approved via OAuth flow');
      
      // Clean up the session
      await c.env.CACHE.delete(`uia_session:${sessionId}`);
    } else {
      // Unknown auth type
      console.log('[keys] Unknown auth type:', auth.type);
      return c.json({
        errcode: 'M_UNRECOGNIZED',
        error: `Unrecognized auth type: ${auth.type}`,
      }, 400);
    }
  }

  // UIA passed - check if SSSS is set up (for logging purposes only)
  // We allow cross-signing key uploads even without SSSS, as Element X may set up
  // SSSS immediately after uploading cross-signing keys during the bootstrap flow.
  // The "confirm your identity" screen in Element X is EXPECTED for new users -
  // it prompts them to set up recovery/SSSS.
  const ssssDefault = await c.env.ACCOUNT_DATA.get(
    `global:${userId}:m.secret_storage.default_key`,
    'json'
  ) as { key?: string } | null;

  let hasValidSSS = !!(ssssDefault && ssssDefault.key);
  if (!hasValidSSS) {
    // Also check D1 as fallback
    const d1Ssss = await db.prepare(`
      SELECT content FROM account_data
      WHERE user_id = ? AND event_type = 'm.secret_storage.default_key' AND room_id = ''
    `).bind(userId).first<{ content: string }>();

    if (d1Ssss) {
      try {
        const parsed = JSON.parse(d1Ssss.content);
        hasValidSSS = !!parsed.key;
      } catch {
        hasValidSSS = false;
      }
    }
  }

  if (!hasValidSSS) {
    // SSSS is not set up yet - this is OK, Element X will prompt user to set up recovery
    // Cross-signing keys can be uploaded before SSSS during initial bootstrap
    console.log('[keys] SSSS not configured for user', userId, '- allowing cross-signing upload (client will prompt for recovery setup)');
  } else {
    console.log('[keys] SSSS is configured, proceeding to store cross-signing keys');
  }

  // Get existing keys from Durable Object (strongly consistent)
  const existingCSKeys = await getCrossSigningKeysFromDO(c.env, userId);

  // Merge new keys with existing
  const csKeys = { ...existingCSKeys };
  if (master_key) csKeys.master = master_key;
  if (self_signing_key) csKeys.self_signing = self_signing_key;
  if (user_signing_key) csKeys.user_signing = user_signing_key;

  // Write to Durable Object (primary - strongly consistent)
  // This is critical for E2EE bootstrap where client uploads then immediately queries
  await putCrossSigningKeysToDO(c.env, userId, csKeys);
  console.log('[keys] Cross-signing keys stored in Durable Object for user:', userId);

  // Also write to D1 as backup (for durability/recovery)
  // These writes are eventually consistent but serve as backup storage
  if (master_key) {
    const keyId = Object.keys(master_key.keys || {})[0] || '';
    await db.prepare(`
      INSERT INTO cross_signing_keys (user_id, key_type, key_id, key_data)
      VALUES (?, 'master', ?, ?)
      ON CONFLICT (user_id, key_type) DO UPDATE SET
        key_id = excluded.key_id,
        key_data = excluded.key_data
    `).bind(userId, keyId, JSON.stringify(master_key)).run();
    await recordKeyChange(db, userId, null, 'update');
  }

  if (self_signing_key) {
    const keyId = Object.keys(self_signing_key.keys || {})[0] || '';
    await db.prepare(`
      INSERT INTO cross_signing_keys (user_id, key_type, key_id, key_data)
      VALUES (?, 'self_signing', ?, ?)
      ON CONFLICT (user_id, key_type) DO UPDATE SET
        key_id = excluded.key_id,
        key_data = excluded.key_data
    `).bind(userId, keyId, JSON.stringify(self_signing_key)).run();
  }

  if (user_signing_key) {
    const keyId = Object.keys(user_signing_key.keys || {})[0] || '';
    await db.prepare(`
      INSERT INTO cross_signing_keys (user_id, key_type, key_id, key_data)
      VALUES (?, 'user_signing', ?, ?)
      ON CONFLICT (user_id, key_type) DO UPDATE SET
        key_id = excluded.key_id,
        key_data = excluded.key_data
    `).bind(userId, keyId, JSON.stringify(user_signing_key)).run();
  }

  // Write to KV as cache (eventually consistent, for performance)
  await c.env.CROSS_SIGNING_KEYS.put(`user:${userId}`, JSON.stringify(csKeys));

  return c.json({});
});

// POST /_matrix/client/v3/keys/signatures/upload - Upload signatures for keys
// Spec: https://spec.matrix.org/v1.12/client-server-api/#post_matrixclientv3keyssignaturesupload
// Body format: { user_id: { key_id: signed_key_object } }
// - For device keys, key_id is the device_id (e.g., "JLAFKJWSCS")
// - For cross-signing keys, key_id is the base64 public key
app.post('/_matrix/client/v3/keys/signatures/upload', requireAuth(), async (c) => {
  const signerUserId = c.get('userId');
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  console.log('[signatures/upload] Request from:', signerUserId);
  console.log('[signatures/upload] Body:', JSON.stringify(body));

  // body is a map of user_id -> key_id -> signed_key_object
  const failures: Record<string, Record<string, { errcode: string; error: string }>> = {};

  for (const [userId, keys] of Object.entries(body)) {
    for (const [keyId, signedKey] of Object.entries(keys as Record<string, any>)) {
      try {
        const signedKeyObj = signedKey as any;

        // Extract signatures from the signed key object
        const signatures = signedKeyObj.signatures?.[signerUserId] || {};

        console.log('[signatures/upload] Processing:', { userId, keyId, hasDeviceId: !!signedKeyObj.device_id });
        console.log('[signatures/upload] Signatures to store:', JSON.stringify(signatures));

        // Store all signatures in the database
        for (const [signerKeyId, signature] of Object.entries(signatures)) {
          // Use the device_id as key_id for device keys, otherwise use the provided keyId
          const effectiveKeyId = signedKeyObj.device_id || keyId;

          await db.prepare(`
            INSERT INTO cross_signing_signatures (
              user_id, key_id, signer_user_id, signer_key_id, signature
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (user_id, key_id, signer_user_id, signer_key_id) DO UPDATE SET
              signature = excluded.signature
          `).bind(userId, effectiveKeyId, signerUserId, signerKeyId, signature as string).run();

          console.log('[signatures/upload] Stored signature:', {
            userId,
            effectiveKeyId,
            signerUserId,
            signerKeyId
          });
        }

        // If this is a device key (has device_id field), update the device key in KV
        if (signedKeyObj.device_id) {
          const deviceId = signedKeyObj.device_id;
          console.log('[signatures/upload] Updating device key for device:', deviceId);

          // Read from Durable Object (strongly consistent)
          const existingKey = await getDeviceKeysFromDO(c.env, userId, deviceId);

          if (existingKey) {
            // Merge new signatures into existing signatures
            existingKey.signatures = existingKey.signatures || {};
            existingKey.signatures[signerUserId] = {
              ...existingKey.signatures[signerUserId],
              ...signatures,
            };

            // Write to Durable Object (primary - strongly consistent)
            await putDeviceKeysToDO(c.env, userId, deviceId, existingKey);

            // Also update KV as backup/cache
            await c.env.DEVICE_KEYS.put(
              `device:${userId}:${deviceId}`,
              JSON.stringify(existingKey)
            );

            console.log('[signatures/upload] Updated device key signatures:', {
              deviceId,
              newSignatures: Object.keys(signatures)
            });
          } else {
            console.log('[signatures/upload] Device key not found:', deviceId);
          }
        }

        // Record key change for sync notifications
        await recordKeyChange(db, userId, signedKeyObj.device_id || null, 'update');
      } catch (err) {
        console.error('[signatures/upload] Error processing signature:', err);
        if (!failures[userId]) failures[userId] = {};
        failures[userId][keyId] = {
          errcode: 'M_UNKNOWN',
          error: 'Failed to store signature',
        };
      }
    }
  }

  console.log('[signatures/upload] Completed, failures:', Object.keys(failures).length > 0 ? failures : 'none');
  return c.json({ failures });
});

// ============================================
// UIA SSO Flow Endpoints (for OIDC users)
// ============================================

// GET /_matrix/client/v3/auth/m.login.sso/redirect - Redirect to SSO for UIA
// This endpoint is used by clients to initiate SSO authentication during UIA
// Spec: https://spec.matrix.org/v1.12/client-server-api/#get_matrixclientv3authmlloginssofallbackweb
app.get('/_matrix/client/v3/auth/m.login.sso/redirect', async (c) => {
  const sessionId = c.req.query('session');
  const redirectUrl = c.req.query('redirectUrl');

  if (!sessionId) {
    return c.json({
      errcode: 'M_MISSING_PARAM',
      error: 'Missing session parameter',
    }, 400);
  }

  // Verify the UIA session exists
  const sessionJson = await c.env.CACHE.get(`uia_session:${sessionId}`);
  if (!sessionJson) {
    return c.json({
      errcode: 'M_UNKNOWN',
      error: 'UIA session not found or expired',
    }, 404);
  }

  const session = JSON.parse(sessionJson);
  const serverName = c.env.SERVER_NAME;
  const baseUrl = `https://${serverName}`;

  // Store the redirect URL for after SSO completes
  session.redirect_url = redirectUrl || `${baseUrl}/_matrix/client/v3/auth/m.login.sso/callback`;
  await c.env.CACHE.put(`uia_session:${sessionId}`, JSON.stringify(session), { expirationTtl: 300 });

  // Redirect to OAuth authorize endpoint for re-authentication
  // The user must authenticate with their IdP to complete the UIA flow
  const authorizeUrl = new URL(`${baseUrl}/oauth/authorize`);
  authorizeUrl.searchParams.set('response_type', 'code');
  authorizeUrl.searchParams.set('client_id', 'matrix-uia');
  authorizeUrl.searchParams.set('redirect_uri', `${baseUrl}/_matrix/client/v3/auth/m.login.sso/callback`);
  authorizeUrl.searchParams.set('scope', 'openid');
  authorizeUrl.searchParams.set('state', sessionId);

  console.log('[keys/sso] Redirecting to SSO for UIA session:', sessionId);
  return c.redirect(authorizeUrl.toString());
});

// GET /_matrix/client/v3/auth/m.login.sso/callback - SSO callback for UIA
// This endpoint handles the return from SSO authentication
app.get('/_matrix/client/v3/auth/m.login.sso/callback', async (c) => {
  const code = c.req.query('code');
  const state = c.req.query('state'); // This is the UIA session ID
  const error = c.req.query('error');
  const errorDescription = c.req.query('error_description');

  if (error) {
    console.log('[keys/sso] SSO error:', error, errorDescription);
    return c.html(generateSSOErrorPage('SSO Authentication Failed', errorDescription || error));
  }

  if (!state) {
    return c.html(generateSSOErrorPage('Invalid Request', 'Missing state parameter'));
  }

  // Retrieve the UIA session
  const sessionJson = await c.env.CACHE.get(`uia_session:${state}`);
  if (!sessionJson) {
    return c.html(generateSSOErrorPage('Session Expired', 'The UIA session has expired. Please try again.'));
  }

  const session = JSON.parse(sessionJson);

  // If code is present, SSO was successful
  // For UIA purposes, we just need to verify the user authenticated - we don't need the token
  if (code) {
    // Mark SSO as completed in the session
    session.completed_stages = session.completed_stages || [];
    if (!session.completed_stages.includes('m.login.sso')) {
      session.completed_stages.push('m.login.sso');
    }
    session.sso_completed_at = Date.now();

    // Save updated session
    await c.env.CACHE.put(`uia_session:${state}`, JSON.stringify(session), { expirationTtl: 300 });

    console.log('[keys/sso] SSO completed for UIA session:', state);

    // Return success page that tells the client to retry the original request
    return c.html(generateSSOSuccessPage(state, session.redirect_url));
  }

  return c.html(generateSSOErrorPage('Authentication Failed', 'No authorization code received'));
});

// POST /_matrix/client/v3/auth/m.login.token/submit - Submit token for UIA
// Alternative flow for OIDC users who have a valid token
app.post('/_matrix/client/v3/auth/m.login.token/submit', requireAuth(), async (c) => {
  const userId = c.get('userId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { session } = body;

  if (!session) {
    return Errors.missingParam('session').toResponse();
  }

  // Retrieve the UIA session
  const sessionJson = await c.env.CACHE.get(`uia_session:${session}`);
  if (!sessionJson) {
    return c.json({
      errcode: 'M_UNKNOWN',
      error: 'UIA session not found or expired',
    }, 404);
  }

  const sessionData = JSON.parse(sessionJson);

  // Verify the session belongs to this user
  if (sessionData.user_id !== userId) {
    return Errors.forbidden('Session user mismatch').toResponse();
  }

  // The user is already authenticated with a valid access token
  // This is sufficient for token-based UIA completion
  sessionData.completed_stages = sessionData.completed_stages || [];
  if (!sessionData.completed_stages.includes('m.login.token')) {
    sessionData.completed_stages.push('m.login.token');
  }
  sessionData.token_completed_at = Date.now();

  // Save updated session
  await c.env.CACHE.put(`uia_session:${session}`, JSON.stringify(sessionData), { expirationTtl: 300 });

  console.log('[keys/token] Token UIA completed for session:', session);

  return c.json({
    completed: ['m.login.token'],
    session,
  });
});

// Helper: Generate SSO error page
function generateSSOErrorPage(title: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .container { background: #1e293b; padding: 40px; border-radius: 12px; max-width: 400px; text-align: center; border: 1px solid #334155; }
    h1 { color: #ef4444; margin-bottom: 16px; }
    p { color: #94a3b8; margin-bottom: 24px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${title}</h1>
    <p>${message}</p>
    <p>You can close this window and try again.</p>
  </div>
</body>
</html>`;
}

// Helper: Generate SSO success page
function generateSSOSuccessPage(sessionId: string, _redirectUrl?: string): string {
  // Note: _redirectUrl is reserved for future use when we support custom redirects
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authentication Successful</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .container { background: #1e293b; padding: 40px; border-radius: 12px; max-width: 400px; text-align: center; border: 1px solid #334155; }
    h1 { color: #22c55e; margin-bottom: 16px; }
    p { color: #94a3b8; margin-bottom: 24px; }
    .session { font-family: monospace; background: #0f172a; padding: 8px 16px; border-radius: 8px; font-size: 12px; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Authentication Successful</h1>
    <p>Your identity has been verified.</p>
    <p>You can now return to your Matrix client and complete the operation.</p>
    <p class="session">Session: ${sessionId}</p>
    <script>
      // Try to notify the parent window/opener if this was opened as a popup
      if (window.opener) {
        window.opener.postMessage({ type: 'uia_complete', session: '${sessionId}' }, '*');
        setTimeout(() => window.close(), 2000);
      }
    </script>
  </div>
</body>
</html>`;
}

export default app;
