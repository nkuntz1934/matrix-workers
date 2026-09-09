// MatrixRTC API endpoints (MSC4143/MSC4195)
// Provides LiveKit JWT tokens for Element X calls
// Also implements MSC4143 RTC transports discovery

import { Hono, type Context } from 'hono';
import type { AppEnv } from '../types';
import { generateLiveKitToken, getLiveKitConfig } from '../services/livekit';
import { getOpenIDIdentity } from '../services/openid';
import { getMembership } from '../services/database';

const app = new Hono<AppEnv>();

// GET /_matrix/client/unstable/org.matrix.msc4143/rtc/transports
// MSC4143: RTC transports discovery - tells clients what real-time communication methods are available
// Returns empty list to indicate standard WebRTC/TURN should be used (no special transports)
app.get('/_matrix/client/unstable/org.matrix.msc4143/rtc/transports', (c) => {
  const config = getLiveKitConfig(c.env);
  
  // If LiveKit is configured, advertise it as a transport option
  if (config) {
    return c.json({
      transports: [
        {
          type: 'livekit',
          url: `https://${c.env.SERVER_NAME}/livekit/get_token`,
        },
      ],
    });
  }

  // No special transports - clients will use standard WebRTC
  return c.json({
    transports: [],
  });
});

// Both the legacy /sfu/get and the newer member-based request authenticate via
// the OpenID token in the body. Requiring a Matrix Bearer header breaks widgets.
function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

// MatrixRTC / lk-jwt-service hashes JSON arrays using standard unpadded base64.
async function rtcIdentifier(parts: string[]): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(parts));
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return btoa(String.fromCharCode(...new Uint8Array(hash))).replace(/=+$/, '');
}

async function getToken(c: Context<AppEnv>) {
  const config = getLiveKitConfig(c.env);
  if (!config) {
    return c.json({ errcode: 'M_UNKNOWN', error: 'LiveKit not configured' }, 503);
  }

  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ errcode: 'M_BAD_JSON', error: 'Invalid JSON body' }, 400);
  }
  if (!isObject(body)) {
    return c.json({ errcode: 'M_BAD_JSON', error: 'Expected a JSON object' }, 400);
  }

  const roomId = body.room_id ?? body.room;
  const token = body.openid_token;
  if (!nonEmptyString(roomId) || !roomId.startsWith('!') ||
      !isObject(token) || !nonEmptyString(token.access_token) ||
      !nonEmptyString(token.matrix_server_name)) {
    return c.json({ errcode: 'M_BAD_JSON', error: 'Missing or invalid room and openid_token' }, 400);
  }

  // This integrated service currently supports local users only. Never fetch a
  // client-supplied server URL or fall back to accepting an unverified identity.
  if (token.matrix_server_name !== c.env.SERVER_NAME) {
    return c.json({ errcode: 'M_UNKNOWN_TOKEN', error: 'Invalid or expired OpenID token' }, 401);
  }
  const identity = await getOpenIDIdentity(c.env, token.access_token);
  if (!identity) {
    return c.json({ errcode: 'M_UNKNOWN_TOKEN', error: 'Invalid or expired OpenID token' }, 401);
  }

  let deviceId: string;
  let memberId: string | undefined;
  let slotId = 'm.call#ROOM';
  if (body.member !== undefined) {
    if (!isObject(body.member) || !nonEmptyString(body.member.claimed_device_id) ||
        !nonEmptyString(body.member.id) || !nonEmptyString(body.slot_id)) {
      return c.json({ errcode: 'M_BAD_JSON', error: 'Missing or invalid member and slot_id' }, 400);
    }
    if (body.member.claimed_user_id !== identity.user_id) {
      return c.json({ errcode: 'M_FORBIDDEN', error: 'Member identity does not match OpenID token' }, 403);
    }
    deviceId = body.member.claimed_device_id;
    memberId = body.member.id;
    slotId = body.slot_id;
  } else {
    if (!nonEmptyString(body.device_id)) {
      return c.json({ errcode: 'M_BAD_JSON', error: 'Missing device_id' }, 400);
    }
    deviceId = body.device_id;
  }

  if (identity.device_id != null && identity.device_id !== deviceId) {
    return c.json({ errcode: 'M_FORBIDDEN', error: 'Device does not match OpenID token' }, 403);
  }
  const device = await c.env.DB.prepare(`
    SELECT d.device_id FROM devices d JOIN users u ON u.user_id = d.user_id
    WHERE d.user_id = ? AND d.device_id = ? AND u.is_deactivated = 0
  `).bind(identity.user_id, deviceId).first();
  const membership = await getMembership(c.env.DB, roomId, identity.user_id);
  if (!device || membership?.membership !== 'join') {
    return c.json({ errcode: 'M_FORBIDDEN', error: 'An active device and joined room membership are required' }, 403);
  }

  // Legacy Element Call matches SFU participants to call membership with this
  // exact user:device identity. A device ID alone cannot match its own member.
  const participantId = memberId === undefined
    ? `${identity.user_id}:${deviceId}`
    : await rtcIdentifier([identity.user_id, deviceId, memberId]);
  const liveKitRoom = await rtcIdentifier([roomId, slotId]);
  const jwt = await generateLiveKitToken(
    config.apiKey, config.apiSecret, liveKitRoom, participantId, identity.user_id,
    Math.min(3600, Math.max(1, Math.floor((identity.expires_at - Date.now()) / 1000))),
  );
  c.header('Cache-Control', 'no-store');
  return c.json({ url: config.wsUrl, jwt });
}

// Keep the existing service URL and both client request formats. Newer clients
// append /get_token to the advertised base, while legacy clients append /sfu/get.
for (const path of ['/livekit/get_token', '/livekit/get_token/sfu/get', '/livekit/get_token/get_token']) {
  app.post(path, getToken);
  app.options(path, () => new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  }));
  app.all(path, (c) => c.text('Method Not Allowed', 405, { Allow: 'POST, OPTIONS' }));
}

export default app;
