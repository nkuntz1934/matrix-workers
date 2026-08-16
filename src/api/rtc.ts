// MatrixRTC API endpoints (MSC4143/MSC4195)
// Provides LiveKit JWT tokens for Element X calls
// Also implements MSC4143 RTC transports discovery

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { generateLiveKitToken, getLiveKitConfig } from '../services/livekit';
import { requireAuth } from '../middleware/auth';

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

// OpenID token structure from Matrix client
interface OpenIDToken {
  access_token: string;
  token_type: string;
  matrix_server_name: string;
  expires_in: number;
}

// Member info from request
interface MemberInfo {
  id: string;
  claimed_user_id: string;
  claimed_device_id: string;
}

// Request body for /get_token
// Note: Element X sends 'room' not 'room_id', and 'device_id' not 'member'
interface GetTokenRequest {
  room_id?: string;  // Old format
  room?: string;     // Element X format
  slot_id?: string;
  openid_token: OpenIDToken;
  member?: MemberInfo;  // Old format
  device_id?: string;   // Element X format - device ID string
  delayed_event_id?: string;
}

// Response for /get_token
interface GetTokenResponse {
  url: string;
  jwt: string;
}

// Verify OpenID token with the homeserver
async function verifyOpenIDToken(
  token: OpenIDToken,
  serverName: string,
  sessionsKv: KVNamespace
): Promise<{ sub: string } | null> {
  try {
    if (token.matrix_server_name !== serverName) {
      console.warn('[rtc] Rejecting OpenID token from different server:', token.matrix_server_name);
      return null;
    }

    // Verify the OpenID token against our local session store
    const tokenData = await sessionsKv.get(`openid:${token.access_token}`);
    if (tokenData) {
      const parsed = JSON.parse(tokenData);
      return { sub: parsed.user_id || parsed.sub };
    }

    // Token not found in our store — reject
    console.warn('[rtc] OpenID token not found in session store');
    return null;
  } catch (error) {
    console.error('[rtc] Error verifying OpenID token:', error);
    return null;
  }
}

// Convert Matrix room ID to a valid LiveKit room name
function roomIdToLiveKitName(roomId: string): string {
  // LiveKit room names can only contain alphanumeric, dash, underscore
  // Matrix room IDs look like: !roomid:server.name
  return roomId.replace(/[^a-zA-Z0-9-_]/g, '_');
}

// POST /livekit/get_token - Get a LiveKit JWT token
// This is the endpoint that Element X calls to get call credentials
app.post('/livekit/get_token', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const config = getLiveKitConfig(c.env);
  if (!config) {
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'LiveKit not configured' },
      500
    );
  }

  let body: GetTokenRequest;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Invalid JSON body' },
      400
    );
  }

  // Handle both old format (room_id, member) and Element X format (room, device_id)
  const roomId = body.room_id || body.room;

  // Validate required fields
  if (!roomId) {
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Missing required field: room' },
      400
    );
  }

  // Verify the OpenID token if provided (additional verification layer)
  if (body.openid_token) {
    const verified = await verifyOpenIDToken(body.openid_token, c.env.SERVER_NAME, c.env.SESSIONS);
    if (!verified) {
      console.warn(`[rtc] OpenID token verification failed for ${userId}`);
    }
  }

  // Use the authenticated user's identity — never trust client-supplied identity
  const participantId = userId;
  const participantName = userId.split(':')[0].replace('@', '');
  void (body.device_id || c.get('deviceId')); // deviceId available for future per-device tracking

  // Convert Matrix room ID to LiveKit room name
  const liveKitRoom = roomIdToLiveKitName(roomId);

  try {
    // Generate JWT token for this participant
    const jwt = await generateLiveKitToken(
      config.apiKey,
      config.apiSecret,
      liveKitRoom,
      participantId,
      participantName,
      3600 // 1 hour TTL
    );

    const response: GetTokenResponse = {
      url: config.wsUrl,
      jwt: jwt,
    };

    return c.json(response);
  } catch (error) {
    console.error('Error generating LiveKit token:', error);
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'Failed to generate token' },
      500
    );
  }
});

// OPTIONS handler for CORS preflight
app.options('/livekit/get_token', () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
});

// POST /livekit/get_token/sfu/get - Alternative endpoint format used by Element X
// This is the same as /livekit/get_token but with /sfu/get suffix
app.post('/livekit/get_token/sfu/get', requireAuth(), async (c) => {
  const userId = c.get('userId');

  const config = getLiveKitConfig(c.env);
  if (!config) {
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'LiveKit not configured' },
      500
    );
  }

  let body: GetTokenRequest;
  try {
    body = await c.req.json();
  } catch {
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Invalid JSON body' },
      400
    );
  }

  // Handle both old format (room_id, member) and Element X format (room, device_id)
  const roomId = body.room_id || body.room;

  // Validate required fields
  if (!roomId) {
    return c.json(
      { errcode: 'M_BAD_JSON', error: 'Missing required field: room' },
      400
    );
  }

  // Verify the OpenID token if provided (additional verification layer)
  if (body.openid_token) {
    const verified = await verifyOpenIDToken(body.openid_token, c.env.SERVER_NAME, c.env.SESSIONS);
    if (!verified) {
      console.warn(`[rtc] OpenID token verification failed for ${userId}`);
    }
  }

  // Use the authenticated user's identity — never trust client-supplied identity
  const participantId = userId;
  const participantName = userId.split(':')[0].replace('@', '');
  void (body.device_id || c.get('deviceId')); // deviceId available for future per-device tracking

  // Convert Matrix room ID to LiveKit room name
  const liveKitRoom = roomIdToLiveKitName(roomId);

  try {
    // Generate JWT token for this participant
    const jwt = await generateLiveKitToken(
      config.apiKey,
      config.apiSecret,
      liveKitRoom,
      participantId,
      participantName,
      3600 // 1 hour TTL
    );

    const response: GetTokenResponse = {
      url: config.wsUrl,
      jwt: jwt,
    };

    return c.json(response);
  } catch (error) {
    console.error('Error generating LiveKit token:', error);
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'Failed to generate token' },
      500
    );
  }
});

// OPTIONS handler for /sfu/get endpoint
app.options('/livekit/get_token/sfu/get', () => {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
});

// Return 405 Method Not Allowed for non-POST/OPTIONS methods
// Element X checks endpoint availability with GET and expects 405 (not 404)
app.all('/livekit/get_token', (c) => {
  return c.text('Method Not Allowed', 405, {
    Allow: 'POST, OPTIONS',
  });
});

app.all('/livekit/get_token/sfu/get', (c) => {
  return c.text('Method Not Allowed', 405, {
    Allow: 'POST, OPTIONS',
  });
});

export default app;
