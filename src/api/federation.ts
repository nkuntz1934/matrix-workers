// Matrix Server-Server (Federation) API endpoints

import { Hono } from 'hono';
import type { AppEnv, PDU } from '../types';
import { Errors } from '../utils/errors';
import { generateSigningKeyPair, signJson } from '../utils/crypto';
import { verifyPduSignature } from '../services/federation-keys';
import {
  checkEventAuthorization,
  fetchRoomAuthState,
  buildAuthStateFromEvents,
  validateAuthChain,
  validateSendJoinAuthChain,
} from '../services/authorization';
import { validatePdu } from '../services/event-validation';

const app = new Hono<AppEnv>();

// Signature enforcement mode: 'log' (warn only) or 'enforce' (reject invalid)
type SignatureEnforcement = 'log' | 'enforce';

function getSignatureEnforcement(env: { SIGNATURE_ENFORCEMENT?: string }): SignatureEnforcement {
  const mode = env.SIGNATURE_ENFORCEMENT;
  if (mode === 'enforce') return 'enforce';
  return 'log'; // Default to log-only mode for gradual rollout
}

// GET /_matrix/key/v2/server - Get server signing keys
app.get('/_matrix/key/v2/server', async (c) => {
  const serverName = c.env.SERVER_NAME;

  // Get or create server signing keys
  let keys = await c.env.DB.prepare(
    `SELECT key_id, public_key, valid_from, valid_until FROM server_keys WHERE is_current = 1`
  ).all<{ key_id: string; public_key: string; valid_from: number; valid_until: number | null }>();

  if (keys.results.length === 0) {
    // Generate new signing key
    const keyPair = await generateSigningKeyPair();
    const validFrom = Date.now();
    const validUntil = validFrom + (365 * 24 * 60 * 60 * 1000); // 1 year

    await c.env.DB.prepare(
      `INSERT INTO server_keys (key_id, public_key, private_key, valid_from, valid_until, is_current)
       VALUES (?, ?, ?, ?, ?, 1)`
    ).bind(keyPair.keyId, keyPair.publicKey, keyPair.privateKey, validFrom, validUntil).run();

    keys = {
      results: [{
        key_id: keyPair.keyId,
        public_key: keyPair.publicKey,
        valid_from: validFrom,
        valid_until: validUntil,
      }],
      success: true,
      meta: { duration: 0, size_after: 0, rows_read: 0, rows_written: 0, last_row_id: 0, changed_db: false, changes: 0 },
    };
  }

  const verifyKeys: Record<string, { key: string }> = {};
  for (const key of keys.results) {
    verifyKeys[key.key_id] = { key: key.public_key };
  }

  const validUntilTs = keys.results[0]?.valid_until || (Date.now() + 365 * 24 * 60 * 60 * 1000);

  const response = {
    server_name: serverName,
    valid_until_ts: validUntilTs,
    verify_keys: verifyKeys,
    old_verify_keys: {},
  };

  // Sign the response
  const privateKey = await c.env.DB.prepare(
    `SELECT private_key, key_id FROM server_keys WHERE is_current = 1 LIMIT 1`
  ).first<{ private_key: string; key_id: string }>();

  if (privateKey) {
    const signed = await signJson(response, serverName, privateKey.key_id, privateKey.private_key);
    return c.json(signed);
  }

  return c.json(response);
});

// GET /_matrix/key/v2/server/:keyId - Get specific key
app.get('/_matrix/key/v2/server/:keyId', async (c) => {
  const keyId = c.req.param('keyId');
  const serverName = c.env.SERVER_NAME;

  const key = await c.env.DB.prepare(
    `SELECT key_id, public_key, valid_from, valid_until FROM server_keys WHERE key_id = ?`
  ).bind(keyId).first<{ key_id: string; public_key: string; valid_from: number; valid_until: number | null }>();

  if (!key) {
    return Errors.notFound('Key not found').toResponse();
  }

  const response = {
    server_name: serverName,
    valid_until_ts: key.valid_until || (Date.now() + 365 * 24 * 60 * 60 * 1000),
    verify_keys: {
      [key.key_id]: { key: key.public_key },
    },
    old_verify_keys: {},
  };

  return c.json(response);
});

// PUT /_matrix/federation/v1/send/:txnId - Receive events from remote server
app.put('/_matrix/federation/v1/send/:txnId', async (c) => {
  // Note: txnId could be used for deduplication in future
  void c.req.param('txnId');
  const origin = c.req.header('X-Matrix-Origin');

  if (!origin) {
    return Errors.missingParam('X-Matrix-Origin header').toResponse();
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { pdus, edus: _edus } = body;
  const pduResults: Record<string, any> = {};
  const enforcement = getSignatureEnforcement(c.env);

  // Process incoming PDUs
  for (const pdu of pdus || []) {
    try {
      // Determine origin server for this PDU
      // Use the 'origin' field if present, otherwise extract from sender
      const pduOrigin = pdu.origin || extractServerName(pdu.sender);

      if (!pduOrigin) {
        pduResults[pdu.event_id] = { error: 'Cannot determine origin server' };
        continue;
      }

      // Validate PDU structure and fields
      const validationResult = validatePdu(pdu);
      if (!validationResult.valid) {
        pduResults[pdu.event_id] = { error: validationResult.error };
        continue;
      }

      // Verify PDU signature
      const sigResult = await verifyPduSignature(c.env, pdu, pduOrigin);

      if (!sigResult.valid) {
        if (enforcement === 'enforce') {
          pduResults[pdu.event_id] = { error: sigResult.error || 'Invalid signature' };
          continue;
        } else {
          // Log-only mode: warn but continue processing
          console.warn(
            `[SIGNATURE] Invalid signature on PDU ${pdu.event_id} from ${pduOrigin}: ${sigResult.error}`
          );
        }
      }

      // Fetch auth events referenced by this PDU
      const authEvents = await fetchAuthEvents(c.env.DB, pdu.auth_events || []);

      // Validate auth chain completeness
      const chainResult = await validateAuthChain(c.env.DB, pdu, authEvents);
      if (!chainResult.authorized) {
        if (enforcement === 'enforce') {
          pduResults[pdu.event_id] = { error: chainResult.reason || 'Invalid auth chain' };
          continue;
        } else {
          console.warn(
            `[AUTH_CHAIN] Invalid auth chain for PDU ${pdu.event_id}: ${chainResult.reason}`
          );
        }
      }

      // Build auth state from auth events and check authorization
      const authState = buildAuthStateFromEvents(authEvents);
      const authResult = await checkEventAuthorization(pdu, authState);

      if (!authResult.authorized) {
        if (enforcement === 'enforce') {
          pduResults[pdu.event_id] = { error: authResult.reason || 'Not authorized' };
          continue;
        } else {
          console.warn(
            `[AUTHORIZATION] PDU ${pdu.event_id} not authorized: ${authResult.reason}`
          );
        }
      }

      // TODO: State resolution will be added in Phase 7
      pduResults[pdu.event_id] = {};
    } catch (e: any) {
      pduResults[pdu.event_id] = {
        error: e.message || 'Unknown error',
      };
    }
  }

  // Process EDUs (ephemeral data units like typing notifications)
  // These don't require responses

  return c.json({ pdus: pduResults });
});

/**
 * Extract server name from a Matrix user ID (@user:server.name)
 */
function extractServerName(userId: string): string | null {
  if (!userId || !userId.startsWith('@')) {
    return null;
  }
  const colonIndex = userId.indexOf(':');
  if (colonIndex === -1) {
    return null;
  }
  return userId.slice(colonIndex + 1);
}

/**
 * Fetch auth events from database by their event IDs
 */
async function fetchAuthEvents(db: D1Database, eventIds: string[]): Promise<PDU[]> {
  if (eventIds.length === 0) {
    return [];
  }

  const placeholders = eventIds.map(() => '?').join(', ');
  const result = await db
    .prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
              origin_server_ts, depth, auth_events, prev_events
       FROM events WHERE event_id IN (${placeholders})`
    )
    .bind(...eventIds)
    .all<{
      event_id: string;
      room_id: string;
      sender: string;
      event_type: string;
      state_key: string | null;
      content: string;
      origin_server_ts: number;
      depth: number;
      auth_events: string;
      prev_events: string;
    }>();

  return result.results.map((row) => ({
    event_id: row.event_id,
    room_id: row.room_id,
    sender: row.sender,
    type: row.event_type,
    state_key: row.state_key ?? undefined,
    content: JSON.parse(row.content),
    origin_server_ts: row.origin_server_ts,
    depth: row.depth,
    auth_events: JSON.parse(row.auth_events),
    prev_events: JSON.parse(row.prev_events),
  }));
}

// GET /_matrix/federation/v1/event/:eventId - Get a single event
app.get('/_matrix/federation/v1/event/:eventId', async (c) => {
  const eventId = c.req.param('eventId');

  const event = await c.env.DB.prepare(
    `SELECT event_id, room_id, sender, event_type, state_key, content,
     origin_server_ts, depth, auth_events, prev_events, hashes, signatures
     FROM events WHERE event_id = ?`
  ).bind(eventId).first<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    depth: number;
    auth_events: string;
    prev_events: string;
    hashes: string | null;
    signatures: string | null;
  }>();

  if (!event) {
    return Errors.notFound('Event not found').toResponse();
  }

  const pdu: PDU = {
    event_id: event.event_id,
    room_id: event.room_id,
    sender: event.sender,
    type: event.event_type,
    state_key: event.state_key ?? undefined,
    content: JSON.parse(event.content),
    origin_server_ts: event.origin_server_ts,
    depth: event.depth,
    auth_events: JSON.parse(event.auth_events),
    prev_events: JSON.parse(event.prev_events),
    hashes: event.hashes ? JSON.parse(event.hashes) : undefined,
    signatures: event.signatures ? JSON.parse(event.signatures) : undefined,
  };

  return c.json({
    origin: c.env.SERVER_NAME,
    origin_server_ts: Date.now(),
    pdus: [pdu],
  });
});

// GET /_matrix/federation/v1/state/:roomId - Get room state
app.get('/_matrix/federation/v1/state/:roomId', async (c) => {
  const roomId = c.req.param('roomId');
  // Note: eventId could be used to get state at a specific point in time
  void c.req.query('event_id');

  // Get current room state
  const stateEvents = await c.env.DB.prepare(
    `SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content,
     e.origin_server_ts, e.depth, e.auth_events, e.prev_events
     FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ?`
  ).bind(roomId).all<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    depth: number;
    auth_events: string;
    prev_events: string;
  }>();

  const pdus = stateEvents.results.map(e => ({
    event_id: e.event_id,
    room_id: e.room_id,
    sender: e.sender,
    type: e.event_type,
    state_key: e.state_key ?? '',
    content: JSON.parse(e.content),
    origin_server_ts: e.origin_server_ts,
    depth: e.depth,
    auth_events: JSON.parse(e.auth_events),
    prev_events: JSON.parse(e.prev_events),
  }));

  // Get auth chain
  const authEventIds = new Set<string>();
  for (const pdu of pdus) {
    for (const authId of pdu.auth_events) {
      authEventIds.add(authId);
    }
  }

  const authChain: any[] = [];
  for (const authId of authEventIds) {
    const authEvent = await c.env.DB.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, depth, auth_events, prev_events
       FROM events WHERE event_id = ?`
    ).bind(authId).first();

    if (authEvent) {
      authChain.push({
        ...authEvent,
        type: (authEvent as any).event_type,
        content: JSON.parse((authEvent as any).content),
        auth_events: JSON.parse((authEvent as any).auth_events),
        prev_events: JSON.parse((authEvent as any).prev_events),
      });
    }
  }

  return c.json({
    origin: c.env.SERVER_NAME,
    origin_server_ts: Date.now(),
    pdus,
    auth_chain: authChain,
  });
});

// POST /_matrix/federation/v1/make_join/:roomId/:userId - Prepare join request
app.get('/_matrix/federation/v1/make_join/:roomId/:userId', async (c) => {
  const roomId = c.req.param('roomId');
  const userId = c.req.param('userId');

  // Check if room exists and is joinable
  const room = await c.env.DB.prepare(
    `SELECT room_id, room_version FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string; room_version: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get current room state for auth events
  const createEvent = await c.env.DB.prepare(
    `SELECT e.event_id FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ? AND rs.event_type = 'm.room.create'`
  ).bind(roomId).first<{ event_id: string }>();

  const joinRulesEvent = await c.env.DB.prepare(
    `SELECT e.event_id FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'`
  ).bind(roomId).first<{ event_id: string }>();

  const powerLevelsEvent = await c.env.DB.prepare(
    `SELECT e.event_id FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ? AND rs.event_type = 'm.room.power_levels'`
  ).bind(roomId).first<{ event_id: string }>();

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (joinRulesEvent) authEvents.push(joinRulesEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);

  // Get latest event for prev_events
  const latestEvent = await c.env.DB.prepare(
    `SELECT event_id, depth FROM events WHERE room_id = ? ORDER BY depth DESC LIMIT 1`
  ).bind(roomId).first<{ event_id: string; depth: number }>();

  const prevEvents = latestEvent ? [latestEvent.event_id] : [];
  const depth = (latestEvent?.depth || 0) + 1;

  // Create unsigned join event template
  const eventTemplate = {
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: {
      membership: 'join',
    },
    origin_server_ts: Date.now(),
    depth,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  return c.json({
    room_version: room.room_version,
    event: eventTemplate,
  });
});

// PUT /_matrix/federation/v1/send_join/:roomId/:eventId - Complete join
app.put('/_matrix/federation/v1/send_join/:roomId/:eventId', async (c) => {
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');
  const enforcement = getSignatureEnforcement(c.env);

  let joinEvent: PDU;
  try {
    joinEvent = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate event ID matches
  if (joinEvent.event_id !== eventId) {
    return Errors.invalidParam('Event ID mismatch').toResponse();
  }

  // Validate room ID matches
  if (joinEvent.room_id !== roomId) {
    return Errors.invalidParam('Room ID mismatch').toResponse();
  }

  // Validate it's a join event
  if (joinEvent.type !== 'm.room.member') {
    return Errors.invalidParam('Expected m.room.member event').toResponse();
  }

  const content = joinEvent.content as { membership?: string };
  if (content.membership !== 'join') {
    return Errors.invalidParam('Expected join membership').toResponse();
  }

  // Verify signature from the joining server
  const joiningServer = extractServerName(joinEvent.sender);
  if (!joiningServer) {
    return Errors.invalidParam('Invalid sender').toResponse();
  }

  const sigResult = await verifyPduSignature(c.env, joinEvent as unknown as Record<string, unknown>, joiningServer);
  if (!sigResult.valid) {
    if (enforcement === 'enforce') {
      return Errors.unauthorized(sigResult.error || 'Invalid signature').toResponse();
    } else {
      console.warn(`[SEND_JOIN] Invalid signature from ${joiningServer}: ${sigResult.error}`);
    }
  }

  // Validate PDU structure
  const pduValidation = validatePdu(joinEvent as unknown as Record<string, unknown>);
  if (!pduValidation.valid) {
    return c.json(
      { errcode: pduValidation.errcode || 'M_BAD_JSON', error: pduValidation.error },
      400
    );
  }

  // Fetch current room auth state
  const authState = await fetchRoomAuthState(c.env.DB, roomId);

  if (!authState.createEvent) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Fetch auth events referenced by the join event for validation
  const joinAuthEvents = await fetchAuthEvents(c.env.DB, joinEvent.auth_events || []);

  // Validate auth chain (DAG structure, recursive authorization)
  const chainResult = await validateSendJoinAuthChain(joinEvent, authState, joinAuthEvents);
  if (!chainResult.authorized) {
    if (enforcement === 'enforce') {
      return Errors.forbidden(chainResult.reason || 'Invalid auth chain').toResponse();
    } else {
      console.warn(`[SEND_JOIN] Invalid auth chain: ${chainResult.reason}`);
    }
  }

  // Check authorization
  const authResult = await checkEventAuthorization(joinEvent, authState);
  if (!authResult.authorized) {
    if (enforcement === 'enforce') {
      return Errors.forbidden(authResult.reason || 'Join not authorized').toResponse();
    } else {
      console.warn(`[SEND_JOIN] Join not authorized: ${authResult.reason}`);
    }
  }

  // Get current state and auth chain
  const stateEvents = await c.env.DB.prepare(
    `SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content,
            e.origin_server_ts, e.depth, e.auth_events, e.prev_events, e.hashes, e.signatures
     FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ?`
  ).bind(roomId).all<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    depth: number;
    auth_events: string;
    prev_events: string;
    hashes: string | null;
    signatures: string | null;
  }>();

  // Build auth chain from state events' auth_events
  const authEventIds = new Set<string>();
  for (const e of stateEvents.results) {
    const authEvents = JSON.parse(e.auth_events) as string[];
    for (const id of authEvents) {
      authEventIds.add(id);
    }
  }

  const authChain = await fetchAuthEvents(c.env.DB, Array.from(authEventIds));

  return c.json({
    origin: c.env.SERVER_NAME,
    auth_chain: authChain.map((e) => ({
      ...e,
      signatures: e.signatures || {},
      hashes: e.hashes || {},
    })),
    state: stateEvents.results.map((e) => ({
      event_id: e.event_id,
      room_id: e.room_id,
      sender: e.sender,
      type: e.event_type,
      state_key: e.state_key ?? undefined,
      content: JSON.parse(e.content),
      origin_server_ts: e.origin_server_ts,
      depth: e.depth,
      auth_events: JSON.parse(e.auth_events),
      prev_events: JSON.parse(e.prev_events),
      hashes: e.hashes ? JSON.parse(e.hashes) : {},
      signatures: e.signatures ? JSON.parse(e.signatures) : {},
    })),
    event: joinEvent,
  });
});

// GET /_matrix/federation/v1/query/directory - Resolve room alias
app.get('/_matrix/federation/v1/query/directory', async (c) => {
  const alias = c.req.query('room_alias');

  if (!alias) {
    return Errors.missingParam('room_alias').toResponse();
  }

  const roomId = await c.env.DB.prepare(
    `SELECT room_id FROM room_aliases WHERE alias = ?`
  ).bind(alias).first<{ room_id: string }>();

  if (!roomId) {
    return Errors.notFound('Room alias not found').toResponse();
  }

  return c.json({
    room_id: roomId.room_id,
    servers: [c.env.SERVER_NAME],
  });
});

// GET /_matrix/federation/v1/query/profile - Query user profile
app.get('/_matrix/federation/v1/query/profile', async (c) => {
  const userId = c.req.query('user_id');
  const field = c.req.query('field');

  if (!userId) {
    return Errors.missingParam('user_id').toResponse();
  }

  const user = await c.env.DB.prepare(
    `SELECT display_name, avatar_url FROM users WHERE user_id = ?`
  ).bind(userId).first<{ display_name: string | null; avatar_url: string | null }>();

  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  if (field === 'displayname') {
    return c.json({ displayname: user.display_name });
  } else if (field === 'avatar_url') {
    return c.json({ avatar_url: user.avatar_url });
  }

  return c.json({
    displayname: user.display_name,
    avatar_url: user.avatar_url,
  });
});

export default app;
