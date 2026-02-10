// Matrix Server-Server (Federation) API endpoints

import { Hono } from 'hono';
import type { AppEnv, PDU } from '../types';
import { Errors } from '../utils/errors';
import { generateSigningKeyPair, signJson, sha256, verifySignature, verifyContentHash } from '../utils/crypto';
import { requireFederationAuth } from '../middleware/federation-auth';
import {
  getRemoteKeysWithNotarySignature,
  verifyRemoteSignature,
  type ServerKeyResponse,
} from '../services/federation-keys';
import { validateUrl } from '../utils/url-validator';
import { checkEventAuth } from '../services/event-auth';
import { getRoomState } from '../services/database';
import { resolveState } from '../services/state-resolution';

// Supported room versions (v1-v12 per Matrix Spec v1.17)
const SUPPORTED_ROOM_VERSIONS = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12'];

const app = new Hono<AppEnv>();

// GET /_matrix/federation/v1/version - Server version info (unauthenticated)
// This must be defined BEFORE the auth middleware is applied
app.get('/_matrix/federation/v1/version', async (c) => {
  return c.json({
    server: {
      name: 'matrix-worker',
      version: c.env.SERVER_VERSION || '0.1.0',
    },
  });
});

// Apply federation authentication to all other federation v1 endpoints
// Key endpoints (/_matrix/key/*) remain unauthenticated as they are used to establish trust
// Version endpoint is also unauthenticated as it's used for initial contact
app.use('/_matrix/federation/v1/*', requireFederationAuth());

// GET /_matrix/key/v2/server - Get server signing keys
app.get('/_matrix/key/v2/server', async (c) => {
  const serverName = c.env.SERVER_NAME;

  // Get or create server signing keys (prefer v2 keys with proper Ed25519)
  let keys = await c.env.DB.prepare(
    `SELECT key_id, public_key, private_key_jwk, key_version, valid_from, valid_until
     FROM server_keys WHERE is_current = 1 ORDER BY key_version DESC`
  ).all<{
    key_id: string;
    public_key: string;
    private_key_jwk: string | null;
    key_version: number | null;
    valid_from: number;
    valid_until: number | null;
  }>();

  // Check if we need to generate a new secure key
  const hasSecureKey = keys.results.some((k) => k.key_version === 2 && k.private_key_jwk);

  if (keys.results.length === 0 || !hasSecureKey) {
    // Generate new secure signing key with proper Ed25519
    const keyPair = await generateSigningKeyPair();
    const validFrom = Date.now();
    const validUntil = validFrom + 365 * 24 * 60 * 60 * 1000; // 1 year

    // Mark old keys as not current
    await c.env.DB.prepare(`UPDATE server_keys SET is_current = 0`).run();

    // Insert new secure key
    await c.env.DB.prepare(
      `INSERT INTO server_keys (key_id, public_key, private_key, private_key_jwk, key_version, valid_from, valid_until, is_current)
       VALUES (?, ?, ?, ?, 2, ?, ?, 1)`
    )
      .bind(
        keyPair.keyId,
        keyPair.publicKey,
        JSON.stringify(keyPair.privateKeyJwk), // Store JWK as string in legacy column too
        JSON.stringify(keyPair.privateKeyJwk),
        validFrom,
        validUntil
      )
      .run();

    keys = {
      results: [
        {
          key_id: keyPair.keyId,
          public_key: keyPair.publicKey,
          private_key_jwk: JSON.stringify(keyPair.privateKeyJwk),
          key_version: 2,
          valid_from: validFrom,
          valid_until: validUntil,
        },
      ],
      success: true,
      meta: {
        duration: 0,
        size_after: 0,
        rows_read: 0,
        rows_written: 0,
        last_row_id: 0,
        changed_db: false,
        changes: 0,
      },
    };
  }

  const verifyKeys: Record<string, { key: string }> = {};
  for (const key of keys.results) {
    verifyKeys[key.key_id] = { key: key.public_key };
  }

  const validUntilTs = keys.results[0]?.valid_until || Date.now() + 365 * 24 * 60 * 60 * 1000;

  const response = {
    server_name: serverName,
    valid_until_ts: validUntilTs,
    verify_keys: verifyKeys,
    old_verify_keys: {},
  };

  // Sign the response with the secure key
  const currentKey = keys.results.find((k) => k.key_version === 2 && k.private_key_jwk);
  if (currentKey && currentKey.private_key_jwk) {
    const signed = await signJson(
      response,
      serverName,
      currentKey.key_id,
      JSON.parse(currentKey.private_key_jwk)
    );
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

// Helper function to get our server's notary signing key
async function getNotarySigningKey(db: D1Database): Promise<{
  keyId: string;
  privateKeyJwk: JsonWebKey;
} | null> {
  const key = await db.prepare(
    `SELECT key_id, private_key_jwk FROM server_keys WHERE is_current = 1 AND key_version = 2`
  ).first<{ key_id: string; private_key_jwk: string | null }>();

  if (!key || !key.private_key_jwk) {
    return null;
  }

  return {
    keyId: key.key_id,
    privateKeyJwk: JSON.parse(key.private_key_jwk),
  };
}

// Helper function to validate server name
function isValidServerName(serverName: string): boolean {
  // Basic server name validation
  // Server names should be hostname:port or just hostname
  // Must not contain SSRF-vulnerable patterns

  // Check for empty or too long
  if (!serverName || serverName.length > 255) {
    return false;
  }

  // Check using URL validation (construct a fake URL to validate the hostname)
  const testUrl = `https://${serverName}/`;
  const validation = validateUrl(testUrl);

  return validation.valid;
}

// Maximum number of servers in a batch query
const MAX_BATCH_SERVERS = 100;

// POST /_matrix/key/v2/query - Batch query for server keys (notary endpoint)
app.post('/_matrix/key/v2/query', async (c) => {
  let body: {
    server_keys?: Record<string, Record<string, { minimum_valid_until_ts?: number }>>;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const serverKeys = body.server_keys;
  if (!serverKeys || typeof serverKeys !== 'object') {
    return Errors.missingParam('server_keys').toResponse();
  }

  // Check batch size limit
  const serverCount = Object.keys(serverKeys).length;
  if (serverCount > MAX_BATCH_SERVERS) {
    return c.json(
      {
        errcode: 'M_LIMIT_EXCEEDED',
        error: `Too many servers in batch request (max ${MAX_BATCH_SERVERS})`,
      },
      400
    );
  }

  // Get our notary signing key
  const notaryKey = await getNotarySigningKey(c.env.DB);
  if (!notaryKey) {
    return c.json(
      {
        errcode: 'M_UNKNOWN',
        error: 'Server signing key not configured',
      },
      500
    );
  }

  const results: ServerKeyResponse[] = [];

  // Process each server in the request
  for (const [serverName, keyRequests] of Object.entries(serverKeys)) {
    // Validate server name to prevent SSRF
    if (!isValidServerName(serverName)) {
      console.warn(`Invalid server name in key query: ${serverName}`);
      continue;
    }

    // If querying our own server, return our keys directly
    if (serverName === c.env.SERVER_NAME) {
      const ownKeys = await c.env.DB.prepare(
        `SELECT key_id, public_key, valid_until FROM server_keys WHERE is_current = 1`
      ).all<{ key_id: string; public_key: string; valid_until: number | null }>();

      if (ownKeys.results.length > 0) {
        const verifyKeys: Record<string, { key: string }> = {};
        let maxValidUntil = 0;

        for (const key of ownKeys.results) {
          verifyKeys[key.key_id] = { key: key.public_key };
          if (key.valid_until && key.valid_until > maxValidUntil) {
            maxValidUntil = key.valid_until;
          }
        }

        const ownResponse: ServerKeyResponse = {
          server_name: serverName,
          valid_until_ts: maxValidUntil || Date.now() + 365 * 24 * 60 * 60 * 1000,
          verify_keys: verifyKeys,
          old_verify_keys: {},
        };

        // Sign with our own key
        const signed = (await signJson(
          ownResponse,
          c.env.SERVER_NAME,
          notaryKey.keyId,
          notaryKey.privateKeyJwk
        )) as ServerKeyResponse;

        results.push(signed);
      }
      continue;
    }

    // Process each key request for this server
    for (const [keyId, keyRequest] of Object.entries(keyRequests)) {
      const minimumValidUntilTs = keyRequest.minimum_valid_until_ts || 0;

      // Fetch keys with notary signature
      const keyResponses = await getRemoteKeysWithNotarySignature(
        serverName,
        keyId === '' ? null : keyId, // Empty key ID means all keys
        minimumValidUntilTs,
        c.env.DB,
        c.env.CACHE,
        c.env.SERVER_NAME,
        notaryKey.keyId,
        notaryKey.privateKeyJwk
      );

      results.push(...keyResponses);
    }
  }

  return c.json({ server_keys: results });
});

// GET /_matrix/key/v2/query/:serverName - Query all keys for a server
app.get('/_matrix/key/v2/query/:serverName', async (c) => {
  const serverName = c.req.param('serverName');
  const minimumValidUntilTs = parseInt(c.req.query('minimum_valid_until_ts') || '0', 10);

  // Validate server name to prevent SSRF
  if (!isValidServerName(serverName)) {
    return c.json(
      {
        errcode: 'M_INVALID_PARAM',
        error: 'Invalid server name',
      },
      400
    );
  }

  // Get our notary signing key
  const notaryKey = await getNotarySigningKey(c.env.DB);
  if (!notaryKey) {
    return c.json(
      {
        errcode: 'M_UNKNOWN',
        error: 'Server signing key not configured',
      },
      500
    );
  }

  // If querying our own server, return our keys directly
  if (serverName === c.env.SERVER_NAME) {
    const ownKeys = await c.env.DB.prepare(
      `SELECT key_id, public_key, valid_until FROM server_keys WHERE is_current = 1`
    ).all<{ key_id: string; public_key: string; valid_until: number | null }>();

    if (ownKeys.results.length === 0) {
      return Errors.notFound('No keys found').toResponse();
    }

    const verifyKeys: Record<string, { key: string }> = {};
    let maxValidUntil = 0;

    for (const key of ownKeys.results) {
      verifyKeys[key.key_id] = { key: key.public_key };
      if (key.valid_until && key.valid_until > maxValidUntil) {
        maxValidUntil = key.valid_until;
      }
    }

    const ownResponse: ServerKeyResponse = {
      server_name: serverName,
      valid_until_ts: maxValidUntil || Date.now() + 365 * 24 * 60 * 60 * 1000,
      verify_keys: verifyKeys,
      old_verify_keys: {},
    };

    // Sign with our own key
    const signed = (await signJson(
      ownResponse,
      c.env.SERVER_NAME,
      notaryKey.keyId,
      notaryKey.privateKeyJwk
    )) as ServerKeyResponse;

    return c.json({ server_keys: [signed] });
  }

  // Fetch keys from remote server with notary signature
  const keyResponses = await getRemoteKeysWithNotarySignature(
    serverName,
    null, // All keys
    minimumValidUntilTs,
    c.env.DB,
    c.env.CACHE,
    c.env.SERVER_NAME,
    notaryKey.keyId,
    notaryKey.privateKeyJwk
  );

  if (keyResponses.length === 0) {
    return Errors.notFound('No keys found for server').toResponse();
  }

  return c.json({ server_keys: keyResponses });
});

// GET /_matrix/key/v2/query/:serverName/:keyId - Query specific key for a server
app.get('/_matrix/key/v2/query/:serverName/:keyId', async (c) => {
  const serverName = c.req.param('serverName');
  const keyId = c.req.param('keyId');
  const minimumValidUntilTs = parseInt(c.req.query('minimum_valid_until_ts') || '0', 10);

  // Validate server name to prevent SSRF
  if (!isValidServerName(serverName)) {
    return c.json(
      {
        errcode: 'M_INVALID_PARAM',
        error: 'Invalid server name',
      },
      400
    );
  }

  // Get our notary signing key
  const notaryKey = await getNotarySigningKey(c.env.DB);
  if (!notaryKey) {
    return c.json(
      {
        errcode: 'M_UNKNOWN',
        error: 'Server signing key not configured',
      },
      500
    );
  }

  // If querying our own server, return the specific key
  if (serverName === c.env.SERVER_NAME) {
    const ownKey = await c.env.DB.prepare(
      `SELECT key_id, public_key, valid_until FROM server_keys WHERE key_id = ?`
    ).bind(keyId).first<{ key_id: string; public_key: string; valid_until: number | null }>();

    if (!ownKey) {
      return Errors.notFound('Key not found').toResponse();
    }

    const ownResponse: ServerKeyResponse = {
      server_name: serverName,
      valid_until_ts: ownKey.valid_until || Date.now() + 365 * 24 * 60 * 60 * 1000,
      verify_keys: {
        [ownKey.key_id]: { key: ownKey.public_key },
      },
      old_verify_keys: {},
    };

    // Sign with our own key
    const signed = (await signJson(
      ownResponse,
      c.env.SERVER_NAME,
      notaryKey.keyId,
      notaryKey.privateKeyJwk
    )) as ServerKeyResponse;

    return c.json({ server_keys: [signed] });
  }

  // Fetch specific key from remote server with notary signature
  const keyResponses = await getRemoteKeysWithNotarySignature(
    serverName,
    keyId,
    minimumValidUntilTs,
    c.env.DB,
    c.env.CACHE,
    c.env.SERVER_NAME,
    notaryKey.keyId,
    notaryKey.privateKeyJwk
  );

  if (keyResponses.length === 0) {
    return Errors.notFound('Key not found').toResponse();
  }

  return c.json({ server_keys: keyResponses });
});

// PUT /_matrix/federation/v1/send/:txnId - Receive events from remote server
// This endpoint is now protected by requireFederationAuth middleware
app.put('/_matrix/federation/v1/send/:txnId', async (c) => {
  const txnId = c.req.param('txnId');

  // Origin is now authenticated via the federation auth middleware
  const origin = c.get('federationOrigin' as any) as string | undefined;
  if (!origin) {
    return Errors.unauthorized('Federation authentication required').toResponse();
  }

  // Check for duplicate transaction (idempotency)
  const existingTxn = await c.env.DB.prepare(
    `SELECT response FROM federation_transactions WHERE origin = ? AND txn_id = ?`
  ).bind(origin, txnId).first<{ response: string | null }>();

  if (existingTxn?.response) {
    // Return cached response for duplicate transaction
    return c.json(JSON.parse(existingTxn.response));
  }

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { pdus, edus } = body;
  const pduResults: Record<string, any> = {};

  // Process incoming PDUs (Persistent Data Units - events)
  for (const pdu of pdus || []) {
    try {
      const eventId = pdu.event_id;
      const roomId = pdu.room_id;

      // Check if we've already processed this PDU
      const existingPdu = await c.env.DB.prepare(
        `SELECT accepted, rejection_reason FROM processed_pdus WHERE event_id = ?`
      ).bind(eventId).first<{ accepted: number; rejection_reason: string | null }>();

      if (existingPdu) {
        // Already processed
        if (existingPdu.accepted) {
          pduResults[eventId] = {};
        } else {
          pduResults[eventId] = {
            error: existingPdu.rejection_reason || 'Previously rejected',
          };
        }
        continue;
      }

      // Validate basic PDU structure
      if (!eventId || !roomId || !pdu.sender || !pdu.type || !pdu.content) {
        pduResults[eventId || 'unknown'] = {
          error: 'Invalid PDU structure',
        };
        continue;
      }

      // Get the origin server from the sender
      const pduOrigin = (pdu.sender as string).split(':')[1];
      if (!pduOrigin) {
        pduResults[eventId] = { error: 'Invalid sender format' };
        continue;
      }

      // Verify PDU signatures
      if (pdu.signatures) {
        let signatureValid = false;
        const signatories = Object.keys(pdu.signatures);

        for (const signatory of signatories) {
          const keyIds = Object.keys(pdu.signatures[signatory]);
          for (const keyId of keyIds) {
            try {
              const isValid = await verifyRemoteSignature(
                pdu,
                signatory,
                keyId,
                c.env.DB,
                c.env.CACHE
              );
              if (isValid) {
                signatureValid = true;
                break;
              }
            } catch (e) {
              console.warn(`Signature verification failed for ${signatory}:${keyId}:`, e);
            }
          }
          if (signatureValid) break;
        }

        if (!signatureValid && pduOrigin !== origin) {
          // PDU from third party without valid signature
          pduResults[eventId] = { error: 'Invalid signature' };
          await c.env.DB.prepare(
            `INSERT OR REPLACE INTO processed_pdus (event_id, origin, room_id, processed_at, accepted, rejection_reason)
             VALUES (?, ?, ?, ?, 0, ?)`
          ).bind(eventId, pduOrigin, roomId, Date.now(), 'Invalid signature').run();
          continue;
        }
      }

      // Verify content hash if present
      if (pdu.hashes?.sha256) {
        try {
          const hashValid = await verifyContentHash(pdu as Record<string, unknown>, pdu.hashes.sha256);
          if (!hashValid) {
            pduResults[eventId] = { error: 'Content hash mismatch' };
            await c.env.DB.prepare(
              `INSERT OR REPLACE INTO processed_pdus (event_id, origin, room_id, processed_at, accepted, rejection_reason)
               VALUES (?, ?, ?, ?, 0, ?)`
            ).bind(eventId, pduOrigin, roomId, Date.now(), 'Content hash mismatch').run();
            continue;
          }
        } catch (hashErr) {
          console.warn(`[federation] Content hash check failed for ${eventId}:`, hashErr);
        }
      }

      // Check if the room exists locally
      const room = await c.env.DB.prepare(
        `SELECT room_id, room_version FROM rooms WHERE room_id = ?`
      ).bind(roomId).first<{ room_id: string; room_version: string }>();

      // Run event authorization check if we have room state
      if (room) {
        try {
          const roomState = await getRoomState(c.env.DB, roomId);
          const authResult = checkEventAuth(pdu as PDU, roomState, room.room_version);
          if (!authResult.allowed) {
            pduResults[eventId] = { error: authResult.error || 'Event authorization failed' };
            await c.env.DB.prepare(
              `INSERT OR REPLACE INTO processed_pdus (event_id, origin, room_id, processed_at, accepted, rejection_reason)
               VALUES (?, ?, ?, ?, 0, ?)`
            ).bind(eventId, pduOrigin, roomId, Date.now(), authResult.error || 'Auth failed').run();
            continue;
          }
        } catch (authErr) {
          console.warn(`[federation] Auth check failed for ${eventId}, accepting anyway:`, authErr);
        }
      }

      // Accept the PDU
      pduResults[eventId] = {};

      // Record that we processed this PDU
      await c.env.DB.prepare(
        `INSERT OR REPLACE INTO processed_pdus (event_id, origin, room_id, processed_at, accepted, rejection_reason)
         VALUES (?, ?, ?, ?, 1, NULL)`
      ).bind(eventId, pduOrigin, roomId, Date.now()).run();

      // If room exists, store the event
      if (room) {
        try {
          await c.env.DB.prepare(
            `INSERT OR IGNORE INTO events
             (event_id, room_id, sender, event_type, state_key, content, origin_server_ts, depth, auth_events, prev_events, hashes, signatures)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
          ).bind(
            eventId,
            roomId,
            pdu.sender,
            pdu.type,
            pdu.state_key ?? null,
            JSON.stringify(pdu.content),
            pdu.origin_server_ts,
            pdu.depth || 0,
            JSON.stringify(pdu.auth_events || []),
            JSON.stringify(pdu.prev_events || []),
            pdu.hashes ? JSON.stringify(pdu.hashes) : null,
            pdu.signatures ? JSON.stringify(pdu.signatures) : null
          ).run();

          // Update room state
          if (pdu.state_key !== undefined) {
            // If the PDU has multiple prev_events, we may need state resolution
            const prevEvents = pdu.prev_events || [];
            if (prevEvents.length > 1 && room) {
              try {
                // Fetch current room state and resolve with new event
                const currentState = await getRoomState(c.env.DB, roomId);
                const newEvent: PDU = {
                  event_id: eventId,
                  room_id: roomId,
                  sender: pdu.sender,
                  type: pdu.type,
                  state_key: pdu.state_key,
                  content: pdu.content,
                  origin_server_ts: pdu.origin_server_ts,
                  depth: pdu.depth || 0,
                  auth_events: pdu.auth_events || [],
                  prev_events: prevEvents,
                };
                const resolved = resolveState(room.room_version, [currentState, [newEvent]]);
                // Apply resolved state
                for (const stateEvent of resolved) {
                  if (stateEvent.state_key !== undefined) {
                    await c.env.DB.prepare(
                      `INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
                       VALUES (?, ?, ?, ?)`
                    ).bind(roomId, stateEvent.type, stateEvent.state_key, stateEvent.event_id).run();
                  }
                }
              } catch (resolveErr) {
                console.warn(`[federation] State resolution failed for ${eventId}, falling back:`, resolveErr);
                await c.env.DB.prepare(
                  `INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
                   VALUES (?, ?, ?, ?)`
                ).bind(roomId, pdu.type, pdu.state_key, eventId).run();
              }
            } else {
              await c.env.DB.prepare(
                `INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
                 VALUES (?, ?, ?, ?)`
              ).bind(roomId, pdu.type, pdu.state_key, eventId).run();
            }
          }
        } catch (e) {
          console.error(`Failed to store event ${eventId}:`, e);
        }
      }
    } catch (e: any) {
      const eventId = pdu?.event_id || 'unknown';
      pduResults[eventId] = {
        error: e.message || 'Unknown error',
      };

      // Record rejection
      if (pdu?.event_id && pdu?.room_id) {
        const pduOrigin = (pdu.sender as string)?.split(':')[1] || origin;
        await c.env.DB.prepare(
          `INSERT OR REPLACE INTO processed_pdus (event_id, origin, room_id, processed_at, accepted, rejection_reason)
           VALUES (?, ?, ?, ?, 0, ?)`
        ).bind(pdu.event_id, pduOrigin, pdu.room_id, Date.now(), e.message || 'Unknown error').run();
      }
    }
  }

  // Process EDUs (Ephemeral Data Units)
  for (const edu of edus || []) {
    try {
      const eduType = edu.edu_type;
      const content = edu.content;

      switch (eduType) {
        case 'm.typing':
          // Handle typing notification
          // In a full implementation, this would notify connected clients
          break;

        case 'm.presence': {
          // Process inbound presence EDUs from federated servers
          const presencePush = content?.push as Array<{
            user_id: string;
            presence: string;
            status_msg?: string;
            last_active_ago?: number;
            currently_active?: boolean;
          }> | undefined;
          if (presencePush) {
            for (const update of presencePush) {
              if (update.user_id && update.presence) {
                const now = Date.now();
                const lastActive = update.last_active_ago
                  ? now - update.last_active_ago
                  : now;
                try {
                  await c.env.DB.prepare(`
                    INSERT INTO presence (user_id, presence, status_msg, last_active_ts, currently_active)
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT (user_id) DO UPDATE SET
                      presence = excluded.presence,
                      status_msg = excluded.status_msg,
                      last_active_ts = excluded.last_active_ts,
                      currently_active = excluded.currently_active
                  `).bind(
                    update.user_id,
                    update.presence,
                    update.status_msg || null,
                    lastActive,
                    update.currently_active ? 1 : 0
                  ).run();
                } catch (presErr) {
                  console.warn(`[federation] Failed to update presence for ${update.user_id}:`, presErr);
                }
              }
            }
          }
          break;
        }

        case 'm.device_list_update': {
          // Process inbound device list update EDUs from federated servers
          const deviceUserId = content?.user_id as string;
          const deviceId = content?.device_id as string;
          const streamId = (content?.stream_id as number) || 0;
          const deviceKeys = content?.keys;
          const deviceDisplayName = content?.device_display_name as string | undefined;
          const deleted = content?.deleted as boolean;

          if (deviceUserId && deviceId) {
            try {
              if (deleted) {
                await c.env.DB.prepare(
                  `DELETE FROM remote_device_lists WHERE user_id = ? AND device_id = ?`
                ).bind(deviceUserId, deviceId).run();
              } else {
                await c.env.DB.prepare(`
                  INSERT INTO remote_device_lists (user_id, device_id, device_display_name, keys, stream_id, updated_at)
                  VALUES (?, ?, ?, ?, ?, ?)
                  ON CONFLICT (user_id, device_id) DO UPDATE SET
                    device_display_name = excluded.device_display_name,
                    keys = excluded.keys,
                    stream_id = excluded.stream_id,
                    updated_at = excluded.updated_at
                `).bind(
                  deviceUserId,
                  deviceId,
                  deviceDisplayName || null,
                  deviceKeys ? JSON.stringify(deviceKeys) : null,
                  streamId,
                  Date.now()
                ).run();
              }

              // Update stream tracking
              await c.env.DB.prepare(`
                INSERT INTO remote_device_list_streams (user_id, stream_id, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT (user_id) DO UPDATE SET
                  stream_id = MAX(remote_device_list_streams.stream_id, excluded.stream_id),
                  updated_at = excluded.updated_at
              `).bind(deviceUserId, streamId, Date.now()).run();
            } catch (devErr) {
              console.warn(`[federation] Failed to update device list for ${deviceUserId}:`, devErr);
            }
          }
          break;
        }

        case 'm.receipt':
          // Handle read receipts
          break;

        case 'm.direct_to_device':
          // Handle to-device messages
          break;

        case 'm.signing_key_update':
          // Handle cross-signing key updates
          break;

        default:
          // Unknown EDU type - log and continue
          console.log(`Received unknown EDU type: ${eduType}`);
      }

      // Store EDU for record keeping
      const eduId = await sha256(`${origin}:${eduType}:${Date.now()}:${Math.random()}`);
      await c.env.DB.prepare(
        `INSERT OR REPLACE INTO processed_edus (edu_id, edu_type, origin, processed_at, content)
         VALUES (?, ?, ?, ?, ?)`
      ).bind(eduId, eduType, origin, Date.now(), JSON.stringify(content)).run();
    } catch (e) {
      console.error(`Failed to process EDU:`, e);
    }
  }

  const response = { pdus: pduResults };

  // Store transaction for idempotency
  await c.env.DB.prepare(
    `INSERT OR REPLACE INTO federation_transactions (txn_id, origin, received_at, response)
     VALUES (?, ?, ?, ?)`
  ).bind(txnId, origin, Date.now(), JSON.stringify(response)).run();

  return c.json(response);
});

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

// GET /_matrix/federation/v1/state_ids/:roomId - Get room state event IDs only
app.get('/_matrix/federation/v1/state_ids/:roomId', async (c) => {
  const roomId = c.req.param('roomId');
  const eventId = c.req.query('event_id');

  // Verify room exists
  const room = await c.env.DB.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get state event IDs
  let stateEventIds: string[];
  let authChainIds: string[];

  if (eventId) {
    // Get state at a specific event
    // For now, we get current state - proper implementation would track state snapshots
    const stateEvents = await c.env.DB.prepare(
      `SELECT e.event_id, e.auth_events
       FROM room_state rs
       JOIN events e ON rs.event_id = e.event_id
       WHERE rs.room_id = ?`
    ).bind(roomId).all<{ event_id: string; auth_events: string }>();

    stateEventIds = stateEvents.results.map(e => e.event_id);

    // Collect auth chain IDs
    const authChainSet = new Set<string>();
    for (const event of stateEvents.results) {
      const authEvents = JSON.parse(event.auth_events) as string[];
      for (const authId of authEvents) {
        authChainSet.add(authId);
      }
    }
    authChainIds = Array.from(authChainSet);
  } else {
    // Get current state
    const stateEvents = await c.env.DB.prepare(
      `SELECT e.event_id, e.auth_events
       FROM room_state rs
       JOIN events e ON rs.event_id = e.event_id
       WHERE rs.room_id = ?`
    ).bind(roomId).all<{ event_id: string; auth_events: string }>();

    stateEventIds = stateEvents.results.map(e => e.event_id);

    // Collect auth chain IDs
    const authChainSet = new Set<string>();
    for (const event of stateEvents.results) {
      const authEvents = JSON.parse(event.auth_events) as string[];
      for (const authId of authEvents) {
        authChainSet.add(authId);
      }
    }
    authChainIds = Array.from(authChainSet);
  }

  return c.json({
    pdu_ids: stateEventIds,
    auth_chain_ids: authChainIds,
  });
});

// GET /_matrix/federation/v1/event_auth/:roomId/:eventId - Get auth chain for an event
app.get('/_matrix/federation/v1/event_auth/:roomId/:eventId', async (c) => {
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');

  // Verify room exists
  const room = await c.env.DB.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get the event
  const event = await c.env.DB.prepare(
    `SELECT event_id, auth_events FROM events WHERE event_id = ? AND room_id = ?`
  ).bind(eventId, roomId).first<{ event_id: string; auth_events: string }>();

  if (!event) {
    return Errors.notFound('Event not found').toResponse();
  }

  // Build auth chain by recursively collecting auth events
  const authChain: PDU[] = [];
  const visited = new Set<string>();
  const toProcess = JSON.parse(event.auth_events) as string[];

  while (toProcess.length > 0) {
    const authId = toProcess.shift()!;
    if (visited.has(authId)) continue;
    visited.add(authId);

    const authEvent = await c.env.DB.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, depth, auth_events, prev_events, hashes, signatures
       FROM events WHERE event_id = ?`
    ).bind(authId).first<{
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

    if (authEvent) {
      authChain.push({
        event_id: authEvent.event_id,
        room_id: authEvent.room_id,
        sender: authEvent.sender,
        type: authEvent.event_type,
        state_key: authEvent.state_key ?? undefined,
        content: JSON.parse(authEvent.content),
        origin_server_ts: authEvent.origin_server_ts,
        depth: authEvent.depth,
        auth_events: JSON.parse(authEvent.auth_events),
        prev_events: JSON.parse(authEvent.prev_events),
        hashes: authEvent.hashes ? JSON.parse(authEvent.hashes) : undefined,
        signatures: authEvent.signatures ? JSON.parse(authEvent.signatures) : undefined,
      });

      // Add this event's auth_events to process
      const moreAuthEvents = JSON.parse(authEvent.auth_events) as string[];
      for (const id of moreAuthEvents) {
        if (!visited.has(id)) {
          toProcess.push(id);
        }
      }
    }
  }

  return c.json({
    auth_chain: authChain,
  });
});

// GET /_matrix/federation/v1/backfill/:roomId - Fetch historical events
app.get('/_matrix/federation/v1/backfill/:roomId', async (c) => {
  const roomId = c.req.param('roomId');
  const limit = Math.min(parseInt(c.req.query('limit') || '100', 10), 1000);
  const vParam = c.req.query('v'); // Starting event IDs

  // Verify room exists
  const room = await c.env.DB.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Parse starting event IDs
  const startEventIds = vParam ? vParam.split(',') : [];

  let events: any[];
  if (startEventIds.length > 0) {
    // Get events before the specified events
    const startEvents = await c.env.DB.prepare(
      `SELECT MIN(depth) as min_depth FROM events WHERE event_id IN (${startEventIds.map(() => '?').join(',')})`
    ).bind(...startEventIds).first<{ min_depth: number }>();

    const maxDepth = startEvents?.min_depth || 0;

    events = (await c.env.DB.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, depth, auth_events, prev_events, hashes, signatures
       FROM events
       WHERE room_id = ? AND depth < ?
       ORDER BY depth DESC
       LIMIT ?`
    ).bind(roomId, maxDepth, limit).all()).results;
  } else {
    // Get most recent events
    events = (await c.env.DB.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, depth, auth_events, prev_events, hashes, signatures
       FROM events
       WHERE room_id = ?
       ORDER BY depth DESC
       LIMIT ?`
    ).bind(roomId, limit).all()).results;
  }

  const pdus = events.map((e: any) => ({
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
    hashes: e.hashes ? JSON.parse(e.hashes) : undefined,
    signatures: e.signatures ? JSON.parse(e.signatures) : undefined,
  }));

  return c.json({
    origin: c.env.SERVER_NAME,
    origin_server_ts: Date.now(),
    pdus,
  });
});

// POST /_matrix/federation/v1/get_missing_events/:roomId - Fill event gaps
app.post('/_matrix/federation/v1/get_missing_events/:roomId', async (c) => {
  const roomId = c.req.param('roomId');

  let body: {
    earliest_events?: string[];
    latest_events?: string[];
    limit?: number;
    min_depth?: number;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const earliestEvents = body.earliest_events || [];
  const latestEvents = body.latest_events || [];
  const limit = Math.min(body.limit || 10, 100);
  const minDepth = body.min_depth || 0;

  // Verify room exists
  const room = await c.env.DB.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Walk backwards from latest_events to earliest_events
  const events: any[] = [];
  const visited = new Set<string>(earliestEvents);
  const toProcess = [...latestEvents];

  while (toProcess.length > 0 && events.length < limit) {
    const eventId = toProcess.shift()!;
    if (visited.has(eventId)) continue;
    visited.add(eventId);

    const event = await c.env.DB.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, depth, auth_events, prev_events, hashes, signatures
       FROM events
       WHERE event_id = ? AND room_id = ? AND depth >= ?`
    ).bind(eventId, roomId, minDepth).first<{
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

    if (event) {
      events.push({
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
      });

      // Add prev_events to process
      const prevEvents = JSON.parse(event.prev_events) as string[];
      for (const prevId of prevEvents) {
        if (!visited.has(prevId)) {
          toProcess.push(prevId);
        }
      }
    }
  }

  return c.json({
    events,
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

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate the event ID matches
  if (body.event_id && body.event_id !== eventId) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event ID mismatch' },
      400
    );
  }

  // Get current state and auth chain
  const stateEvents = await c.env.DB.prepare(
    `SELECT e.* FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ?`
  ).bind(roomId).all();

  // Build auth chain
  const authChainIds = new Set<string>();
  for (const event of stateEvents.results) {
    const authEvents = JSON.parse((event as any).auth_events) as string[];
    for (const authId of authEvents) {
      authChainIds.add(authId);
    }
  }

  const authChain: any[] = [];
  for (const authId of authChainIds) {
    const authEvent = await c.env.DB.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, depth, auth_events, prev_events, hashes, signatures
       FROM events WHERE event_id = ?`
    ).bind(authId).first();

    if (authEvent) {
      authChain.push({
        event_id: (authEvent as any).event_id,
        room_id: (authEvent as any).room_id,
        sender: (authEvent as any).sender,
        type: (authEvent as any).event_type,
        state_key: (authEvent as any).state_key ?? undefined,
        content: JSON.parse((authEvent as any).content),
        origin_server_ts: (authEvent as any).origin_server_ts,
        depth: (authEvent as any).depth,
        auth_events: JSON.parse((authEvent as any).auth_events),
        prev_events: JSON.parse((authEvent as any).prev_events),
        hashes: (authEvent as any).hashes ? JSON.parse((authEvent as any).hashes) : undefined,
        signatures: (authEvent as any).signatures ? JSON.parse((authEvent as any).signatures) : undefined,
      });
    }
  }

  return c.json({
    origin: c.env.SERVER_NAME,
    auth_chain: authChain,
    state: stateEvents.results.map((e: any) => ({
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
      hashes: e.hashes ? JSON.parse(e.hashes) : undefined,
      signatures: e.signatures ? JSON.parse(e.signatures) : undefined,
    })),
    event: body,
  });
});

// PUT /_matrix/federation/v2/send_join/:roomId/:eventId - Complete join (v2)
// v2 wraps response in { event, state, auth_chain, ... } instead of returning array
app.put('/_matrix/federation/v2/send_join/:roomId/:eventId', async (c) => {
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate the event ID matches
  if (body.event_id && body.event_id !== eventId) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event ID mismatch' },
      400
    );
  }

  // Get room info
  const room = await c.env.DB.prepare(
    `SELECT room_id, room_version FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string; room_version: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get current state and auth chain
  const stateEvents = await c.env.DB.prepare(
    `SELECT e.* FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ?`
  ).bind(roomId).all();

  // Build auth chain
  const authChainIds = new Set<string>();
  for (const event of stateEvents.results) {
    const authEvents = JSON.parse((event as any).auth_events) as string[];
    for (const authId of authEvents) {
      authChainIds.add(authId);
    }
  }

  const authChain: any[] = [];
  for (const authId of authChainIds) {
    const authEvent = await c.env.DB.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, depth, auth_events, prev_events, hashes, signatures
       FROM events WHERE event_id = ?`
    ).bind(authId).first();

    if (authEvent) {
      authChain.push({
        event_id: (authEvent as any).event_id,
        room_id: (authEvent as any).room_id,
        sender: (authEvent as any).sender,
        type: (authEvent as any).event_type,
        state_key: (authEvent as any).state_key ?? undefined,
        content: JSON.parse((authEvent as any).content),
        origin_server_ts: (authEvent as any).origin_server_ts,
        depth: (authEvent as any).depth,
        auth_events: JSON.parse((authEvent as any).auth_events),
        prev_events: JSON.parse((authEvent as any).prev_events),
        hashes: (authEvent as any).hashes ? JSON.parse((authEvent as any).hashes) : undefined,
        signatures: (authEvent as any).signatures ? JSON.parse((authEvent as any).signatures) : undefined,
      });
    }
  }

  // v2 returns servers_in_room for restricted joins
  const serversInRoom = new Set<string>();
  for (const event of stateEvents.results) {
    if ((event as any).event_type === 'm.room.member') {
      const content = JSON.parse((event as any).content);
      if (content.membership === 'join') {
        const sender = (event as any).sender as string;
        const serverName = sender.split(':')[1];
        if (serverName) serversInRoom.add(serverName);
      }
    }
  }

  return c.json({
    origin: c.env.SERVER_NAME,
    auth_chain: authChain,
    state: stateEvents.results.map((e: any) => ({
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
      hashes: e.hashes ? JSON.parse(e.hashes) : undefined,
      signatures: e.signatures ? JSON.parse(e.signatures) : undefined,
    })),
    event: body,
    members_omitted: false,
    servers_in_room: Array.from(serversInRoom),
  });
});

// GET /_matrix/federation/v1/make_leave/:roomId/:userId - Prepare leave request
app.get('/_matrix/federation/v1/make_leave/:roomId/:userId', async (c) => {
  const roomId = c.req.param('roomId');
  const userId = c.req.param('userId');

  // Check if room exists
  const room = await c.env.DB.prepare(
    `SELECT room_id, room_version FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string; room_version: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check if user is a member of the room
  const membership = await c.env.DB.prepare(
    `SELECT e.event_id FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ? AND rs.event_type = 'm.room.member' AND rs.state_key = ?`
  ).bind(roomId, userId).first<{ event_id: string }>();

  if (!membership) {
    return c.json(
      { errcode: 'M_FORBIDDEN', error: 'User is not a member of the room' },
      403
    );
  }

  // Get auth events for leave
  const createEvent = await c.env.DB.prepare(
    `SELECT e.event_id FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ? AND rs.event_type = 'm.room.create'`
  ).bind(roomId).first<{ event_id: string }>();

  const powerLevelsEvent = await c.env.DB.prepare(
    `SELECT e.event_id FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ? AND rs.event_type = 'm.room.power_levels'`
  ).bind(roomId).first<{ event_id: string }>();

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (membership) authEvents.push(membership.event_id);

  // Get latest event for prev_events
  const latestEvent = await c.env.DB.prepare(
    `SELECT event_id, depth FROM events WHERE room_id = ? ORDER BY depth DESC LIMIT 1`
  ).bind(roomId).first<{ event_id: string; depth: number }>();

  const prevEvents = latestEvent ? [latestEvent.event_id] : [];
  const depth = (latestEvent?.depth || 0) + 1;

  // Create unsigned leave event template
  const eventTemplate = {
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: {
      membership: 'leave',
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

// PUT /_matrix/federation/v1/send_leave/:roomId/:eventId - Complete leave
app.put('/_matrix/federation/v1/send_leave/:roomId/:eventId', async (c) => {
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate the event is a leave event
  if (body.type !== 'm.room.member' || body.content?.membership !== 'leave') {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event is not a leave event' },
      400
    );
  }

  // Validate the event ID matches
  if (body.event_id && body.event_id !== eventId) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event ID mismatch' },
      400
    );
  }

  // Verify room exists
  const room = await c.env.DB.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // v1 returns empty array on success [200, {}]
  return c.json([200, {}]);
});

// PUT /_matrix/federation/v2/send_leave/:roomId/:eventId - Complete leave (v2)
app.put('/_matrix/federation/v2/send_leave/:roomId/:eventId', async (c) => {
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate the event is a leave event
  if (body.type !== 'm.room.member' || body.content?.membership !== 'leave') {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event is not a leave event' },
      400
    );
  }

  // Validate the event ID matches
  if (body.event_id && body.event_id !== eventId) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event ID mismatch' },
      400
    );
  }

  // Verify room exists
  const room = await c.env.DB.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // v2 returns empty object on success
  return c.json({});
});

// PUT /_matrix/federation/v1/invite/:roomId/:eventId - Receive invite (v1)
// Used when a remote server invites a local user to a room
app.put('/_matrix/federation/v1/invite/:roomId/:eventId', async (c) => {
  // roomId is available from route params but we validate from the event body
  void c.req.param('roomId');
  const eventId = c.req.param('eventId');

  let body: {
    room_version?: string;
    event?: any;
    invite_room_state?: any[];
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const inviteEvent = body.event || body;

  // Validate the event is an invite
  if (inviteEvent.type !== 'm.room.member' || inviteEvent.content?.membership !== 'invite') {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event is not an invite event' },
      400
    );
  }

  // Validate event ID matches
  if (inviteEvent.event_id && inviteEvent.event_id !== eventId) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event ID mismatch' },
      400
    );
  }

  // Validate the invite is for a local user
  const stateKey = inviteEvent.state_key;
  if (!stateKey || !stateKey.includes(':')) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Invalid state_key for invite' },
      400
    );
  }

  const invitedServer = stateKey.split(':')[1];
  if (invitedServer !== c.env.SERVER_NAME) {
    return c.json(
      { errcode: 'M_FORBIDDEN', error: 'User is not local to this server' },
      403
    );
  }

  // Check if user exists locally
  const localUser = await c.env.DB.prepare(
    `SELECT user_id FROM users WHERE user_id = ?`
  ).bind(stateKey).first<{ user_id: string }>();

  if (!localUser) {
    return c.json(
      { errcode: 'M_NOT_FOUND', error: 'User not found' },
      404
    );
  }

  // Sign the invite event and return it
  // Get our signing key
  const key = await c.env.DB.prepare(
    `SELECT key_id, private_key_jwk FROM server_keys WHERE is_current = 1 AND key_version = 2`
  ).first<{ key_id: string; private_key_jwk: string | null }>();

  if (!key || !key.private_key_jwk) {
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'Server signing key not configured' },
      500
    );
  }

  // Sign the event
  const signedEvent = await signJson(
    inviteEvent,
    c.env.SERVER_NAME,
    key.key_id,
    JSON.parse(key.private_key_jwk)
  );

  // v1 returns the signed event directly
  return c.json([200, signedEvent]);
});

// PUT /_matrix/federation/v2/invite/:roomId/:eventId - Receive invite (v2)
app.put('/_matrix/federation/v2/invite/:roomId/:eventId', async (c) => {
  // roomId is available from route params but we validate from the event body
  void c.req.param('roomId');
  const eventId = c.req.param('eventId');

  let body: {
    room_version: string;
    event: any;
    invite_room_state?: any[];
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const roomVersion = body.room_version;
  const inviteEvent = body.event;

  if (!roomVersion) {
    return Errors.missingParam('room_version').toResponse();
  }

  if (!inviteEvent) {
    return Errors.missingParam('event').toResponse();
  }

  // Check room version is supported
  if (!SUPPORTED_ROOM_VERSIONS.includes(roomVersion)) {
    return c.json(
      { errcode: 'M_INCOMPATIBLE_ROOM_VERSION', error: `Unsupported room version: ${roomVersion}` },
      400
    );
  }

  // Validate the event is an invite
  if (inviteEvent.type !== 'm.room.member' || inviteEvent.content?.membership !== 'invite') {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event is not an invite event' },
      400
    );
  }

  // Validate event ID matches
  if (inviteEvent.event_id && inviteEvent.event_id !== eventId) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Event ID mismatch' },
      400
    );
  }

  // Validate the invite is for a local user
  const stateKey = inviteEvent.state_key;
  if (!stateKey || !stateKey.includes(':')) {
    return c.json(
      { errcode: 'M_INVALID_PARAM', error: 'Invalid state_key for invite' },
      400
    );
  }

  const invitedServer = stateKey.split(':')[1];
  if (invitedServer !== c.env.SERVER_NAME) {
    return c.json(
      { errcode: 'M_FORBIDDEN', error: 'User is not local to this server' },
      403
    );
  }

  // Check if user exists locally
  const localUser = await c.env.DB.prepare(
    `SELECT user_id FROM users WHERE user_id = ?`
  ).bind(stateKey).first<{ user_id: string }>();

  if (!localUser) {
    return c.json(
      { errcode: 'M_NOT_FOUND', error: 'User not found' },
      404
    );
  }

  // Sign the invite event and return it
  const key = await c.env.DB.prepare(
    `SELECT key_id, private_key_jwk FROM server_keys WHERE is_current = 1 AND key_version = 2`
  ).first<{ key_id: string; private_key_jwk: string | null }>();

  if (!key || !key.private_key_jwk) {
    return c.json(
      { errcode: 'M_UNKNOWN', error: 'Server signing key not configured' },
      500
    );
  }

  // Sign the event
  const signedEvent = await signJson(
    inviteEvent,
    c.env.SERVER_NAME,
    key.key_id,
    JSON.parse(key.private_key_jwk)
  );

  // v2 returns { event: signedEvent }
  return c.json({ event: signedEvent });
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

// ============================================
// Federation E2EE Endpoints
// Required for cross-server encrypted messaging
// ============================================

// Helper to get UserKeys Durable Object for a user
function getUserKeysDO(env: typeof app extends Hono<infer E> ? E['Bindings'] : never, userId: string): DurableObjectStub {
  const id = env.USER_KEYS.idFromName(userId);
  return env.USER_KEYS.get(id);
}

// Helper to get device keys from Durable Object
async function getDeviceKeysFromDO(env: typeof app extends Hono<infer E> ? E['Bindings'] : never, userId: string, deviceId?: string): Promise<any> {
  const stub = getUserKeysDO(env, userId);
  const url = deviceId
    ? `http://internal/device-keys/get?device_id=${encodeURIComponent(deviceId)}`
    : 'http://internal/device-keys/get';
  const response = await stub.fetch(new Request(url));
  if (!response.ok) {
    return deviceId ? null : {};
  }
  return await response.json();
}

// Helper to get cross-signing keys from Durable Object
async function getCrossSigningKeysFromDO(env: typeof app extends Hono<infer E> ? E['Bindings'] : never, userId: string): Promise<{
  master?: any;
  self_signing?: any;
  user_signing?: any;
}> {
  const stub = getUserKeysDO(env, userId);
  const response = await stub.fetch(new Request('http://internal/cross-signing/get'));
  if (!response.ok) {
    return {};
  }
  return await response.json();
}

// POST /_matrix/federation/v1/user/keys/query - Query device keys for local users
// This endpoint is called by remote servers to get device keys for E2EE
app.post('/_matrix/federation/v1/user/keys/query', async (c) => {
  const serverName = c.env.SERVER_NAME;
  const db = c.env.DB;

  let body: {
    device_keys?: Record<string, string[]>;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const requestedKeys = body.device_keys;
  if (!requestedKeys || typeof requestedKeys !== 'object') {
    return Errors.missingParam('device_keys').toResponse();
  }

  const deviceKeys: Record<string, Record<string, any>> = {};
  const masterKeys: Record<string, any> = {};
  const selfSigningKeys: Record<string, any> = {};

  // Helper to merge signatures from D1 into device keys
  async function mergeSignaturesForDevice(userId: string, deviceId: string, deviceKey: any): Promise<any> {
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

  for (const [userId, requestedDevices] of Object.entries(requestedKeys)) {
    // Verify user is local to this server
    const userServerName = userId.split(':')[1];
    if (userServerName !== serverName) {
      // Skip non-local users - federation should query their home server
      continue;
    }

    // Check if user exists locally
    const user = await db.prepare(
      `SELECT user_id FROM users WHERE user_id = ?`
    ).bind(userId).first<{ user_id: string }>();

    if (!user) {
      continue;
    }

    deviceKeys[userId] = {};

    // Get device keys from Durable Object (strongly consistent)
    if (!requestedDevices || requestedDevices.length === 0) {
      // Get all devices for this user
      const allDeviceKeys = await getDeviceKeysFromDO(c.env, userId);
      for (const [deviceId, keys] of Object.entries(allDeviceKeys)) {
        if (keys) {
          deviceKeys[userId][deviceId] = await mergeSignaturesForDevice(userId, deviceId, keys);
        }
      }
    } else {
      // Get specific devices
      for (const deviceId of requestedDevices) {
        const keys = await getDeviceKeysFromDO(c.env, userId, deviceId);
        if (keys) {
          deviceKeys[userId][deviceId] = await mergeSignaturesForDevice(userId, deviceId, keys);
        }
      }
    }

    // Get cross-signing keys (master + self_signing only for federation)
    // Note: user_signing key is NOT included in federation responses per spec
    const csKeys = await getCrossSigningKeysFromDO(c.env, userId);

    if (csKeys.master) {
      masterKeys[userId] = csKeys.master;
    }
    if (csKeys.self_signing) {
      selfSigningKeys[userId] = csKeys.self_signing;
    }
  }

  return c.json({
    device_keys: deviceKeys,
    master_keys: masterKeys,
    self_signing_keys: selfSigningKeys,
  });
});

// POST /_matrix/federation/v1/user/keys/claim - Claim one-time keys for E2EE session establishment
// Remote servers call this to get OTKs to establish encrypted sessions with local users
app.post('/_matrix/federation/v1/user/keys/claim', async (c) => {
  const serverName = c.env.SERVER_NAME;
  const db = c.env.DB;

  let body: {
    one_time_keys?: Record<string, Record<string, string>>;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const requestedKeys = body.one_time_keys;
  if (!requestedKeys || typeof requestedKeys !== 'object') {
    return Errors.missingParam('one_time_keys').toResponse();
  }

  const oneTimeKeys: Record<string, Record<string, Record<string, any>>> = {};

  for (const [userId, devices] of Object.entries(requestedKeys)) {
    // Verify user is local to this server
    const userServerName = userId.split(':')[1];
    if (userServerName !== serverName) {
      continue;
    }

    oneTimeKeys[userId] = {};

    for (const [deviceId, algorithm] of Object.entries(devices)) {
      // Try to claim a one-time key from KV first (fast path)
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
        // Fallback to D1 for keys not in KV
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
        // Try fallback key as last resort
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

  return c.json({
    one_time_keys: oneTimeKeys,
  });
});

// GET /_matrix/federation/v1/user/devices/:userId - Get device list for a local user
// Remote servers call this to get the list of devices for a user
app.get('/_matrix/federation/v1/user/devices/:userId', async (c) => {
  const serverName = c.env.SERVER_NAME;
  const userId = c.req.param('userId');
  const db = c.env.DB;

  // Verify user is local to this server
  const userServerName = userId.split(':')[1];
  if (userServerName !== serverName) {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'User is not local to this server',
    }, 403);
  }

  // Check if user exists
  const user = await db.prepare(
    `SELECT user_id FROM users WHERE user_id = ?`
  ).bind(userId).first<{ user_id: string }>();

  if (!user) {
    return Errors.notFound('User not found').toResponse();
  }

  // Get all devices from D1 (for display names)
  const dbDevices = await db.prepare(
    `SELECT device_id, display_name FROM devices WHERE user_id = ?`
  ).bind(userId).all<{ device_id: string; display_name: string | null }>();

  // Get device keys from Durable Object (strongly consistent)
  const allDeviceKeys = await getDeviceKeysFromDO(c.env, userId);

  // Get stream_id for device key changes
  const streamPosition = await db.prepare(
    `SELECT MAX(stream_position) as stream_id FROM device_key_changes WHERE user_id = ?`
  ).bind(userId).first<{ stream_id: number | null }>();

  // Build device list
  const devices: Array<{
    device_id: string;
    keys?: any;
    device_display_name?: string;
  }> = [];

  for (const dbDevice of dbDevices.results) {
    const deviceKeys = allDeviceKeys[dbDevice.device_id];
    devices.push({
      device_id: dbDevice.device_id,
      keys: deviceKeys || undefined,
      device_display_name: dbDevice.display_name || undefined,
    });
  }

  // Get cross-signing keys (master + self_signing only for federation)
  const csKeys = await getCrossSigningKeysFromDO(c.env, userId);

  const response: any = {
    user_id: userId,
    stream_id: streamPosition?.stream_id || 0,
    devices,
  };

  // Add cross-signing keys if present
  if (csKeys.master) {
    response.master_key = csKeys.master;
  }
  if (csKeys.self_signing) {
    response.self_signing_key = csKeys.self_signing;
  }

  return c.json(response);
});

// ============================================
// Knock Protocol Endpoints
// Allows users to request to join rooms
// ============================================

// GET /_matrix/federation/v1/make_knock/:roomId/:userId - Prepare knock request
// Remote servers call this to get a knock event template
app.get('/_matrix/federation/v1/make_knock/:roomId/:userId', async (c) => {
  const roomId = c.req.param('roomId');
  const userId = c.req.param('userId');
  const db = c.env.DB;

  // Check if room exists
  const room = await db.prepare(
    `SELECT room_id, room_version FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string; room_version: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get join_rules to verify room allows knocking
  const joinRulesEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'
  `).bind(roomId).first<{ content: string }>();

  if (joinRulesEvent) {
    const joinRules = JSON.parse(joinRulesEvent.content);
    if (joinRules.join_rule !== 'knock' && joinRules.join_rule !== 'knock_restricted') {
      return c.json({
        errcode: 'M_FORBIDDEN',
        error: 'Room does not allow knocking',
      }, 403);
    }
  } else {
    // Default join_rule is 'invite', knocking not allowed
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Room does not allow knocking',
    }, 403);
  }

  // Check if user is already banned
  const membership = await db.prepare(
    `SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?`
  ).bind(roomId, userId).first<{ membership: string }>();

  if (membership?.membership === 'ban') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'User is banned from this room',
    }, 403);
  }

  if (membership?.membership === 'join') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'User is already a member of this room',
    }, 403);
  }

  // Get auth events for knock
  const createEvent = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.create'
  `).bind(roomId).first<{ event_id: string }>();

  const joinRulesEventId = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'
  `).bind(roomId).first<{ event_id: string }>();

  const powerLevelsEvent = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.power_levels'
  `).bind(roomId).first<{ event_id: string }>();

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (joinRulesEventId) authEvents.push(joinRulesEventId.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);

  // Get latest event for prev_events
  const latestEvent = await db.prepare(
    `SELECT event_id, depth FROM events WHERE room_id = ? ORDER BY depth DESC LIMIT 1`
  ).bind(roomId).first<{ event_id: string; depth: number }>();

  const prevEvents = latestEvent ? [latestEvent.event_id] : [];
  const depth = (latestEvent?.depth || 0) + 1;

  // Create unsigned knock event template
  const eventTemplate = {
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: {
      membership: 'knock',
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

// PUT /_matrix/federation/v1/send_knock/:roomId/:eventId - Complete knock
// Remote servers call this to finalize the knock with a signed event
app.put('/_matrix/federation/v1/send_knock/:roomId/:eventId', async (c) => {
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');
  const db = c.env.DB;

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate the event is a knock event
  if (body.type !== 'm.room.member' || body.content?.membership !== 'knock') {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Event is not a knock event',
    }, 400);
  }

  // Validate the event ID matches
  if (body.event_id && body.event_id !== eventId) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Event ID mismatch',
    }, 400);
  }

  // Verify room exists
  const room = await db.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Verify room allows knocking
  const joinRulesEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'
  `).bind(roomId).first<{ content: string }>();

  if (joinRulesEvent) {
    const joinRules = JSON.parse(joinRulesEvent.content);
    if (joinRules.join_rule !== 'knock' && joinRules.join_rule !== 'knock_restricted') {
      return c.json({
        errcode: 'M_FORBIDDEN',
        error: 'Room does not allow knocking',
      }, 403);
    }
  } else {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Room does not allow knocking',
    }, 403);
  }

  // Check if user is already banned or joined
  const userId = body.state_key;
  const membership = await db.prepare(
    `SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?`
  ).bind(roomId, userId).first<{ membership: string }>();

  if (membership?.membership === 'ban') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'User is banned from this room',
    }, 403);
  }

  if (membership?.membership === 'join') {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'User is already a member of this room',
    }, 403);
  }

  // Store the knock event
  try {
    await db.prepare(`
      INSERT OR IGNORE INTO events
      (event_id, room_id, sender, event_type, state_key, content, origin_server_ts, depth, auth_events, prev_events, hashes, signatures)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      eventId,
      roomId,
      body.sender,
      body.type,
      body.state_key,
      JSON.stringify(body.content),
      body.origin_server_ts,
      body.depth || 0,
      JSON.stringify(body.auth_events || []),
      JSON.stringify(body.prev_events || []),
      body.hashes ? JSON.stringify(body.hashes) : null,
      body.signatures ? JSON.stringify(body.signatures) : null
    ).run();

    // Update room state
    await db.prepare(`
      INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
      VALUES (?, ?, ?, ?)
    `).bind(roomId, body.type, body.state_key, eventId).run();

    // Update memberships table
    await db.prepare(`
      INSERT OR REPLACE INTO room_memberships (room_id, user_id, membership, event_id)
      VALUES (?, ?, 'knock', ?)
    `).bind(roomId, userId, eventId).run();
  } catch (e) {
    console.error(`Failed to store knock event ${eventId}:`, e);
  }

  // Return stripped state events (room name, avatar, join_rules, canonical_alias)
  const strippedState: any[] = [];

  // Get room name
  const nameEvent = await db.prepare(`
    SELECT e.event_type, e.state_key, e.content, e.sender, e.origin_server_ts
    FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.name'
  `).bind(roomId).first<{
    event_type: string;
    state_key: string;
    content: string;
    sender: string;
    origin_server_ts: number;
  }>();

  if (nameEvent) {
    strippedState.push({
      type: nameEvent.event_type,
      state_key: nameEvent.state_key,
      content: JSON.parse(nameEvent.content),
      sender: nameEvent.sender,
    });
  }

  // Get room avatar
  const avatarEvent = await db.prepare(`
    SELECT e.event_type, e.state_key, e.content, e.sender
    FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.avatar'
  `).bind(roomId).first<{
    event_type: string;
    state_key: string;
    content: string;
    sender: string;
  }>();

  if (avatarEvent) {
    strippedState.push({
      type: avatarEvent.event_type,
      state_key: avatarEvent.state_key,
      content: JSON.parse(avatarEvent.content),
      sender: avatarEvent.sender,
    });
  }

  // Get join_rules
  if (joinRulesEvent) {
    const joinRulesEventFull = await db.prepare(`
      SELECT e.event_type, e.state_key, e.content, e.sender
      FROM room_state rs
      JOIN events e ON rs.event_id = e.event_id
      WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'
    `).bind(roomId).first<{
      event_type: string;
      state_key: string;
      content: string;
      sender: string;
    }>();

    if (joinRulesEventFull) {
      strippedState.push({
        type: joinRulesEventFull.event_type,
        state_key: joinRulesEventFull.state_key,
        content: JSON.parse(joinRulesEventFull.content),
        sender: joinRulesEventFull.sender,
      });
    }
  }

  // Get canonical alias
  const aliasEvent = await db.prepare(`
    SELECT e.event_type, e.state_key, e.content, e.sender
    FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.canonical_alias'
  `).bind(roomId).first<{
    event_type: string;
    state_key: string;
    content: string;
    sender: string;
  }>();

  if (aliasEvent) {
    strippedState.push({
      type: aliasEvent.event_type,
      state_key: aliasEvent.state_key,
      content: JSON.parse(aliasEvent.content),
      sender: aliasEvent.sender,
    });
  }

  return c.json({
    knock_room_state: strippedState,
  });
});

// ============================================
// Federation Media Endpoints
// Serve local media to remote servers
// ============================================

// GET /_matrix/federation/v1/media/download/:mediaId - Download media via federation
app.get('/_matrix/federation/v1/media/download/:mediaId', async (c) => {
  const mediaId = c.req.param('mediaId');

  // Get media from R2
  const object = await c.env.MEDIA.get(mediaId);
  if (!object) {
    return Errors.notFound('Media not found').toResponse();
  }

  // Get metadata from D1
  const metadata = await c.env.DB.prepare(
    `SELECT content_type, filename FROM media WHERE media_id = ?`
  ).bind(mediaId).first<{ content_type: string; filename: string | null }>();

  const headers = new Headers();
  headers.set('Content-Type', metadata?.content_type || 'application/octet-stream');
  if (metadata?.filename) {
    headers.set('Content-Disposition', `inline; filename="${metadata.filename}"`);
  }
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');

  return new Response(object.body, { headers });
});

// GET /_matrix/federation/v1/media/thumbnail/:mediaId - Get thumbnail via federation
app.get('/_matrix/federation/v1/media/thumbnail/:mediaId', async (c) => {
  const mediaId = c.req.param('mediaId');
  const width = Math.min(parseInt(c.req.query('width') || '96'), 1920);
  const height = Math.min(parseInt(c.req.query('height') || '96'), 1920);
  const method = c.req.query('method') || 'scale';

  // Get media metadata
  const metadata = await c.env.DB.prepare(
    `SELECT content_type FROM media WHERE media_id = ?`
  ).bind(mediaId).first<{ content_type: string }>();

  if (!metadata) {
    return Errors.notFound('Media not found').toResponse();
  }

  const isImage = metadata.content_type.startsWith('image/');

  // Check for pre-generated thumbnail
  const thumbnailKey = `thumb_${mediaId}_${width}x${height}_${method}`;
  const existingThumb = await c.env.MEDIA.get(thumbnailKey);

  if (existingThumb) {
    const headers = new Headers();
    headers.set('Content-Type', 'image/jpeg');
    headers.set('Cache-Control', 'public, max-age=31536000, immutable');
    return new Response(existingThumb.body, { headers });
  }

  // Get original
  const object = await c.env.MEDIA.get(mediaId);
  if (!object) {
    return Errors.notFound('Media not found').toResponse();
  }

  // If not an image, return original
  const headers = new Headers();
  headers.set('Content-Type', metadata.content_type);
  headers.set('Cache-Control', 'public, max-age=31536000, immutable');
  if (isImage) {
    headers.set('X-Thumbnail-Generated', 'false');
  }

  return new Response(object.body, { headers });
});

// ============================================
// Federation Public Rooms Directory
// ============================================

// GET /_matrix/federation/v1/publicRooms - Get public rooms
app.get('/_matrix/federation/v1/publicRooms', async (c) => {
  const db = c.env.DB;
  const serverName = c.env.SERVER_NAME;

  const limit = Math.min(parseInt(c.req.query('limit') || '100'), 500);
  const since = c.req.query('since');
  // Note: include_all_networks reserved for future use
  void c.req.query('include_all_networks');

  // Parse since token for pagination (format: "offset_N")
  let offset = 0;
  if (since && since.startsWith('offset_')) {
    offset = parseInt(since.substring(7), 10) || 0;
  }

  // Query public rooms
  const rooms = await db.prepare(`
    SELECT r.room_id
    FROM rooms r
    WHERE r.is_public = 1
    ORDER BY r.created_at DESC
    LIMIT ? OFFSET ?
  `).bind(limit + 1, offset).all<{ room_id: string }>();

  const hasMore = rooms.results.length > limit;
  const roomResults = rooms.results.slice(0, limit);

  // Build room chunks
  const chunks: any[] = [];

  for (const room of roomResults) {
    const roomInfo = await getRoomPublicInfo(db, room.room_id, serverName);
    if (roomInfo) {
      chunks.push(roomInfo);
    }
  }

  // Count total
  const totalCount = await db.prepare(`
    SELECT COUNT(*) as count FROM rooms WHERE is_public = 1
  `).first<{ count: number }>();

  const response: any = {
    chunk: chunks,
    total_room_count_estimate: totalCount?.count || 0,
  };

  if (hasMore) {
    response.next_batch = `offset_${offset + limit}`;
  }
  if (offset > 0) {
    response.prev_batch = `offset_${Math.max(0, offset - limit)}`;
  }

  return c.json(response);
});

// POST /_matrix/federation/v1/publicRooms - Search public rooms
app.post('/_matrix/federation/v1/publicRooms', async (c) => {
  const db = c.env.DB;
  const serverName = c.env.SERVER_NAME;

  let body: {
    limit?: number;
    since?: string;
    filter?: { generic_search_term?: string };
    include_all_networks?: boolean;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const limit = Math.min(body.limit || 100, 500);
  const since = body.since;
  const searchTerm = body.filter?.generic_search_term?.toLowerCase();

  // Parse since token
  let offset = 0;
  if (since && since.startsWith('offset_')) {
    offset = parseInt(since.substring(7), 10) || 0;
  }

  // Query public rooms with optional search
  let rooms;
  if (searchTerm) {
    rooms = await db.prepare(`
      SELECT DISTINCT r.room_id
      FROM rooms r
      LEFT JOIN room_state rs_name ON rs_name.room_id = r.room_id AND rs_name.event_type = 'm.room.name'
      LEFT JOIN events e_name ON rs_name.event_id = e_name.event_id
      LEFT JOIN room_state rs_topic ON rs_topic.room_id = r.room_id AND rs_topic.event_type = 'm.room.topic'
      LEFT JOIN events e_topic ON rs_topic.event_id = e_topic.event_id
      LEFT JOIN room_aliases ra ON ra.room_id = r.room_id
      WHERE r.is_public = 1
        AND (
          LOWER(e_name.content) LIKE ?
          OR LOWER(e_topic.content) LIKE ?
          OR LOWER(ra.alias) LIKE ?
        )
      ORDER BY r.created_at DESC
      LIMIT ? OFFSET ?
    `).bind(`%${searchTerm}%`, `%${searchTerm}%`, `%${searchTerm}%`, limit + 1, offset).all<{ room_id: string }>();
  } else {
    rooms = await db.prepare(`
      SELECT r.room_id
      FROM rooms r
      WHERE r.is_public = 1
      ORDER BY r.created_at DESC
      LIMIT ? OFFSET ?
    `).bind(limit + 1, offset).all<{ room_id: string }>();
  }

  const hasMore = rooms.results.length > limit;
  const roomResults = rooms.results.slice(0, limit);

  // Build room chunks
  const chunks: any[] = [];

  for (const room of roomResults) {
    const roomInfo = await getRoomPublicInfo(db, room.room_id, serverName);
    if (roomInfo) {
      chunks.push(roomInfo);
    }
  }

  // Count total
  const totalCount = await db.prepare(`
    SELECT COUNT(*) as count FROM rooms WHERE is_public = 1
  `).first<{ count: number }>();

  const response: any = {
    chunk: chunks,
    total_room_count_estimate: totalCount?.count || 0,
  };

  if (hasMore) {
    response.next_batch = `offset_${offset + limit}`;
  }
  if (offset > 0) {
    response.prev_batch = `offset_${Math.max(0, offset - limit)}`;
  }

  return c.json(response);
});

// Helper to get public room info
async function getRoomPublicInfo(db: D1Database, roomId: string, _serverName: string): Promise<any> {
  // Get room name
  const nameEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.name'
  `).bind(roomId).first<{ content: string }>();

  // Get room topic
  const topicEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.topic'
  `).bind(roomId).first<{ content: string }>();

  // Get canonical alias
  const aliasEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.canonical_alias'
  `).bind(roomId).first<{ content: string }>();

  // Get avatar
  const avatarEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.avatar'
  `).bind(roomId).first<{ content: string }>();

  // Get join rule
  const joinRuleEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'
  `).bind(roomId).first<{ content: string }>();

  // Get history visibility
  const historyEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.history_visibility'
  `).bind(roomId).first<{ content: string }>();

  // Get guest access
  const guestEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.guest_access'
  `).bind(roomId).first<{ content: string }>();

  // Get member count
  const memberCount = await db.prepare(`
    SELECT COUNT(*) as count FROM room_memberships WHERE room_id = ? AND membership = 'join'
  `).bind(roomId).first<{ count: number }>();

  // Get room type
  const createEvent = await db.prepare(`
    SELECT e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.create'
  `).bind(roomId).first<{ content: string }>();

  let roomType: string | undefined;
  if (createEvent) {
    try {
      const content = JSON.parse(createEvent.content);
      roomType = content.type;
    } catch {}
  }

  let historyVisibility = 'shared';
  if (historyEvent) {
    try {
      historyVisibility = JSON.parse(historyEvent.content).history_visibility;
    } catch {}
  }

  let guestAccess = false;
  if (guestEvent) {
    try {
      guestAccess = JSON.parse(guestEvent.content).guest_access === 'can_join';
    } catch {}
  }

  return {
    room_id: roomId,
    name: nameEvent ? JSON.parse(nameEvent.content).name : undefined,
    topic: topicEvent ? JSON.parse(topicEvent.content).topic : undefined,
    canonical_alias: aliasEvent ? JSON.parse(aliasEvent.content).alias : undefined,
    avatar_url: avatarEvent ? JSON.parse(avatarEvent.content).url : undefined,
    join_rule: joinRuleEvent ? JSON.parse(joinRuleEvent.content).join_rule : 'invite',
    num_joined_members: memberCount?.count || 0,
    world_readable: historyVisibility === 'world_readable',
    guest_can_join: guestAccess,
    room_type: roomType,
  };
}

// ============================================
// Federation Space Hierarchy
// ============================================

// GET /_matrix/federation/v1/hierarchy/:roomId - Get space hierarchy
app.get('/_matrix/federation/v1/hierarchy/:roomId', async (c) => {
  const roomId = c.req.param('roomId');
  const db = c.env.DB;
  const serverName = c.env.SERVER_NAME;

  const suggestedOnly = c.req.query('suggested_only') === 'true';
  const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
  const from = c.req.query('from');

  // Check if room exists
  const room = await db.prepare(`
    SELECT room_id FROM rooms WHERE room_id = ?
  `).bind(roomId).first();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Parse pagination token
  let offset = 0;
  if (from && from.startsWith('offset_')) {
    offset = parseInt(from.substring(7), 10) || 0;
  }

  // Get space children from m.space.child state events
  const childEvents = await db.prepare(`
    SELECT rs.state_key, e.content
    FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.space.child'
    LIMIT ? OFFSET ?
  `).bind(roomId, limit + 1, offset).all<{ state_key: string; content: string }>();

  const hasMore = childEvents.results.length > limit;
  const childResults = childEvents.results.slice(0, limit);

  const rooms: any[] = [];

  // Add the space itself first (only on first page)
  if (offset === 0) {
    const spaceInfo = await getRoomPublicInfo(db, roomId, serverName);
    if (spaceInfo) {
      const spaceChildState = await db.prepare(`
        SELECT rs.state_key, e.content
        FROM room_state rs
        JOIN events e ON rs.event_id = e.event_id
        WHERE rs.room_id = ? AND rs.event_type = 'm.space.child'
      `).bind(roomId).all<{ state_key: string; content: string }>();

      rooms.push({
        ...spaceInfo,
        children_state: spaceChildState.results.map(ce => {
          try {
            return {
              type: 'm.space.child',
              state_key: ce.state_key,
              content: JSON.parse(ce.content),
            };
          } catch {
            return null;
          }
        }).filter(Boolean),
      });
    }
  }

  // Process each child
  for (const child of childResults) {
    const childRoomId = child.state_key;

    try {
      const content = JSON.parse(child.content);

      // Skip if suggested_only and not suggested
      if (suggestedOnly && !content.suggested) {
        continue;
      }

      // Skip if content has empty via array (deleted child)
      if (!content.via || content.via.length === 0) {
        continue;
      }

      // Get child room info
      const childInfo = await getRoomPublicInfo(db, childRoomId, serverName);
      if (childInfo) {
        rooms.push({
          ...childInfo,
          children_state: [], // Grandchildren not included in federation response
        });
      }
    } catch {
      // Skip invalid child entries
    }
  }

  const response: any = {
    room: rooms[0] || null,
    children: rooms.slice(1),
    inaccessible_children: [],
  };

  if (hasMore) {
    response.next_batch = `offset_${offset + limit}`;
  }

  return c.json(response);
});

// ============================================
// Miscellaneous Federation Endpoints
// ============================================

// GET /_matrix/federation/v1/timestamp_to_event/:roomId - Find event closest to timestamp
app.get('/_matrix/federation/v1/timestamp_to_event/:roomId', async (c) => {
  const roomId = c.req.param('roomId');
  const ts = parseInt(c.req.query('ts') || '0', 10);
  const dir = c.req.query('dir') || 'f'; // 'f' = forward, 'b' = backward
  const db = c.env.DB;

  if (!ts || ts <= 0) {
    return Errors.missingParam('ts').toResponse();
  }

  // Verify room exists
  const room = await db.prepare(
    `SELECT room_id FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  let event;
  if (dir === 'b') {
    // Find closest event at or before timestamp
    event = await db.prepare(`
      SELECT event_id, origin_server_ts
      FROM events
      WHERE room_id = ? AND origin_server_ts <= ?
      ORDER BY origin_server_ts DESC
      LIMIT 1
    `).bind(roomId, ts).first<{ event_id: string; origin_server_ts: number }>();
  } else {
    // Find closest event at or after timestamp
    event = await db.prepare(`
      SELECT event_id, origin_server_ts
      FROM events
      WHERE room_id = ? AND origin_server_ts >= ?
      ORDER BY origin_server_ts ASC
      LIMIT 1
    `).bind(roomId, ts).first<{ event_id: string; origin_server_ts: number }>();
  }

  if (!event) {
    return Errors.notFound('No event found near timestamp').toResponse();
  }

  return c.json({
    event_id: event.event_id,
    origin_server_ts: event.origin_server_ts,
  });
});

// GET /_matrix/federation/v1/openid/userinfo - Validate OpenID token and return user info
app.get('/_matrix/federation/v1/openid/userinfo', async (c) => {
  const accessToken = c.req.query('access_token');

  if (!accessToken) {
    return Errors.missingParam('access_token').toResponse();
  }

  // Look up the OpenID token in KV
  const tokenData = await c.env.SESSIONS.get(`openid:${accessToken}`, 'json') as {
    user_id: string;
    expires_at: number;
  } | null;

  if (!tokenData) {
    return c.json({
      errcode: 'M_UNKNOWN_TOKEN',
      error: 'Invalid or expired OpenID token',
    }, 401);
  }

  // Check if token has expired
  if (Date.now() > tokenData.expires_at) {
    // Clean up expired token
    await c.env.SESSIONS.delete(`openid:${accessToken}`);
    return c.json({
      errcode: 'M_UNKNOWN_TOKEN',
      error: 'OpenID token has expired',
    }, 401);
  }

  return c.json({
    sub: tokenData.user_id,
  });
});

// PUT /_matrix/federation/v1/exchange_third_party_invite/:roomId - Exchange 3PID invite
// Handles third-party invites when a user accepts an invite via their verified email/phone
app.put('/_matrix/federation/v1/exchange_third_party_invite/:roomId', async (c) => {
  const roomId = c.req.param('roomId');
  const db = c.env.DB;
  const serverName = c.env.SERVER_NAME;

  let body: {
    type: string;
    room_id: string;
    sender: string;
    state_key: string;
    content: {
      membership: string;
      third_party_invite?: {
        display_name?: string;
        signed: {
          mxid: string;
          token: string;
          signatures: Record<string, Record<string, string>>;
        };
      };
    };
    origin_server_ts?: number;
    depth?: number;
    auth_events?: string[];
    prev_events?: string[];
    event_id?: string;
    signatures?: Record<string, Record<string, string>>;
  };

  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate this is a membership invite
  if (body.type !== 'm.room.member' || body.content?.membership !== 'invite') {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Event must be a membership invite',
    }, 400);
  }

  // Validate room ID matches
  if (body.room_id !== roomId) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Room ID mismatch',
    }, 400);
  }

  // Validate third_party_invite is present
  const thirdPartyInvite = body.content.third_party_invite;
  if (!thirdPartyInvite || !thirdPartyInvite.signed) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Missing third_party_invite or signed data',
    }, 400);
  }

  const { mxid, token, signatures } = thirdPartyInvite.signed;
  if (!mxid || !token || !signatures) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Incomplete signed data in third_party_invite',
    }, 400);
  }

  // Verify room exists
  const room = await db.prepare(`
    SELECT room_id, room_version FROM rooms WHERE room_id = ?
  `).bind(roomId).first<{ room_id: string; room_version: string }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Find the matching m.room.third_party_invite state event
  const thirdPartyInviteEvent = await db.prepare(`
    SELECT e.event_id, e.content, e.sender, e.state_key
    FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.third_party_invite' AND rs.state_key = ?
  `).bind(roomId, token).first<{
    event_id: string;
    content: string;
    sender: string;
    state_key: string;
  }>();

  if (!thirdPartyInviteEvent) {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'No third party invite found with matching token',
    }, 403);
  }

  // Parse the third-party invite content to get the public keys
  let inviteContent: {
    display_name?: string;
    key_validity_url?: string;
    public_key?: string;
    public_keys?: Array<{ public_key: string; key_validity_url?: string }>;
  };

  try {
    inviteContent = JSON.parse(thirdPartyInviteEvent.content);
  } catch {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'Invalid third party invite content',
    }, 400);
  }

  // Verify the signature against the public keys in the invite
  // The signed object format is: { mxid, sender, token, signatures }
  // where sender is from the original third_party_invite event
  const signedDataForVerification: Record<string, unknown> = {
    mxid,
    sender: thirdPartyInviteEvent.sender,
    token,
    signatures,
  };

  let signatureValid = false;
  const publicKeys = inviteContent.public_keys || [];
  if (inviteContent.public_key) {
    publicKeys.push({ public_key: inviteContent.public_key });
  }

  // Try to verify with each public key
  for (const keyInfo of publicKeys) {
    const publicKey = keyInfo.public_key;
    if (!publicKey) continue;

    // Look for a signature from the identity server
    // Signatures are keyed by server name (typically the identity server)
    for (const [signingServer, keySignatures] of Object.entries(signatures)) {
      for (const [keyId, signature] of Object.entries(keySignatures)) {
        if (!signature) continue;

        try {
          // Verify the Ed25519 signature using the public key from the invite
          const isValid = await verifySignature(
            signedDataForVerification,
            signingServer,
            keyId,
            publicKey
          );

          if (isValid) {
            signatureValid = true;
            break;
          }
        } catch (e) {
          console.warn(`Failed to verify signature from ${signingServer}:${keyId}:`, e);
        }
      }
      if (signatureValid) break;
    }
    if (signatureValid) break;
  }

  if (!signatureValid) {
    return c.json({
      errcode: 'M_FORBIDDEN',
      error: 'Could not verify third party invite signature',
    }, 403);
  }

  // Verify the mxid matches the state_key
  if (mxid !== body.state_key) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'mxid does not match state_key',
    }, 400);
  }

  // Get our signing key
  const key = await db.prepare(
    `SELECT key_id, private_key_jwk FROM server_keys WHERE is_current = 1 AND key_version = 2`
  ).first<{ key_id: string; private_key_jwk: string | null }>();

  if (!key || !key.private_key_jwk) {
    return c.json({
      errcode: 'M_UNKNOWN',
      error: 'Server signing key not configured',
    }, 500);
  }

  // Get auth events for the invite
  const createEvent = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.create'
  `).bind(roomId).first<{ event_id: string }>();

  const joinRulesEvent = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.join_rules'
  `).bind(roomId).first<{ event_id: string }>();

  const powerLevelsEvent = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.power_levels'
  `).bind(roomId).first<{ event_id: string }>();

  const senderMembershipEvent = await db.prepare(`
    SELECT e.event_id FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type = 'm.room.member' AND rs.state_key = ?
  `).bind(roomId, body.sender).first<{ event_id: string }>();

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (joinRulesEvent) authEvents.push(joinRulesEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (senderMembershipEvent) authEvents.push(senderMembershipEvent.event_id);
  authEvents.push(thirdPartyInviteEvent.event_id);

  // Get latest event for prev_events
  const latestEvent = await db.prepare(
    `SELECT event_id, depth FROM events WHERE room_id = ? ORDER BY depth DESC LIMIT 1`
  ).bind(roomId).first<{ event_id: string; depth: number }>();

  const prevEvents = latestEvent ? [latestEvent.event_id] : [];
  const depth = (latestEvent?.depth || 0) + 1;
  const originServerTs = Date.now();

  // Create the invite event
  const inviteEvent = {
    room_id: roomId,
    sender: body.sender,
    type: 'm.room.member',
    state_key: mxid,
    content: {
      membership: 'invite',
      third_party_invite: {
        display_name: inviteContent.display_name || thirdPartyInvite.display_name,
        signed: thirdPartyInvite.signed,
      },
    },
    origin_server_ts: originServerTs,
    depth,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  // Calculate event ID (for room versions 1-3, event_id is computed differently)
  // For room versions 4+, event_id is computed from the content hash
  const eventIdHash = await sha256(JSON.stringify({
    ...inviteEvent,
    origin: serverName,
  }));
  const eventId = body.event_id || `$${eventIdHash}`;

  // Sign the event
  const signedEvent = await signJson(
    { ...inviteEvent, event_id: eventId },
    serverName,
    key.key_id,
    JSON.parse(key.private_key_jwk)
  );

  // Store the event
  try {
    await db.prepare(`
      INSERT OR IGNORE INTO events
      (event_id, room_id, sender, event_type, state_key, content, origin_server_ts, depth, auth_events, prev_events, signatures)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      eventId,
      roomId,
      body.sender,
      'm.room.member',
      mxid,
      JSON.stringify(inviteEvent.content),
      originServerTs,
      depth,
      JSON.stringify(authEvents),
      JSON.stringify(prevEvents),
      JSON.stringify((signedEvent as any).signatures)
    ).run();

    // Update room state
    await db.prepare(`
      INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
      VALUES (?, 'm.room.member', ?, ?)
    `).bind(roomId, mxid, eventId).run();

    // Update memberships table
    await db.prepare(`
      INSERT OR REPLACE INTO room_memberships (room_id, user_id, membership, event_id, display_name)
      VALUES (?, ?, 'invite', ?, ?)
    `).bind(roomId, mxid, eventId, inviteContent.display_name || null).run();

    // Delete the third party invite state event (it's been consumed)
    await db.prepare(`
      DELETE FROM room_state
      WHERE room_id = ? AND event_type = 'm.room.third_party_invite' AND state_key = ?
    `).bind(roomId, token).run();
  } catch (e) {
    console.error('Failed to store third party invite exchange event:', e);
    return c.json({
      errcode: 'M_UNKNOWN',
      error: 'Failed to store invite event',
    }, 500);
  }

  return c.json({});
});

export default app;
