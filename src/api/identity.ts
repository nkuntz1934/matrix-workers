// Identity Service API
// Implements: https://spec.matrix.org/v1.12/identity-service-api/

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { sha256 } from '../utils/crypto';

const app = new Hono<AppEnv>();

// GET /_matrix/identity/v2 - Status check
app.get('/_matrix/identity/v2', (c) => {
  return c.json({});
});

// GET /_matrix/identity/v2/account - Check if registered
app.get('/_matrix/identity/v2/account', async (c) => {
  const token = extractBearerToken(c.req);
  if (!token) {
    return Errors.missingToken().toResponse();
  }

  // For now, all valid tokens from our homeserver are accepted
  return c.json({ user_id: `@unknown:${c.env.SERVER_NAME}` });
});

// POST /_matrix/identity/v2/account/register - Register with identity server
app.post('/_matrix/identity/v2/account/register', async (c) => {
  let body: { access_token: string; token_type: string; matrix_server_name: string; expires_in: number };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Accept the registration (our IS is integrated with our HS)
  return c.json({ token: body.access_token });
});

// GET /_matrix/identity/v2/terms - Terms of service
app.get('/_matrix/identity/v2/terms', (c) => {
  return c.json({
    policies: {},
  });
});

// POST /_matrix/identity/v2/terms - Accept terms
app.post('/_matrix/identity/v2/terms', (c) => {
  return c.json({});
});

// GET /_matrix/identity/v2/hash_details - Get hash algorithm details
app.get('/_matrix/identity/v2/hash_details', async (c) => {
  // Generate a lookup pepper (rotated periodically)
  const pepper = await getPepper(c.env.CACHE);

  return c.json({
    lookup_pepper: pepper,
    algorithms: ['sha256', 'none'],
  });
});

// POST /_matrix/identity/v2/lookup - Lookup 3PID → MXID
app.post('/_matrix/identity/v2/lookup', async (c) => {
  let body: {
    algorithm: string;
    pepper: string;
    addresses: string[];
  };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { algorithm, pepper, addresses } = body;

  if (!algorithm || !addresses || !Array.isArray(addresses)) {
    return c.json({ errcode: 'M_INVALID_PARAM', error: 'Missing required fields' }, 400);
  }

  const currentPepper = await getPepper(c.env.CACHE);
  if (pepper !== currentPepper) {
    return c.json({
      errcode: 'M_INVALID_PEPPER',
      error: 'Pepper does not match',
      algorithm: 'sha256',
      lookup_pepper: currentPepper,
    }, 400);
  }

  const mappings: Record<string, string> = {};

  if (algorithm === 'sha256') {
    // Addresses are pre-hashed: sha256(address + " " + medium + " " + pepper)
    // Look up all stored associations and hash them to match
    const associations = await c.env.DB.prepare(
      `SELECT medium, address, mxid FROM identity_associations`
    ).all<{ medium: string; address: string; mxid: string }>();

    for (const assoc of associations.results) {
      const hashInput = `${assoc.address} ${assoc.medium} ${pepper}`;
      const hash = await sha256(hashInput);
      if (addresses.includes(hash)) {
        mappings[hash] = assoc.mxid;
      }
    }
  } else if (algorithm === 'none') {
    // Addresses are "address medium" pairs
    for (const addr of addresses) {
      const parts = addr.split(' ');
      if (parts.length >= 2) {
        const address = parts[0];
        const medium = parts[1];
        const result = await c.env.DB.prepare(
          `SELECT mxid FROM identity_associations WHERE medium = ? AND address = ?`
        ).bind(medium, address).first<{ mxid: string }>();

        if (result) {
          mappings[addr] = result.mxid;
        }
      }
    }
  } else {
    return c.json({ errcode: 'M_INVALID_PARAM', error: `Unknown algorithm: ${algorithm}` }, 400);
  }

  return c.json({ mappings });
});

// POST /_matrix/identity/v2/validate/email/requestToken - Request email validation
app.post('/_matrix/identity/v2/validate/email/requestToken', async (c) => {
  let body: { email: string; client_secret: string; send_attempt: number; next_link?: string };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { email, client_secret, send_attempt } = body;

  if (!email || !client_secret) {
    return c.json({ errcode: 'M_MISSING_PARAM', error: 'Missing email or client_secret' }, 400);
  }

  // Generate a session ID and token
  const sessionId = crypto.randomUUID();
  const token = Math.floor(100000 + Math.random() * 900000).toString();

  await c.env.DB.prepare(`
    INSERT INTO email_verification_sessions (session_id, email, client_secret, token, send_attempt, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    sessionId,
    email,
    client_secret,
    token,
    send_attempt,
    Date.now(),
    Date.now() + (24 * 60 * 60 * 1000)
  ).run();

  // TODO: Send email via Cloudflare Email Service (requires EMAIL binding)

  return c.json({ sid: sessionId });
});

// POST /_matrix/identity/v2/validate/email/submitToken - Submit email validation token
app.post('/_matrix/identity/v2/validate/email/submitToken', async (c) => {
  let body: { sid: string; client_secret: string; token: string };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { sid, client_secret, token } = body;

  const session = await c.env.DB.prepare(`
    SELECT session_id, email, client_secret, token, validated, expires_at
    FROM email_verification_sessions
    WHERE session_id = ? AND client_secret = ?
  `).bind(sid, client_secret).first<{
    session_id: string;
    email: string;
    client_secret: string;
    token: string;
    validated: number;
    expires_at: number;
  }>();

  if (!session) {
    return c.json({ errcode: 'M_NO_VALID_SESSION', error: 'Session not found' }, 400);
  }

  if (session.expires_at < Date.now()) {
    return c.json({ errcode: 'M_SESSION_EXPIRED', error: 'Session expired' }, 400);
  }

  if (session.token !== token) {
    return c.json({ errcode: 'M_INVALID_PARAM', error: 'Invalid token' }, 400);
  }

  // Mark as validated
  await c.env.DB.prepare(`
    UPDATE email_verification_sessions SET validated = 1, validated_at = ? WHERE session_id = ?
  `).bind(Date.now(), sid).run();

  return c.json({ success: true });
});

// Helper to get/create lookup pepper
async function getPepper(cache: KVNamespace): Promise<string> {
  const existing = await cache.get('identity:pepper');
  if (existing) return existing;

  const pepper = crypto.randomUUID().replace(/-/g, '');
  await cache.put('identity:pepper', pepper, { expirationTtl: 7 * 24 * 60 * 60 }); // 7 day TTL
  return pepper;
}

// Helper to extract bearer token
function extractBearerToken(req: any): string | null {
  const auth = req.header('Authorization');
  if (auth?.startsWith('Bearer ')) {
    return auth.slice(7);
  }
  return null;
}

export default app;
