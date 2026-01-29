// Federation Key Management Service
// Handles fetching, caching, and validating remote server signing keys
// Includes notary support for key query endpoints

import { verifySignature, signJson, base64UrlDecode } from '../utils/crypto';
import { discoverServer, buildServerUrl } from './server-discovery';

export interface ServerKeyResponse {
  server_name: string;
  valid_until_ts: number;
  verify_keys: Record<string, { key: string }>;
  old_verify_keys?: Record<string, { key: string; expired_ts?: number }>;
  signatures?: Record<string, Record<string, string>>;
  [key: string]: unknown; // Index signature for Record<string, unknown> compatibility
}

interface RemoteServerKey {
  server_name: string;
  key_id: string;
  public_key: string;
  valid_from: number;
  valid_until: number | null;
  fetched_at: number;
  verified: boolean;
}

// Cache TTL for remote server keys (5 minutes for KV, longer in D1)
const KEY_CACHE_TTL = 5 * 60;

/**
 * Fetch and cache a remote server's signing keys
 */
export async function fetchRemoteServerKeys(
  serverName: string,
  db: D1Database,
  cache: KVNamespace
): Promise<RemoteServerKey[]> {
  const cacheKey = `federation:keys:${serverName}`;

  // Check KV cache first
  const cached = await cache.get(cacheKey);
  if (cached) {
    return JSON.parse(cached);
  }

  // Check D1 cache for non-expired keys
  const dbKeys = await db
    .prepare(
      `SELECT server_name, key_id, public_key, valid_from, valid_until, fetched_at, verified
       FROM remote_server_keys
       WHERE server_name = ? AND (valid_until IS NULL OR valid_until > ?)`
    )
    .bind(serverName, Date.now())
    .all<RemoteServerKey>();

  // If we have recent keys in D1 (fetched within last hour), use them
  const recentKeys = dbKeys.results.filter((k) => k.fetched_at > Date.now() - 60 * 60 * 1000);
  if (recentKeys.length > 0) {
    await cache.put(cacheKey, JSON.stringify(recentKeys), { expirationTtl: KEY_CACHE_TTL });
    return recentKeys;
  }

  // Fetch fresh keys from remote server
  try {
    const keys = await fetchKeysFromRemote(serverName, cache);

    // Store in D1
    for (const key of keys) {
      await db
        .prepare(
          `INSERT OR REPLACE INTO remote_server_keys
           (server_name, key_id, public_key, valid_from, valid_until, fetched_at, verified)
           VALUES (?, ?, ?, ?, ?, ?, ?)`
        )
        .bind(
          key.server_name,
          key.key_id,
          key.public_key,
          key.valid_from,
          key.valid_until,
          key.fetched_at,
          key.verified ? 1 : 0
        )
        .run();
    }

    // Cache in KV
    await cache.put(cacheKey, JSON.stringify(keys), { expirationTtl: KEY_CACHE_TTL });

    return keys;
  } catch (error) {
    console.error(`Failed to fetch keys from ${serverName}:`, error);

    // Fall back to D1 cache even if stale
    if (dbKeys.results.length > 0) {
      return dbKeys.results;
    }

    throw new Error(`Cannot fetch signing keys from ${serverName}`);
  }
}

/**
 * Fetch keys directly from a remote Matrix server
 */
async function fetchKeysFromRemote(
  serverName: string,
  cache?: KVNamespace
): Promise<RemoteServerKey[]> {
  // Use the new server discovery service
  const discovery = await discoverServer(serverName, cache);
  const serverUrl = buildServerUrl(discovery);

  const response = await fetch(`${serverUrl}/_matrix/key/v2/server`, {
    headers: {
      Accept: 'application/json',
    },
    cf: {
      // Cache at edge for 5 minutes
      cacheTtl: 300,
      cacheEverything: true,
    },
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from ${serverName}`);
  }

  const keyResponse: ServerKeyResponse = await response.json();

  // Validate the response has the expected server name
  if (keyResponse.server_name !== serverName) {
    throw new Error(`Server name mismatch: expected ${serverName}, got ${keyResponse.server_name}`);
  }

  const keys: RemoteServerKey[] = [];
  const now = Date.now();

  // Process current keys
  for (const [keyId, keyData] of Object.entries(keyResponse.verify_keys || {})) {
    // Validate key format (should be base64url-encoded 32 bytes for Ed25519)
    try {
      const keyBytes = base64UrlDecode(keyData.key);
      if (keyBytes.length !== 32) {
        console.warn(`Invalid key length for ${serverName}:${keyId}: ${keyBytes.length}`);
        continue;
      }
    } catch {
      console.warn(`Invalid key format for ${serverName}:${keyId}`);
      continue;
    }

    // Verify self-signature if present
    let verified = false;
    if (keyResponse.signatures?.[serverName]?.[keyId]) {
      try {
        verified = await verifySignature(keyResponse, serverName, keyId, keyData.key);
        if (!verified) {
          console.warn(`Self-signature verification failed for ${serverName}:${keyId}`);
        }
      } catch (error) {
        console.warn(`Error verifying signature for ${serverName}:${keyId}:`, error);
      }
    }

    keys.push({
      server_name: serverName,
      key_id: keyId,
      public_key: keyData.key,
      valid_from: now,
      valid_until: keyResponse.valid_until_ts || null,
      fetched_at: now,
      verified,
    });
  }

  // Process old keys (for verifying historical signatures)
  for (const [keyId, keyData] of Object.entries(keyResponse.old_verify_keys || {})) {
    try {
      const keyBytes = base64UrlDecode(keyData.key);
      if (keyBytes.length !== 32) continue;
    } catch {
      continue;
    }

    keys.push({
      server_name: serverName,
      key_id: keyId,
      public_key: keyData.key,
      valid_from: 0,
      valid_until: keyData.expired_ts || now,
      fetched_at: now,
      verified: false, // Old keys don't need self-signature verification
    });
  }

  if (keys.length === 0) {
    throw new Error(`No valid keys found for ${serverName}`);
  }

  return keys;
}

/**
 * Fetch the raw key response from a remote server (for notary use)
 * Returns the full ServerKeyResponse including signatures
 */
export async function fetchRawServerKeyResponse(
  serverName: string,
  cache?: KVNamespace
): Promise<ServerKeyResponse | null> {
  try {
    const discovery = await discoverServer(serverName, cache);
    const serverUrl = buildServerUrl(discovery);

    const response = await fetch(`${serverUrl}/_matrix/key/v2/server`, {
      headers: {
        Accept: 'application/json',
      },
      cf: {
        cacheTtl: 300,
        cacheEverything: true,
      },
    });

    if (!response.ok) {
      return null;
    }

    const keyResponse: ServerKeyResponse = await response.json();

    // Validate server name matches
    if (keyResponse.server_name !== serverName) {
      console.warn(`Server name mismatch: expected ${serverName}, got ${keyResponse.server_name}`);
      return null;
    }

    return keyResponse;
  } catch (error) {
    console.error(`Failed to fetch raw keys from ${serverName}:`, error);
    return null;
  }
}

/**
 * Get remote server keys with notary signature
 * Fetches keys from remote server, verifies them, and adds our notary signature
 */
export async function getRemoteKeysWithNotarySignature(
  serverName: string,
  keyId: string | null,
  minimumValidUntilTs: number,
  db: D1Database,
  cache: KVNamespace,
  notaryServerName: string,
  notaryKeyId: string,
  notaryPrivateKey: JsonWebKey
): Promise<ServerKeyResponse[]> {
  // Check cache first for keys meeting validity requirement
  const cacheKey = `notary:keys:${serverName}:${keyId || 'all'}`;
  const cached = await cache.get(cacheKey);

  if (cached) {
    const cachedResponses: ServerKeyResponse[] = JSON.parse(cached);
    // Check if cached keys meet validity requirement
    const validCached = cachedResponses.filter(
      (r) => r.valid_until_ts >= minimumValidUntilTs
    );
    if (validCached.length > 0) {
      return validCached;
    }
  }

  // Fetch fresh keys from remote server
  const remoteResponse = await fetchRawServerKeyResponse(serverName, cache);

  if (!remoteResponse) {
    // If we can't fetch, try to use D1 cached keys
    const dbKeys = await fetchRemoteServerKeys(serverName, db, cache);
    if (dbKeys.length > 0) {
      // Build a response from cached keys (without remote signatures)
      const verifyKeys: Record<string, { key: string }> = {};
      let maxValidUntil = 0;

      for (const key of dbKeys) {
        if (keyId && key.key_id !== keyId) continue;
        verifyKeys[key.key_id] = { key: key.public_key };
        if (key.valid_until && key.valid_until > maxValidUntil) {
          maxValidUntil = key.valid_until;
        }
      }

      if (Object.keys(verifyKeys).length === 0) {
        return [];
      }

      const response: ServerKeyResponse = {
        server_name: serverName,
        valid_until_ts: maxValidUntil || Date.now() + 24 * 60 * 60 * 1000,
        verify_keys: verifyKeys,
        old_verify_keys: {},
      };

      // Add notary signature
      const signed = (await signJson(
        response,
        notaryServerName,
        notaryKeyId,
        notaryPrivateKey
      )) as ServerKeyResponse;

      return [signed];
    }

    return [];
  }

  // Verify remote server's self-signature on at least one key
  let hasValidSignature = false;
  for (const [verifyKeyId, keyData] of Object.entries(remoteResponse.verify_keys || {})) {
    if (remoteResponse.signatures?.[serverName]?.[verifyKeyId]) {
      try {
        const verified = await verifySignature(
          remoteResponse,
          serverName,
          verifyKeyId,
          keyData.key
        );
        if (verified) {
          hasValidSignature = true;
          break;
        }
      } catch (error) {
        console.warn(`Failed to verify signature for ${serverName}:${verifyKeyId}:`, error);
      }
    }
  }

  if (!hasValidSignature) {
    console.warn(`No valid self-signature found for ${serverName}`);
    // Still return the keys but log the warning
  }

  // Filter to requested key if specified
  let responseToSign = remoteResponse;
  if (keyId) {
    const specificKey = remoteResponse.verify_keys[keyId];
    if (!specificKey) {
      // Check old_verify_keys
      const oldKey = remoteResponse.old_verify_keys?.[keyId];
      if (!oldKey) {
        return [];
      }
      // Return with old key
      responseToSign = {
        server_name: serverName,
        valid_until_ts: remoteResponse.valid_until_ts,
        verify_keys: {},
        old_verify_keys: { [keyId]: oldKey },
        signatures: remoteResponse.signatures,
      };
    } else {
      responseToSign = {
        server_name: serverName,
        valid_until_ts: remoteResponse.valid_until_ts,
        verify_keys: { [keyId]: specificKey },
        old_verify_keys: {},
        signatures: remoteResponse.signatures,
      };
    }
  }

  // Add our notary signature
  const signed = (await signJson(
    responseToSign,
    notaryServerName,
    notaryKeyId,
    notaryPrivateKey
  )) as ServerKeyResponse;

  // Cache the signed response
  await cache.put(cacheKey, JSON.stringify([signed]), {
    expirationTtl: KEY_CACHE_TTL,
  });

  return [signed];
}

/**
 * Get a specific key for a server by key ID
 */
export async function getRemoteServerKey(
  serverName: string,
  keyId: string,
  db: D1Database,
  cache: KVNamespace
): Promise<RemoteServerKey | null> {
  const keys = await fetchRemoteServerKeys(serverName, db, cache);
  return keys.find((k) => k.key_id === keyId) || null;
}

/**
 * Verify a signature from a remote server
 */
export async function verifyRemoteSignature(
  obj: Record<string, unknown>,
  serverName: string,
  keyId: string,
  db: D1Database,
  cache: KVNamespace
): Promise<boolean> {
  const key = await getRemoteServerKey(serverName, keyId, db, cache);
  if (!key) {
    console.warn(`No key found for ${serverName}:${keyId}`);
    return false;
  }

  // Check key validity
  if (key.valid_until && key.valid_until < Date.now()) {
    console.warn(`Key ${serverName}:${keyId} has expired`);
    // Still try to verify - the key might have been valid when the signature was made
  }

  return verifySignature(obj, serverName, keyId, key.public_key);
}

// --- Outgoing Request Signing ---

export interface SigningKey {
  keyId: string;
  privateKeyJwk: JsonWebKey;
}

/**
 * Get the current server signing key for outgoing requests
 */
export async function getServerSigningKey(db: D1Database): Promise<SigningKey | null> {
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

/**
 * Build the X-Matrix authorization header for outgoing federation requests
 *
 * Per Matrix spec, the Authorization header format is:
 * X-Matrix origin=<origin>,destination=<destination>,key=<key_id>,sig=<signature>
 *
 * The signature is computed over a JSON object containing:
 * {
 *   "method": "GET" or "POST" etc,
 *   "uri": "/path/to/endpoint",
 *   "origin": "sending.server.name",
 *   "destination": "receiving.server.name",
 *   "content": { ... } // Only for POST/PUT requests with body
 * }
 */
export async function signFederationRequest(
  method: string,
  uri: string,
  origin: string,
  destination: string,
  signingKey: SigningKey,
  content?: unknown
): Promise<string> {
  // Build the request object to sign
  const requestObj: Record<string, unknown> = {
    method,
    uri,
    origin,
    destination,
  };

  // Only include content for requests with body
  if (content !== undefined && content !== null) {
    requestObj.content = content;
  }

  // Sign the request object
  const signed = await signJson(
    requestObj,
    origin,
    signingKey.keyId,
    signingKey.privateKeyJwk
  );

  // Extract the signature
  const signature = (signed.signatures as Record<string, Record<string, string>>)?.[origin]?.[signingKey.keyId];

  if (!signature) {
    throw new Error('Failed to sign federation request');
  }

  // Build the Authorization header
  // Format: X-Matrix origin="sending.server",destination="receiving.server",key="ed25519:abc",sig="base64sig"
  return `X-Matrix origin="${origin}",destination="${destination}",key="${signingKey.keyId}",sig="${signature}"`;
}

/**
 * Make an authenticated federation request to a remote server
 */
export async function makeFederationRequest(
  method: string,
  serverName: string,
  path: string,
  localServerName: string,
  signingKey: SigningKey,
  cache: KVNamespace,
  body?: unknown
): Promise<Response> {
  // Discover the remote server's endpoint
  const discovery = await discoverServer(serverName, cache);
  const serverUrl = buildServerUrl(discovery);

  // Build the full URI (path only, not full URL)
  const uri = path;

  // Sign the request
  const authHeader = await signFederationRequest(
    method,
    uri,
    localServerName,
    serverName,
    signingKey,
    body
  );

  // Make the request
  const options: RequestInit = {
    method,
    headers: {
      'Authorization': authHeader,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  };

  if (body !== undefined && body !== null) {
    options.body = JSON.stringify(body);
  }

  return fetch(`${serverUrl}${path}`, options);
}

/**
 * Helper to make a GET request to a remote federation server
 */
export async function federationGet(
  serverName: string,
  path: string,
  localServerName: string,
  db: D1Database,
  cache: KVNamespace
): Promise<Response> {
  const signingKey = await getServerSigningKey(db);
  if (!signingKey) {
    throw new Error('Server signing key not configured');
  }

  return makeFederationRequest('GET', serverName, path, localServerName, signingKey, cache);
}

/**
 * Helper to make a POST request to a remote federation server
 */
export async function federationPost(
  serverName: string,
  path: string,
  body: unknown,
  localServerName: string,
  db: D1Database,
  cache: KVNamespace
): Promise<Response> {
  const signingKey = await getServerSigningKey(db);
  if (!signingKey) {
    throw new Error('Server signing key not configured');
  }

  return makeFederationRequest('POST', serverName, path, localServerName, signingKey, cache, body);
}

/**
 * Helper to make a PUT request to a remote federation server
 */
export async function federationPut(
  serverName: string,
  path: string,
  body: unknown,
  localServerName: string,
  db: D1Database,
  cache: KVNamespace
): Promise<Response> {
  const signingKey = await getServerSigningKey(db);
  if (!signingKey) {
    throw new Error('Server signing key not configured');
  }

  return makeFederationRequest('PUT', serverName, path, localServerName, signingKey, cache, body);
}
