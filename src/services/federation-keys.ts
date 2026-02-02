// Federation key fetching and caching service
// Handles fetching, validating, and caching remote server signing keys

import type { Env } from '../types/env';
import { verifyJsonSignature } from '../utils/crypto';

/**
 * Server key response from /_matrix/key/v2/server
 */
export interface ServerKeyResponse {
  server_name: string;
  valid_until_ts: number;
  verify_keys: Record<string, { key: string }>;
  old_verify_keys?: Record<string, { key: string; expired_ts: number }>;
  signatures?: Record<string, Record<string, string>>;
}

/**
 * Cached server keys with metadata
 */
interface CachedServerKeys {
  keys: ServerKeyResponse;
  fetchedAt: number;
}

const CACHE_KEY_PREFIX = 'federation:keys:';
const MIN_CACHE_TTL_SECONDS = 300; // 5 minutes
const MAX_CACHE_TTL_SECONDS = 86400; // 24 hours
const FETCH_TIMEOUT_MS = 10000; // 10 seconds

/**
 * Get server signing keys, using cache when available
 */
export async function getServerKeys(
  env: Env,
  serverName: string
): Promise<ServerKeyResponse | null> {
  const cacheKey = `${CACHE_KEY_PREFIX}${serverName}`;

  // Try cache first
  const cached = (await env.CACHE.get(cacheKey, 'json')) as CachedServerKeys | null;
  if (cached && cached.keys.valid_until_ts > Date.now()) {
    return cached.keys;
  }

  // Fetch fresh keys
  const keys = await fetchServerKeys(serverName);
  if (!keys) {
    // If fetch failed but we have stale cached keys, return them
    if (cached) {
      console.warn(`Failed to fetch keys for ${serverName}, using stale cache`);
      return cached.keys;
    }
    return null;
  }

  // Validate the key response is self-signed
  const isValid = await validateServerKeyResponse(keys);
  if (!isValid) {
    console.error(`Invalid server key response from ${serverName}: signature verification failed`);
    if (cached) {
      return cached.keys;
    }
    return null;
  }

  // Cache the keys
  const ttlSeconds = calculateCacheTtl(keys.valid_until_ts);
  await env.CACHE.put(
    cacheKey,
    JSON.stringify({ keys, fetchedAt: Date.now() } as CachedServerKeys),
    { expirationTtl: ttlSeconds }
  );

  return keys;
}

/**
 * Fetch server keys from remote server
 */
export async function fetchServerKeys(serverName: string): Promise<ServerKeyResponse | null> {
  const url = `https://${serverName}/_matrix/key/v2/server`;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    const response = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      console.error(`Failed to fetch keys from ${serverName}: ${response.status}`);
      return null;
    }

    const keys = (await response.json()) as ServerKeyResponse;

    // Basic validation
    if (!keys.server_name || !keys.verify_keys || !keys.valid_until_ts) {
      console.error(`Invalid key response from ${serverName}: missing required fields`);
      return null;
    }

    if (keys.server_name !== serverName) {
      console.error(`Server name mismatch: expected ${serverName}, got ${keys.server_name}`);
      return null;
    }

    return keys;
  } catch (error) {
    if (error instanceof Error && error.name === 'AbortError') {
      console.error(`Timeout fetching keys from ${serverName}`);
    } else {
      console.error(`Error fetching keys from ${serverName}:`, error);
    }
    return null;
  }
}

/**
 * Validate that a server key response is properly self-signed
 */
export async function validateServerKeyResponse(response: ServerKeyResponse): Promise<boolean> {
  if (!response.signatures || !response.signatures[response.server_name]) {
    console.error(`Server key response from ${response.server_name} has no self-signature`);
    return false;
  }

  const serverSignatures = response.signatures[response.server_name];

  // Verify at least one signature from verify_keys
  for (const [keyId, { key: publicKey }] of Object.entries(response.verify_keys)) {
    if (serverSignatures[keyId]) {
      try {
        const valid = await verifyJsonSignature(
          response as unknown as Record<string, unknown>,
          response.server_name,
          keyId,
          publicKey
        );
        if (valid) {
          return true;
        }
      } catch (error) {
        console.error(`Error verifying signature with key ${keyId}:`, error);
      }
    }
  }

  // Also check old_verify_keys for signature verification
  if (response.old_verify_keys) {
    for (const [keyId, { key: publicKey }] of Object.entries(response.old_verify_keys)) {
      if (serverSignatures[keyId]) {
        try {
          const valid = await verifyJsonSignature(
            response as unknown as Record<string, unknown>,
            response.server_name,
            keyId,
            publicKey
          );
          if (valid) {
            return true;
          }
        } catch (error) {
          console.error(`Error verifying signature with old key ${keyId}:`, error);
        }
      }
    }
  }

  return false;
}

/**
 * Get a specific public key for a server
 */
export async function getServerPublicKey(
  env: Env,
  serverName: string,
  keyId: string
): Promise<string | null> {
  const keys = await getServerKeys(env, serverName);
  if (!keys) {
    return null;
  }

  // Check current verify_keys
  if (keys.verify_keys[keyId]) {
    return keys.verify_keys[keyId].key;
  }

  // Check old_verify_keys (for verifying old events)
  if (keys.old_verify_keys && keys.old_verify_keys[keyId]) {
    return keys.old_verify_keys[keyId].key;
  }

  return null;
}

/**
 * Calculate cache TTL based on valid_until_ts
 */
function calculateCacheTtl(validUntilTs: number): number {
  const remainingMs = validUntilTs - Date.now();
  const remainingSeconds = Math.floor(remainingMs / 1000);

  return Math.max(MIN_CACHE_TTL_SECONDS, Math.min(remainingSeconds, MAX_CACHE_TTL_SECONDS));
}

/**
 * Result of PDU signature verification
 */
export interface SignatureVerificationResult {
  valid: boolean;
  error?: string;
  keyId?: string;
}

/**
 * Verify signatures on a PDU from a remote server
 */
export async function verifyPduSignature(
  env: Env,
  pdu: Record<string, unknown>,
  originServer: string
): Promise<SignatureVerificationResult> {
  const signatures = pdu.signatures as Record<string, Record<string, string>> | undefined;

  if (!signatures) {
    return { valid: false, error: 'PDU has no signatures' };
  }

  const serverSignatures = signatures[originServer];
  if (!serverSignatures) {
    return { valid: false, error: `PDU has no signature from origin server ${originServer}` };
  }

  // Get server keys
  const serverKeys = await getServerKeys(env, originServer);
  if (!serverKeys) {
    return { valid: false, error: `Failed to fetch keys for server ${originServer}` };
  }

  // Try each signature from the origin server
  for (const keyId of Object.keys(serverSignatures)) {
    // Get the public key
    const publicKey = await getServerPublicKey(env, originServer, keyId);
    if (!publicKey) {
      console.warn(`Key ${keyId} not found for server ${originServer}`);
      continue;
    }

    try {
      const valid = await verifyJsonSignature(pdu, originServer, keyId, publicKey);
      if (valid) {
        return { valid: true, keyId };
      }
    } catch (error) {
      console.error(`Error verifying PDU signature with key ${keyId}:`, error);
    }
  }

  return { valid: false, error: 'No valid signature found' };
}
