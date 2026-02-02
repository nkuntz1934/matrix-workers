// Cryptographic utilities for Matrix homeserver

import { base64UrlEncode, base64UrlDecode } from './ids';

// Re-export for convenience
export { base64UrlEncode, base64UrlDecode };

// ============================================================================
// Base64 Utilities (Matrix uses unpadded Base64)
// ============================================================================

/**
 * Convert unpadded Base64 string to Uint8Array
 */
export function unpadBase64ToBytes(unpadded: string): Uint8Array {
  // Add padding if needed
  const padded = unpadded + '='.repeat((4 - (unpadded.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * Convert Uint8Array to unpadded Base64 string
 */
export function bytesToUnpadBase64(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  return btoa(binary).replace(/=+$/, '');
}

// ============================================================================
// Ed25519 Cryptographic Operations
// ============================================================================

// Ed25519 algorithm parameters for Cloudflare Workers
// Note: NODE-ED25519 is Cloudflare Workers' proprietary Ed25519 implementation
interface Ed25519Params {
  name: 'NODE-ED25519';
  namedCurve: 'NODE-ED25519';
}

interface Ed25519KeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

/**
 * Generate an Ed25519 key pair for signing
 * Returns keys in formats suitable for Matrix federation:
 * - publicKey: 32-byte raw key as unpadded Base64
 * - privateKey: PKCS8-encoded private key as unpadded Base64
 * - keyId: Matrix key ID format (ed25519:XXXXXXXX)
 */
export async function generateEd25519KeyPair(): Promise<{
  publicKey: string;
  privateKey: string;
  keyId: string;
}> {
  // Generate Ed25519 key pair using Web Crypto API
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true, // extractable
    ['sign', 'verify']
  )) as CryptoKeyPair;

  // Export public key as raw bytes (32 bytes for Ed25519)
  const publicKeyRaw = (await crypto.subtle.exportKey('raw', keyPair.publicKey)) as ArrayBuffer;
  const publicKey = bytesToUnpadBase64(new Uint8Array(publicKeyRaw));

  // Export private key as PKCS8 for storage
  const privateKeyPkcs8 = (await crypto.subtle.exportKey('pkcs8', keyPair.privateKey)) as ArrayBuffer;
  const privateKey = bytesToUnpadBase64(new Uint8Array(privateKeyPkcs8));

  // Generate a random key ID (8 hex characters)
  const keyIdBytes = crypto.getRandomValues(new Uint8Array(4));
  const keyId = `ed25519:${Array.from(keyIdBytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;

  return { publicKey, privateKey, keyId };
}

/**
 * Import an Ed25519 public key from unpadded Base64
 */
export async function importEd25519PublicKey(base64Key: string): Promise<CryptoKey> {
  const keyBytes = unpadBase64ToBytes(base64Key);
  return crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'Ed25519' },
    true,
    ['verify']
  );
}

/**
 * Import an Ed25519 private key from unpadded Base64 (PKCS8 format)
 */
export async function importEd25519PrivateKey(base64Key: string): Promise<CryptoKey> {
  const keyBytes = unpadBase64ToBytes(base64Key);
  return crypto.subtle.importKey(
    'pkcs8',
    keyBytes,
    { name: 'Ed25519' },
    true,
    ['sign']
  );
}

/**
 * Sign data with an Ed25519 private key
 * @param data - Data to sign
 * @param privateKey - CryptoKey or unpadded Base64 PKCS8 private key
 * @returns Signature as unpadded Base64
 */
export async function signEd25519(
  data: Uint8Array,
  privateKey: CryptoKey | string
): Promise<string> {
  const key = typeof privateKey === 'string' ? await importEd25519PrivateKey(privateKey) : privateKey;
  const signature = await crypto.subtle.sign('Ed25519', key, data);
  return bytesToUnpadBase64(new Uint8Array(signature));
}

/**
 * Verify an Ed25519 signature
 * @param data - Original data that was signed
 * @param signature - Signature as unpadded Base64
 * @param publicKey - CryptoKey or unpadded Base64 public key
 * @returns true if signature is valid
 */
export async function verifyEd25519(
  data: Uint8Array,
  signature: string,
  publicKey: CryptoKey | string
): Promise<boolean> {
  const key = typeof publicKey === 'string' ? await importEd25519PublicKey(publicKey) : publicKey;
  const signatureBytes = unpadBase64ToBytes(signature);
  return crypto.subtle.verify('Ed25519', key, signatureBytes, data);
}

// ============================================================================
// Password Hashing
// ============================================================================

// Hash a password using PBKDF2 (Web Crypto compatible alternative to Argon2)
export async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  // Format: $pbkdf2-sha256$iterations$salt$hash
  const saltB64 = btoa(String.fromCharCode(...salt));
  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return `$pbkdf2-sha256$100000$${saltB64}$${hashB64}`;
}

// Verify a password against a hash
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  const parts = storedHash.split('$');
  if (parts.length !== 5 || parts[1] !== 'pbkdf2-sha256') {
    return false;
  }

  const iterations = parseInt(parts[2], 10);
  const salt = Uint8Array.from(atob(parts[3]), c => c.charCodeAt(0));
  const expectedHash = parts[4];

  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );

  const hash = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: iterations,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const hashB64 = btoa(String.fromCharCode(...new Uint8Array(hash)));
  return hashB64 === expectedHash;
}

// SHA-256 hash
export async function sha256(data: string | Uint8Array): Promise<string> {
  const encoder = new TextEncoder();
  const bytes = typeof data === 'string' ? encoder.encode(data) : data;
  const hash = await crypto.subtle.digest('SHA-256', bytes);
  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Hash an access token for storage
export async function hashToken(token: string): Promise<string> {
  return sha256(token);
}

// ============================================================================
// Signing Key Generation (NODE-ED25519 variant for compatibility)
// ============================================================================

// Generate Ed25519 key pair for signing using Cloudflare Workers' NODE-ED25519 algorithm
export async function generateSigningKeyPair(): Promise<{
  publicKey: string;
  privateKeyJwk: JsonWebKey;
  keyId: string;
}> {
  // Generate Ed25519 key pair using Cloudflare Workers' native support
  const keyPair = (await crypto.subtle.generateKey(
    { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
    true, // extractable
    ['sign', 'verify']
  )) as Ed25519KeyPair;

  // Export the public key as JWK to get the raw key bytes
  const publicKeyJwk = (await crypto.subtle.exportKey('jwk', keyPair.publicKey)) as JsonWebKey;
  const privateKeyJwk = (await crypto.subtle.exportKey('jwk', keyPair.privateKey)) as JsonWebKey;

  // Get raw public key bytes from the JWK 'x' parameter
  const publicKeyBytes = base64UrlDecode(publicKeyJwk.x!);

  // Generate key ID from first 4 bytes of public key hash (for uniqueness)
  const keyIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', publicKeyBytes)).slice(
    0,
    4
  );
  const keyId = `ed25519:${Array.from(keyIdHash)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}`;

  return {
    publicKey: base64UrlEncode(publicKeyBytes),
    privateKeyJwk,
    keyId,
  };
}

// Legacy function for backwards compatibility during migration
// Returns the old format but with a proper key
export async function generateSigningKeyPairLegacy(): Promise<{
  publicKey: string;
  privateKey: string;
  keyId: string;
}> {
  const { publicKey, privateKeyJwk, keyId } = await generateSigningKeyPair();
  return {
    publicKey,
    privateKey: JSON.stringify(privateKeyJwk),
    keyId,
  };
}

// ============================================================================
// JSON Signing (supports both key formats)
// ============================================================================

/**
 * Sign a JSON object per Matrix spec
 * @param obj - Object to sign (signatures and unsigned fields will be removed before signing)
 * @param serverName - Server name to attribute signature to
 * @param keyId - Key ID (e.g., "ed25519:abc123")
 * @param privateKey - Private key as unpadded Base64 (PKCS8 format) or JWK
 * @returns Object with signatures field added
 */
export async function signJson(
  obj: Record<string, unknown>,
  serverName: string,
  keyId: string,
  privateKey: string | JsonWebKey
): Promise<Record<string, unknown>> {
  // Remove signatures and unsigned before signing (per Matrix spec)
  const toSign = { ...obj };
  delete toSign['signatures'];
  delete toSign['unsigned'];

  // Get canonical JSON representation
  const canonical = canonicalJson(toSign);
  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);

  let signature: string;

  // Handle both PKCS8 (our format) and JWK (upstream format) private keys
  if (typeof privateKey === 'string') {
    // Check if it's a JSON string (JWK)
    if (privateKey.startsWith('{')) {
      const jwk = JSON.parse(privateKey) as JsonWebKey;
      const key = await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
        false,
        ['sign']
      );
      const signatureBytes = await crypto.subtle.sign({ name: 'NODE-ED25519' }, key, data);
      signature = base64UrlEncode(new Uint8Array(signatureBytes));
    } else {
      // PKCS8 format
      signature = await signEd25519(data, privateKey);
    }
  } else {
    // JWK object
    const key = await crypto.subtle.importKey(
      'jwk',
      privateKey,
      { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
      false,
      ['sign']
    );
    const signatureBytes = await crypto.subtle.sign({ name: 'NODE-ED25519' }, key, data);
    signature = base64UrlEncode(new Uint8Array(signatureBytes));
  }

  // Merge with existing signatures if present
  const existingSignatures = (obj['signatures'] as Record<string, Record<string, string>>) || {};

  return {
    ...obj,
    signatures: {
      ...existingSignatures,
      [serverName]: {
        ...existingSignatures[serverName],
        [keyId]: signature,
      },
    },
  };
}

/**
 * Verify a signature on a JSON object
 * @param obj - Object with signatures field
 * @param serverName - Server name that signed
 * @param keyId - Key ID to verify
 * @param publicKey - Public key as unpadded Base64
 * @returns true if signature is valid
 */
export async function verifyJsonSignature(
  obj: Record<string, unknown>,
  serverName: string,
  keyId: string,
  publicKey: string
): Promise<boolean> {
  const signatures = obj['signatures'] as Record<string, Record<string, string>> | undefined;
  if (!signatures || !signatures[serverName] || !signatures[serverName][keyId]) {
    return false;
  }

  const signature = signatures[serverName][keyId];

  // Remove signatures and unsigned before verifying (per Matrix spec)
  const toVerify = { ...obj };
  delete toVerify['signatures'];
  delete toVerify['unsigned'];

  // Get canonical JSON representation
  const canonical = canonicalJson(toVerify);
  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);

  // Try standard Ed25519 first, then NODE-ED25519
  try {
    return await verifyEd25519(data, signature, publicKey);
  } catch {
    // Fall back to NODE-ED25519 with URL-safe base64
    try {
      const publicKeyBytes = base64UrlDecode(publicKey);
      const key = await crypto.subtle.importKey(
        'raw',
        publicKeyBytes,
        { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
        false,
        ['verify']
      );
      const signatureBytes = base64UrlDecode(signature);
      return await crypto.subtle.verify({ name: 'NODE-ED25519' }, key, signatureBytes, data);
    } catch (error) {
      console.error('Signature verification failed:', error);
      return false;
    }
  }
}

// Alias for compatibility with upstream code
export const verifySignature = verifyJsonSignature;

// Canonical JSON for signing
export function canonicalJson(obj: unknown): string {
  if (obj === null || obj === undefined) {
    return 'null';
  }

  if (typeof obj === 'boolean' || typeof obj === 'number') {
    return JSON.stringify(obj);
  }

  if (typeof obj === 'string') {
    return JSON.stringify(obj);
  }

  if (Array.isArray(obj)) {
    const items = obj.map(item => canonicalJson(item));
    return `[${items.join(',')}]`;
  }

  if (typeof obj === 'object') {
    const keys = Object.keys(obj).sort();
    const pairs = keys.map(key => {
      const value = canonicalJson((obj as Record<string, unknown>)[key]);
      return `${JSON.stringify(key)}:${value}`;
    });
    return `{${pairs.join(',')}}`;
  }

  return 'null';
}

/**
 * Calculate content hash for a Matrix event/PDU.
 * Per Matrix spec, this is SHA-256 of the canonical JSON with
 * 'signatures', 'unsigned', and 'hashes' fields removed.
 *
 * @param event - The event object
 * @returns The SHA-256 hash as unpadded base64
 */
export async function calculateContentHash(event: Record<string, unknown>): Promise<string> {
  // Remove signatures, unsigned, and hashes before hashing (per spec)
  const toHash = { ...event };
  delete toHash['signatures'];
  delete toHash['unsigned'];
  delete toHash['hashes'];

  const canonical = canonicalJson(toHash);

  // Compute SHA-256 and return as unpadded base64 (not URL-safe)
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest('SHA-256', encoder.encode(canonical));
  return bytesToUnpadBase64(new Uint8Array(hash));
}

/**
 * Add the hashes field to an event.
 * Call this when creating events before signing.
 *
 * @param event - The event object (without hashes)
 * @returns The event with hashes.sha256 added
 */
export async function addEventHash<T extends Record<string, unknown>>(
  event: T
): Promise<T & { hashes: { sha256: string } }> {
  const contentHash = await calculateContentHash(event);
  return {
    ...event,
    hashes: { sha256: contentHash },
  };
}

// Verify content hash
export async function verifyContentHash(
  event: Record<string, unknown>,
  expectedHash: string
): Promise<boolean> {
  const actualHash = await calculateContentHash(event);
  return actualHash === expectedHash;
}

// Generate a random string for CSRF tokens, etc.
export function generateRandomString(length: number = 32): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

// ============================================================================
// Federation Request Signing
// ============================================================================

/**
 * Sign a federation request per Matrix spec
 * https://spec.matrix.org/v1.12/server-server-api/#request-authentication
 *
 * @param method - HTTP method (GET, PUT, POST, etc.)
 * @param uri - Request URI path (e.g., /_matrix/federation/v1/send/123)
 * @param origin - Origin server name (this server)
 * @param destination - Destination server name
 * @param keyId - Key ID (e.g., "ed25519:abc123")
 * @param privateKey - Private key as unpadded Base64 (PKCS8 format) or JWK string
 * @param content - Optional request body (for PUT/POST)
 * @returns Authorization header value
 */
export async function signFederationRequest(
  method: string,
  uri: string,
  origin: string,
  destination: string,
  keyId: string,
  privateKey: string,
  content?: Record<string, unknown>
): Promise<string> {
  // Build the object to sign
  const requestObject: Record<string, unknown> = {
    method: method.toUpperCase(),
    uri,
    origin,
    destination,
  };

  // Include content for requests with body
  if (content !== undefined) {
    requestObject.content = content;
  }

  // Get canonical JSON and sign
  const canonical = canonicalJson(requestObject);
  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);

  let signature: string;

  // Handle both PKCS8 and JWK formats
  if (privateKey.startsWith('{')) {
    const jwk = JSON.parse(privateKey) as JsonWebKey;
    const key = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
      false,
      ['sign']
    );
    const signatureBytes = await crypto.subtle.sign({ name: 'NODE-ED25519' }, key, data);
    signature = base64UrlEncode(new Uint8Array(signatureBytes));
  } else {
    signature = await signEd25519(data, privateKey);
  }

  // Build Authorization header
  // Format: X-Matrix origin="${origin}",destination="${destination}",key="${keyId}",sig="${signature}"
  return `X-Matrix origin="${origin}",destination="${destination}",key="${keyId}",sig="${signature}"`;
}

/**
 * Parse an X-Matrix Authorization header
 * @returns Parsed components or null if invalid
 */
export function parseAuthorizationHeader(
  header: string
): { origin: string; destination: string; keyId: string; signature: string } | null {
  if (!header.startsWith('X-Matrix ')) {
    return null;
  }

  const params = header.slice(9); // Remove "X-Matrix "
  const result: Record<string, string> = {};

  // Parse key="value" pairs
  const regex = /(\w+)="([^"]+)"/g;
  let match;
  while ((match = regex.exec(params)) !== null) {
    result[match[1]] = match[2];
  }

  if (!result.origin || !result.destination || !result.key || !result.sig) {
    return null;
  }

  return {
    origin: result.origin,
    destination: result.destination,
    keyId: result.key,
    signature: result.sig,
  };
}

/**
 * Verify a federation request signature
 */
export async function verifyFederationRequest(
  method: string,
  uri: string,
  origin: string,
  destination: string,
  _keyId: string,
  signature: string,
  publicKey: string,
  content?: Record<string, unknown>
): Promise<boolean> {
  // Build the object that was signed
  const requestObject: Record<string, unknown> = {
    method: method.toUpperCase(),
    uri,
    origin,
    destination,
  };

  if (content !== undefined) {
    requestObject.content = content;
  }

  // Get canonical JSON and verify
  const canonical = canonicalJson(requestObject);
  const encoder = new TextEncoder();
  const data = encoder.encode(canonical);

  // Try standard Ed25519 first
  try {
    return await verifyEd25519(data, signature, publicKey);
  } catch {
    // Fall back to NODE-ED25519 with URL-safe base64
    try {
      const publicKeyBytes = base64UrlDecode(publicKey);
      const key = await crypto.subtle.importKey(
        'raw',
        publicKeyBytes,
        { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
        false,
        ['verify']
      );
      const signatureBytes = base64UrlDecode(signature);
      return await crypto.subtle.verify({ name: 'NODE-ED25519' }, key, signatureBytes, data);
    } catch (error) {
      console.error('Federation request verification failed:', error);
      return false;
    }
  }
}
