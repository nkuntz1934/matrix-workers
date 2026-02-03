// Cryptographic utilities for Matrix homeserver

import { base64UrlEncode, base64UrlDecode } from './ids';

// Re-export for convenience
export { base64UrlEncode, base64UrlDecode };

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

// Sign a JSON object with Ed25519 per Matrix spec
export async function signJson(
  obj: Record<string, unknown>,
  serverName: string,
  keyId: string,
  privateKeyJwk: JsonWebKey | string
): Promise<Record<string, unknown>> {
  // Parse JWK if passed as string (for backwards compatibility)
  const jwk: JsonWebKey =
    typeof privateKeyJwk === 'string' ? JSON.parse(privateKeyJwk) : privateKeyJwk;

  // Remove signatures and unsigned before signing (per Matrix spec)
  const toSign = { ...obj };
  delete toSign['signatures'];
  delete toSign['unsigned'];

  // Import the private key
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
    false,
    ['sign']
  );

  // Get canonical JSON representation
  const canonical = canonicalJson(toSign);

  // Sign the canonical JSON
  const signatureBytes = await crypto.subtle.sign(
    { name: 'NODE-ED25519' },
    privateKey,
    new TextEncoder().encode(canonical)
  );

  // Encode signature as unpadded base64
  const signatureB64 = base64UrlEncode(new Uint8Array(signatureBytes));

  // Merge with existing signatures if present
  const existingSignatures = (obj.signatures as Record<string, Record<string, string>>) || {};

  return {
    ...obj,
    signatures: {
      ...existingSignatures,
      [serverName]: {
        ...(existingSignatures[serverName] || {}),
        [keyId]: signatureB64,
      },
    },
  };
}

// Verify an Ed25519 signature on a JSON object
export async function verifySignature(
  obj: Record<string, unknown>,
  serverName: string,
  keyId: string,
  publicKeyB64: string
): Promise<boolean> {
  try {
    // Get the signature
    const signatures = obj.signatures as Record<string, Record<string, string>> | undefined;
    const signature = signatures?.[serverName]?.[keyId];
    if (!signature) {
      return false;
    }

    // Remove signatures and unsigned before verifying
    const toVerify = { ...obj };
    delete toVerify['signatures'];
    delete toVerify['unsigned'];

    // Decode the public key
    const publicKeyBytes = base64UrlDecode(publicKeyB64);

    // Import the public key
    const publicKey = await crypto.subtle.importKey(
      'raw',
      publicKeyBytes,
      { name: 'NODE-ED25519', namedCurve: 'NODE-ED25519' } as Ed25519Params,
      false,
      ['verify']
    );

    // Decode the signature
    const signatureBytes = base64UrlDecode(signature);

    // Get canonical JSON
    const canonical = canonicalJson(toVerify);

    // Verify the signature
    return await crypto.subtle.verify(
      { name: 'NODE-ED25519' },
      publicKey,
      signatureBytes,
      new TextEncoder().encode(canonical)
    );
  } catch (error) {
    console.error('Signature verification failed:', error);
    return false;
  }
}

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

// Calculate content hash for PDU
export async function calculateContentHash(content: Record<string, unknown>): Promise<string> {
  // Remove signatures and unsigned before hashing
  const toHash = { ...content };
  delete toHash['signatures'];
  delete toHash['unsigned'];

  const canonical = canonicalJson(toHash);
  return sha256(canonical);
}

// Verify content hash
export async function verifyContentHash(
  content: Record<string, unknown>,
  expectedHash: string
): Promise<boolean> {
  const actualHash = await calculateContentHash(content);
  return actualHash === expectedHash;
}

// Generate a random string for CSRF tokens, etc.
export function generateRandomString(length: number = 32): string {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charsLen = chars.length; // 62 characters
  // Use rejection sampling to avoid modulo bias
  // 256 % 62 = 8, so we reject values >= 248 to ensure uniform distribution
  const maxValid = 256 - (256 % charsLen); // 248
  const result: string[] = [];
  
  while (result.length < length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length - result.length));
    for (const b of bytes) {
      if (b < maxValid && result.length < length) {
        result.push(chars[b % charsLen]);
      }
    }
  }
  
  return result.join('');
}
