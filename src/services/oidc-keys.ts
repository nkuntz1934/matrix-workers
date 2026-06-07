// RS256 signing key for the OAuth provider's OIDC id_tokens.
//
// Generated once on first use and persisted in KV (mirrors how the Matrix server
// signing key is auto-provisioned). The public half is published at the JWKS
// endpoint so clients like Element Web/Desktop can verify id_tokens. See
// oidc-id-token.ts for the signing itself.

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Minimal KV surface this module needs (satisfied by Cloudflare KVNamespace). */
export interface KVLike {
  get(key: string): Promise<string | null>;
  put(key: string, value: string): Promise<void>;
}

export interface PublicJwk {
  kty: string;
  n: string;
  e: string;
  use: 'sig';
  alg: 'RS256';
  kid: string;
}

export interface OidcSigningKey {
  privateKeyJwk: JsonWebKey;
  publicKeyJwk: PublicJwk;
  kid: string;
}

const STORAGE_KEY = 'oidc_signing_key';

async function computeKid(publicKeyJwk: JsonWebKey): Promise<string> {
  const material = new TextEncoder().encode(`${publicKeyJwk.n}.${publicKeyJwk.e}`);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
  return base64UrlEncode(digest).slice(0, 16);
}

/**
 * Load the OIDC signing key from KV, generating and persisting it on first use.
 * Idempotent: subsequent calls return the same key.
 */
export async function getOrCreateOidcSigningKey(kv: KVLike): Promise<OidcSigningKey> {
  const existing = await kv.get(STORAGE_KEY);
  if (existing) return JSON.parse(existing) as OidcSigningKey;

  const pair = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;

  const privateKeyJwk = (await crypto.subtle.exportKey('jwk', pair.privateKey)) as JsonWebKey;
  const rawPublicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as JsonWebKey;
  const kid = await computeKid(rawPublicJwk);

  const publicKeyJwk: PublicJwk = {
    kty: rawPublicJwk.kty as string,
    n: rawPublicJwk.n as string,
    e: rawPublicJwk.e as string,
    use: 'sig',
    alg: 'RS256',
    kid,
  };

  const key: OidcSigningKey = { privateKeyJwk, publicKeyJwk, kid };
  await kv.put(STORAGE_KEY, JSON.stringify(key));
  return key;
}
