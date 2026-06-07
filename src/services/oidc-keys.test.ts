import { describe, it, expect } from 'vitest';
import { getOrCreateOidcSigningKey } from './oidc-keys';
import { signIdToken } from './oidc-id-token';

function b64urlToBytes(segment: string): Uint8Array {
  const binary = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function makeKvStub() {
  const store = new Map<string, string>();
  return {
    store,
    get: async (k: string) => (store.has(k) ? store.get(k)! : null),
    put: async (k: string, v: string) => void store.set(k, v),
  };
}

describe('getOrCreateOidcSigningKey', () => {
  it('generates a JWKS-ready RS256 public key on first use', async () => {
    const kv = makeKvStub();
    const key = await getOrCreateOidcSigningKey(kv);

    expect(key.kid).toBeTruthy();
    expect(key.publicKeyJwk).toMatchObject({ kty: 'RSA', use: 'sig', alg: 'RS256', kid: key.kid });
    expect(key.publicKeyJwk.n).toBeTruthy();
    expect(key.publicKeyJwk.e).toBeTruthy();
    // private key never carries private material into the JWKS public copy
    expect(key.publicKeyJwk).not.toHaveProperty('d');
    // it was persisted
    expect(kv.store.has('oidc_signing_key')).toBe(true);
  });

  it('returns the same persisted key on subsequent calls (idempotent)', async () => {
    const kv = makeKvStub();
    const first = await getOrCreateOidcSigningKey(kv);
    const second = await getOrCreateOidcSigningKey(kv);

    expect(second.kid).toBe(first.kid);
    expect(second.publicKeyJwk.n).toBe(first.publicKeyJwk.n);
  });

  it('produces a key whose id_token signature verifies against its own public JWK', async () => {
    const kv = makeKvStub();
    const key = await getOrCreateOidcSigningKey(kv);

    const jwt = await signIdToken({
      issuer: 'https://m.gsudo.net',
      subject: '@admin:m.gsudo.net',
      audience: 'client_abc',
      nowSec: 1_700_000_000,
      expiresInSec: 3600,
      privateKeyJwk: key.privateKeyJwk,
      kid: key.kid,
    });

    const [h, p, s] = jwt.split('.');
    const pub = await crypto.subtle.importKey(
      'jwk',
      // strip the JWKS-only metadata before importing
      { kty: key.publicKeyJwk.kty, n: key.publicKeyJwk.n, e: key.publicKeyJwk.e },
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const ok = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      pub,
      b64urlToBytes(s),
      new TextEncoder().encode(`${h}.${p}`),
    );
    expect(ok).toBe(true);
  });
});
