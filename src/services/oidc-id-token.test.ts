import { describe, it, expect } from 'vitest';
import { signIdToken } from './oidc-id-token';

function b64urlToString(segment: string): string {
  return atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
}

function b64urlToBytes(segment: string): Uint8Array {
  const binary = atob(segment.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

async function generateRsaKeyPair() {
  const kp = (await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )) as CryptoKeyPair;
  return {
    privateKeyJwk: (await crypto.subtle.exportKey('jwk', kp.privateKey)) as JsonWebKey,
    publicKeyJwk: (await crypto.subtle.exportKey('jwk', kp.publicKey)) as JsonWebKey,
  };
}

describe('signIdToken', () => {
  it('produces an RS256 JWT with the required OIDC claims and a verifiable signature', async () => {
    const { privateKeyJwk, publicKeyJwk } = await generateRsaKeyPair();
    const nowSec = 1_700_000_000;

    const jwt = await signIdToken({
      issuer: 'https://m.gsudo.net',
      subject: '@admin:m.gsudo.net',
      audience: 'client_abc',
      nonce: 'n-123',
      nowSec,
      expiresInSec: 3600,
      privateKeyJwk,
      kid: 'kid-1',
    });

    const [headerB64, payloadB64, signatureB64] = jwt.split('.');
    expect(signatureB64, 'JWT must have three segments').toBeTruthy();

    const header = JSON.parse(b64urlToString(headerB64));
    const payload = JSON.parse(b64urlToString(payloadB64));

    // OIDC-required header
    expect(header).toMatchObject({ alg: 'RS256', typ: 'JWT', kid: 'kid-1' });

    // OIDC-required claims (the bits Element Web/Desktop validate)
    expect(payload).toMatchObject({
      iss: 'https://m.gsudo.net',
      sub: '@admin:m.gsudo.net',
      aud: 'client_abc',
      nonce: 'n-123',
      iat: nowSec,
      exp: nowSec + 3600,
    });

    // Signature must verify against the public key
    const publicKey = await crypto.subtle.importKey(
      'jwk',
      publicKeyJwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
    const verified = await crypto.subtle.verify(
      'RSASSA-PKCS1-v1_5',
      publicKey,
      b64urlToBytes(signatureB64),
      new TextEncoder().encode(`${headerB64}.${payloadB64}`),
    );
    expect(verified, 'id_token signature must verify against the JWKS public key').toBe(true);
  });

  it('omits the nonce claim when no nonce was provided', async () => {
    const { privateKeyJwk } = await generateRsaKeyPair();
    const jwt = await signIdToken({
      issuer: 'https://m.gsudo.net',
      subject: '@admin:m.gsudo.net',
      audience: 'client_abc',
      nowSec: 1_700_000_000,
      expiresInSec: 3600,
      privateKeyJwk,
      kid: 'kid-1',
    });
    const payload = JSON.parse(b64urlToString(jwt.split('.')[1]));
    expect(payload).not.toHaveProperty('nonce');
  });
});
