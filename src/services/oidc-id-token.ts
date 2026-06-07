// OIDC id_token issuance for the OAuth provider.
//
// Element X (Rust SDK / MSC3861 pure OAuth2) is happy with just an access token,
// but Element Web/Desktop (oidc-client-ts) require a signed `id_token` whenever the
// `openid` scope is requested, and verify it against the keys at `jwks_uri`. Without
// it they fail authentication after a successful token exchange. This module signs
// the id_token; see oidc-keys.ts for the RS256 signing key + JWKS.

function base64UrlEncode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlEncodeString(value: string): string {
  return base64UrlEncode(new TextEncoder().encode(value));
}

export interface IdTokenParams {
  issuer: string;
  subject: string;
  audience: string;
  nowSec: number;
  expiresInSec: number;
  privateKeyJwk: JsonWebKey;
  kid: string;
  nonce?: string;
  atHash?: string;
}

/** Build and RS256-sign an OIDC id_token. Returns the compact JWT string. */
export async function signIdToken(params: IdTokenParams): Promise<string> {
  const header = { alg: 'RS256', typ: 'JWT', kid: params.kid };

  const payload: Record<string, unknown> = {
    iss: params.issuer,
    sub: params.subject,
    aud: params.audience,
    iat: params.nowSec,
    exp: params.nowSec + params.expiresInSec,
  };
  if (params.nonce) payload.nonce = params.nonce;
  if (params.atHash) payload.at_hash = params.atHash;

  const signingInput =
    `${base64UrlEncodeString(JSON.stringify(header))}.${base64UrlEncodeString(JSON.stringify(payload))}`;

  const key = await crypto.subtle.importKey(
    'jwk',
    params.privateKeyJwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    key,
    new TextEncoder().encode(signingInput),
  );

  return `${signingInput}.${base64UrlEncode(new Uint8Array(signature))}`;
}
