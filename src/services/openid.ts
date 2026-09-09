import type { Env } from '../types';

export interface OpenIDIdentity {
  user_id: string;
  expires_at: number;
  device_id?: string | null;
}

// Use the same namespace and key as /user/:userId/openid/request_token.
// KV expiry is not sufficient on its own: reject expired or malformed records too.
export async function getOpenIDIdentity(
  env: Env,
  accessToken: string,
): Promise<OpenIDIdentity | null> {
  const data = await env.CACHE.get<OpenIDIdentity>(`openid_token:${accessToken}`, 'json');
  if (!data || typeof data.user_id !== 'string' || !data.user_id.startsWith('@') ||
      data.user_id.indexOf(':') <= 1 ||
      data.user_id.slice(data.user_id.indexOf(':') + 1) !== env.SERVER_NAME ||
      !Number.isFinite(data.expires_at) || data.expires_at <= Date.now()) {
    return null;
  }
  return data;
}
