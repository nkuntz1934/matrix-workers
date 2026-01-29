// OAuth 2.0 Provider for Matrix OIDC-native authentication
// Implements RFC 6749 (OAuth 2.0), RFC 7636 (PKCE), RFC 7591 (Dynamic Client Registration)
// and Matrix-specific extensions (MSC2965, MSC3861)

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { requireAuth } from '../middleware/auth';
import { hashToken, verifyPassword } from '../utils/crypto';
import { generateAccessToken, generateDeviceId, generateOpaqueId, formatUserId } from '../utils/ids';
import { createDevice, createAccessToken, getUserById } from '../services/database';

const app = new Hono<AppEnv>();

// ============================================
// Types
// ============================================

interface OAuthClient {
  client_id: string;
  client_secret_hash: string | null;
  client_name: string;
  redirect_uris: string[];
  grant_types: string[];
  response_types: string[];
  token_endpoint_auth_method: string;
  created_at: number;
}

interface AuthorizationCode {
  code: string;
  client_id: string;
  user_id: string;
  redirect_uri: string;
  scope: string;
  code_challenge?: string;
  code_challenge_method?: string;
  nonce?: string;
  created_at: number;
  expires_at: number;
}

interface OAuthToken {
  token_id: string;
  access_token_hash: string;
  refresh_token_hash?: string;
  client_id: string;
  user_id: string;
  device_id: string;
  scope: string;
  created_at: number;
  expires_at: number;
}

// ============================================
// Helper Functions
// ============================================

// Generate a cryptographically secure random string
function generateRandomString(length: number = 32): string {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

// Base64URL encode
function base64UrlEncode(data: Uint8Array): string {
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Base64URL decode (for future JWT parsing)
function base64UrlDecode(str: string): Uint8Array {
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

// Verify PKCE code challenge
async function verifyCodeChallenge(
  codeVerifier: string,
  codeChallenge: string,
  method: string
): Promise<boolean> {
  if (method === 'plain') {
    return codeVerifier === codeChallenge;
  } else if (method === 'S256') {
    const encoder = new TextEncoder();
    const data = encoder.encode(codeVerifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const computed = base64UrlEncode(new Uint8Array(hash));
    return computed === codeChallenge;
  }
  return false;
}

// Hash a client secret
async function hashClientSecret(secret: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(secret);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(new Uint8Array(hash));
}

// ============================================
// Dynamic Client Registration (RFC 7591)
// ============================================

// POST /oauth/register - Register a new OAuth client
app.post('/oauth/register', async (c) => {
  let body: {
    client_name?: string;
    redirect_uris?: string[];
    grant_types?: string[];
    response_types?: string[];
    token_endpoint_auth_method?: string;
    application_type?: string;
    contacts?: string[];
    logo_uri?: string;
    client_uri?: string;
    policy_uri?: string;
    tos_uri?: string;
  };

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: 'invalid_request', error_description: 'Invalid JSON body' }, 400);
  }

  // Validate required fields
  if (!body.redirect_uris || body.redirect_uris.length === 0) {
    return c.json({ error: 'invalid_client_metadata', error_description: 'redirect_uris is required' }, 400);
  }

  // Generate client credentials
  const clientId = `client_${generateRandomString(16)}`;
  const clientSecret = generateRandomString(32);
  const clientSecretHash = await hashClientSecret(clientSecret);

  // Default values
  const grantTypes = body.grant_types || ['authorization_code'];
  const responseTypes = body.response_types || ['code'];
  const tokenEndpointAuthMethod = body.token_endpoint_auth_method || 'client_secret_basic';

  // Store client in KV
  const client: OAuthClient = {
    client_id: clientId,
    client_secret_hash: tokenEndpointAuthMethod === 'none' ? null : clientSecretHash,
    client_name: body.client_name || 'Unknown Client',
    redirect_uris: body.redirect_uris,
    grant_types: grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: tokenEndpointAuthMethod,
    created_at: Date.now(),
  };

  await c.env.CACHE.put(`oauth_client:${clientId}`, JSON.stringify(client), {
    expirationTtl: 365 * 24 * 60 * 60, // 1 year
  });

  // Return client registration response
  const response: Record<string, unknown> = {
    client_id: clientId,
    client_name: client.client_name,
    redirect_uris: client.redirect_uris,
    grant_types: client.grant_types,
    response_types: client.response_types,
    token_endpoint_auth_method: client.token_endpoint_auth_method,
    client_id_issued_at: Math.floor(client.created_at / 1000),
  };

  // Only include client_secret if using secret-based auth
  if (tokenEndpointAuthMethod !== 'none') {
    response.client_secret = clientSecret;
    response.client_secret_expires_at = 0; // Never expires
  }

  return c.json(response, 201);
});

// ============================================
// Authorization Endpoint (RFC 6749 Section 4.1.1)
// ============================================

// GET /oauth/authorize - Show authorization page
app.get('/oauth/authorize', async (c) => {
  const clientId = c.req.query('client_id');
  const redirectUri = c.req.query('redirect_uri');
  const responseType = c.req.query('response_type');
  const scope = c.req.query('scope') || 'openid';
  const state = c.req.query('state');
  const nonce = c.req.query('nonce');
  const codeChallenge = c.req.query('code_challenge');
  const codeChallengeMethod = c.req.query('code_challenge_method') || 'plain';

  // Validate required parameters
  if (!clientId) {
    return c.json({ error: 'invalid_request', error_description: 'client_id is required' }, 400);
  }
  if (!redirectUri) {
    return c.json({ error: 'invalid_request', error_description: 'redirect_uri is required' }, 400);
  }
  if (responseType !== 'code') {
    return c.json({ error: 'unsupported_response_type', error_description: 'Only code response type is supported' }, 400);
  }

  // Validate client
  const clientJson = await c.env.CACHE.get(`oauth_client:${clientId}`);
  if (!clientJson) {
    return c.json({ error: 'invalid_client', error_description: 'Unknown client' }, 400);
  }

  const client: OAuthClient = JSON.parse(clientJson);

  // Validate redirect URI
  if (!client.redirect_uris.includes(redirectUri)) {
    return c.json({ error: 'invalid_request', error_description: 'Invalid redirect_uri' }, 400);
  }

  // Store authorization request in session
  const authRequestId = generateRandomString(16);
  await c.env.SESSIONS.put(`oauth_auth_request:${authRequestId}`, JSON.stringify({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope,
    state,
    nonce,
    code_challenge: codeChallenge,
    code_challenge_method: codeChallengeMethod,
  }), { expirationTtl: 600 }); // 10 minutes

  // Return login page
  return c.html(generateLoginPage(client.client_name, authRequestId, c.env.SERVER_NAME));
});

// POST /oauth/authorize - Handle login form submission
app.post('/oauth/authorize', async (c) => {
  const formData = await c.req.formData();
  const username = formData.get('username') as string;
  const password = formData.get('password') as string;
  const authRequestId = formData.get('auth_request_id') as string;

  if (!username || !password || !authRequestId) {
    return c.html(generateLoginPage('', authRequestId || '', c.env.SERVER_NAME, 'Missing username or password'));
  }

  // Get authorization request
  const authRequestJson = await c.env.SESSIONS.get(`oauth_auth_request:${authRequestId}`);
  if (!authRequestJson) {
    return c.json({ error: 'invalid_request', error_description: 'Authorization request expired' }, 400);
  }

  const authRequest = JSON.parse(authRequestJson);
  await c.env.SESSIONS.delete(`oauth_auth_request:${authRequestId}`);

  // Authenticate user
  const userId = formatUserId(username, c.env.SERVER_NAME);
  const user = await c.env.DB.prepare(
    'SELECT user_id, password_hash FROM users WHERE user_id = ? AND is_deactivated = 0'
  ).bind(userId).first<{ user_id: string; password_hash: string | null }>();

  if (!user || !user.password_hash) {
    // Get client name for error page
    const clientJson = await c.env.CACHE.get(`oauth_client:${authRequest.client_id}`);
    const clientName = clientJson ? JSON.parse(clientJson).client_name : 'Unknown Client';
    
    // Re-create auth request for retry
    const newAuthRequestId = generateRandomString(16);
    await c.env.SESSIONS.put(`oauth_auth_request:${newAuthRequestId}`, JSON.stringify(authRequest), { expirationTtl: 600 });
    
    return c.html(generateLoginPage(clientName, newAuthRequestId, c.env.SERVER_NAME, 'Invalid username or password'));
  }

  const passwordValid = await verifyPassword(password, user.password_hash);
  if (!passwordValid) {
    const clientJson = await c.env.CACHE.get(`oauth_client:${authRequest.client_id}`);
    const clientName = clientJson ? JSON.parse(clientJson).client_name : 'Unknown Client';
    
    const newAuthRequestId = generateRandomString(16);
    await c.env.SESSIONS.put(`oauth_auth_request:${newAuthRequestId}`, JSON.stringify(authRequest), { expirationTtl: 600 });
    
    return c.html(generateLoginPage(clientName, newAuthRequestId, c.env.SERVER_NAME, 'Invalid username or password'));
  }

  // Generate authorization code
  const code = generateRandomString(32);
  const authCode: AuthorizationCode = {
    code,
    client_id: authRequest.client_id,
    user_id: userId,
    redirect_uri: authRequest.redirect_uri,
    scope: authRequest.scope,
    code_challenge: authRequest.code_challenge,
    code_challenge_method: authRequest.code_challenge_method,
    nonce: authRequest.nonce,
    created_at: Date.now(),
    expires_at: Date.now() + 10 * 60 * 1000, // 10 minutes
  };

  await c.env.SESSIONS.put(`oauth_code:${code}`, JSON.stringify(authCode), { expirationTtl: 600 });

  // Redirect back to client with authorization code
  const redirectUrl = new URL(authRequest.redirect_uri);
  redirectUrl.searchParams.set('code', code);
  if (authRequest.state) {
    redirectUrl.searchParams.set('state', authRequest.state);
  }

  return c.redirect(redirectUrl.toString());
});

// ============================================
// Token Endpoint (RFC 6749 Section 4.1.3)
// ============================================

// POST /oauth/token - Exchange authorization code for tokens
app.post('/oauth/token', async (c) => {
  // Parse request body (form-urlencoded)
  const contentType = c.req.header('Content-Type') || '';
  let params: Record<string, string> = {};

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await c.req.formData();
    for (const [key, value] of formData.entries()) {
      params[key] = value as string;
    }
  } else if (contentType.includes('application/json')) {
    params = await c.req.json();
  } else {
    return c.json({ error: 'invalid_request', error_description: 'Unsupported content type' }, 400);
  }

  const grantType = params.grant_type;
  const clientId = params.client_id;
  const clientSecret = params.client_secret;
  const code = params.code;
  const redirectUri = params.redirect_uri;
  const codeVerifier = params.code_verifier;
  const refreshToken = params.refresh_token;

  // Check for client authentication in Authorization header
  let headerClientId: string | undefined;
  let headerClientSecret: string | undefined;
  const authHeader = c.req.header('Authorization');
  if (authHeader?.startsWith('Basic ')) {
    const decoded = atob(authHeader.slice(6));
    const [id, secret] = decoded.split(':');
    headerClientId = decodeURIComponent(id);
    headerClientSecret = decodeURIComponent(secret);
  }

  const effectiveClientId = clientId || headerClientId;
  const effectiveClientSecret = clientSecret || headerClientSecret;

  if (!effectiveClientId) {
    return c.json({ error: 'invalid_client', error_description: 'client_id is required' }, 400);
  }

  // Get client
  const clientJson = await c.env.CACHE.get(`oauth_client:${effectiveClientId}`);
  if (!clientJson) {
    return c.json({ error: 'invalid_client', error_description: 'Unknown client' }, 401);
  }

  const client: OAuthClient = JSON.parse(clientJson);

  // Verify client secret if required
  if (client.client_secret_hash && client.token_endpoint_auth_method !== 'none') {
    if (!effectiveClientSecret) {
      return c.json({ error: 'invalid_client', error_description: 'client_secret is required' }, 401);
    }
    const secretHash = await hashClientSecret(effectiveClientSecret);
    if (secretHash !== client.client_secret_hash) {
      return c.json({ error: 'invalid_client', error_description: 'Invalid client credentials' }, 401);
    }
  }

  if (grantType === 'authorization_code') {
    if (!code) {
      return c.json({ error: 'invalid_request', error_description: 'code is required' }, 400);
    }

    // Get and validate authorization code
    const authCodeJson = await c.env.SESSIONS.get(`oauth_code:${code}`);
    if (!authCodeJson) {
      return c.json({ error: 'invalid_grant', error_description: 'Invalid or expired authorization code' }, 400);
    }

    const authCode: AuthorizationCode = JSON.parse(authCodeJson);

    // Delete code (one-time use)
    await c.env.SESSIONS.delete(`oauth_code:${code}`);

    // Validate code
    if (authCode.client_id !== effectiveClientId) {
      return c.json({ error: 'invalid_grant', error_description: 'Code was not issued to this client' }, 400);
    }
    if (authCode.expires_at < Date.now()) {
      return c.json({ error: 'invalid_grant', error_description: 'Authorization code has expired' }, 400);
    }
    if (redirectUri && authCode.redirect_uri !== redirectUri) {
      return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
    }

    // Verify PKCE if code challenge was provided
    if (authCode.code_challenge) {
      if (!codeVerifier) {
        return c.json({ error: 'invalid_request', error_description: 'code_verifier is required' }, 400);
      }
      const valid = await verifyCodeChallenge(codeVerifier, authCode.code_challenge, authCode.code_challenge_method || 'plain');
      if (!valid) {
        return c.json({ error: 'invalid_grant', error_description: 'Invalid code_verifier' }, 400);
      }
    }

    // Generate tokens
    const accessToken = await generateAccessToken();
    const newRefreshToken = generateRandomString(32);
    const deviceId = await generateDeviceId();
    const tokenId = await generateOpaqueId(16);

    // Create device and access token in database
    await createDevice(c.env.DB, authCode.user_id, deviceId, `OAuth Client (${client.client_name})`);
    const tokenHash = await hashToken(accessToken);
    await createAccessToken(c.env.DB, tokenId, tokenHash, authCode.user_id, deviceId);

    // Store refresh token
    const oauthToken: OAuthToken = {
      token_id: tokenId,
      access_token_hash: tokenHash,
      refresh_token_hash: await hashClientSecret(newRefreshToken),
      client_id: effectiveClientId,
      user_id: authCode.user_id,
      device_id: deviceId,
      scope: authCode.scope,
      created_at: Date.now(),
      expires_at: Date.now() + 24 * 60 * 60 * 1000, // 24 hours
    };

    await c.env.SESSIONS.put(`oauth_refresh:${newRefreshToken}`, JSON.stringify(oauthToken), {
      expirationTtl: 30 * 24 * 60 * 60, // 30 days
    });

    return c.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 86400, // 24 hours
      refresh_token: newRefreshToken,
      scope: authCode.scope,
      // Matrix-specific fields
      user_id: authCode.user_id,
      device_id: deviceId,
    });

  } else if (grantType === 'refresh_token') {
    if (!refreshToken) {
      return c.json({ error: 'invalid_request', error_description: 'refresh_token is required' }, 400);
    }

    // Get refresh token data
    const tokenDataJson = await c.env.SESSIONS.get(`oauth_refresh:${refreshToken}`);
    if (!tokenDataJson) {
      return c.json({ error: 'invalid_grant', error_description: 'Invalid refresh token' }, 400);
    }

    const tokenData: OAuthToken = JSON.parse(tokenDataJson);

    // Validate client
    if (tokenData.client_id !== effectiveClientId) {
      return c.json({ error: 'invalid_grant', error_description: 'Token was not issued to this client' }, 400);
    }

    // Generate new tokens
    const newAccessToken = await generateAccessToken();
    const newRefreshToken = generateRandomString(32);
    const newTokenId = await generateOpaqueId(16);

    // Update access token in database
    const newTokenHash = await hashToken(newAccessToken);
    await createAccessToken(c.env.DB, newTokenId, newTokenHash, tokenData.user_id, tokenData.device_id);

    // Delete old refresh token and create new one
    await c.env.SESSIONS.delete(`oauth_refresh:${refreshToken}`);

    const newOauthToken: OAuthToken = {
      token_id: newTokenId,
      access_token_hash: newTokenHash,
      refresh_token_hash: await hashClientSecret(newRefreshToken),
      client_id: effectiveClientId,
      user_id: tokenData.user_id,
      device_id: tokenData.device_id,
      scope: tokenData.scope,
      created_at: Date.now(),
      expires_at: Date.now() + 24 * 60 * 60 * 1000,
    };

    await c.env.SESSIONS.put(`oauth_refresh:${newRefreshToken}`, JSON.stringify(newOauthToken), {
      expirationTtl: 30 * 24 * 60 * 60,
    });

    return c.json({
      access_token: newAccessToken,
      token_type: 'Bearer',
      expires_in: 86400,
      refresh_token: newRefreshToken,
      scope: tokenData.scope,
    });

  } else {
    return c.json({ error: 'unsupported_grant_type', error_description: 'Only authorization_code and refresh_token grants are supported' }, 400);
  }
});

// ============================================
// UserInfo Endpoint (OpenID Connect Core)
// ============================================

// Helper to build userinfo response
async function buildUserInfoResponse(c: any, userId: string) {
  const user = await getUserById(c.env.DB, userId);

  if (!user) {
    return c.json({ error: 'invalid_token', error_description: 'User not found' }, 401);
  }

  return c.json({
    sub: user.user_id,
    name: user.display_name,
    picture: user.avatar_url,
    // Matrix extension
    'urn:matrix:user_id': user.user_id,
  });
}

// GET /oauth/userinfo - Get user information
app.get('/oauth/userinfo', requireAuth(), async (c) => {
  return buildUserInfoResponse(c, c.get('userId'));
});

// POST /oauth/userinfo - Same as GET (some clients use POST)
app.post('/oauth/userinfo', requireAuth(), async (c) => {
  return buildUserInfoResponse(c, c.get('userId'));
});

// ============================================
// Token Revocation (RFC 7009)
// ============================================

// POST /oauth/revoke - Revoke a token
app.post('/oauth/revoke', async (c) => {
  const contentType = c.req.header('Content-Type') || '';
  let params: Record<string, string> = {};

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await c.req.formData();
    for (const [key, value] of formData.entries()) {
      params[key] = value as string;
    }
  } else if (contentType.includes('application/json')) {
    params = await c.req.json();
  }

  const token = params.token;
  const tokenTypeHint = params.token_type_hint;

  if (!token) {
    return c.json({ error: 'invalid_request', error_description: 'token is required' }, 400);
  }

  // Try to revoke as refresh token
  if (!tokenTypeHint || tokenTypeHint === 'refresh_token') {
    const deleted = await c.env.SESSIONS.delete(`oauth_refresh:${token}`);
    if (deleted !== undefined) {
      return new Response(null, { status: 200 });
    }
  }

  // Try to revoke as access token (delete from database)
  if (!tokenTypeHint || tokenTypeHint === 'access_token') {
    const tokenHash = await hashToken(token);
    await c.env.DB.prepare(
      'DELETE FROM access_tokens WHERE token_hash = ?'
    ).bind(tokenHash).run();
  }

  // RFC 7009 says to return 200 even if token doesn't exist
  return new Response(null, { status: 200 });
});

// ============================================
// Token Introspection (RFC 7662)
// ============================================

// POST /oauth/introspect - Introspect a token
app.post('/oauth/introspect', async (c) => {
  const contentType = c.req.header('Content-Type') || '';
  let params: Record<string, string> = {};

  if (contentType.includes('application/x-www-form-urlencoded')) {
    const formData = await c.req.formData();
    for (const [key, value] of formData.entries()) {
      params[key] = value as string;
    }
  } else if (contentType.includes('application/json')) {
    params = await c.req.json();
  }

  const token = params.token;

  if (!token) {
    return c.json({ error: 'invalid_request', error_description: 'token is required' }, 400);
  }

  // Check if it looks like a JWT (has 3 base64url-encoded parts)
  const jwtParts = token.split('.');
  if (jwtParts.length === 3) {
    try {
      // Decode the payload (second part) to extract claims
      const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(jwtParts[1])));
      
      // Check if expired
      if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
        return c.json({ active: false });
      }
      
      return c.json({
        active: true,
        sub: payload.sub,
        client_id: payload.client_id || payload.azp,
        token_type: 'Bearer',
        exp: payload.exp,
        iat: payload.iat,
        scope: payload.scope,
        iss: payload.iss,
      });
    } catch {
      // Not a valid JWT, fall through to database check
    }
  }

  // Check if it's an access token in the database
  const tokenHash = await hashToken(token);
  const accessToken = await c.env.DB.prepare(
    'SELECT user_id, device_id, created_at FROM access_tokens WHERE token_hash = ?'
  ).bind(tokenHash).first<{ user_id: string; device_id: string; created_at: number }>();

  if (accessToken) {
    return c.json({
      active: true,
      sub: accessToken.user_id,
      client_id: 'unknown', // We don't track this for all tokens
      token_type: 'Bearer',
      iat: Math.floor(accessToken.created_at / 1000),
    });
  }

  // Token not found or invalid
  return c.json({ active: false });
});

// ============================================
// Login Page HTML
// ============================================

function generateLoginPage(clientName: string, authRequestId: string, serverName: string, error?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign in - ${serverName}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: #1e293b;
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 400px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid #334155;
    }
    .logo {
      text-align: center;
      margin-bottom: 24px;
    }
    .logo svg {
      width: 48px;
      height: 48px;
    }
    h1 {
      color: #f1f5f9;
      font-size: 24px;
      text-align: center;
      margin-bottom: 8px;
    }
    .subtitle {
      color: #94a3b8;
      text-align: center;
      margin-bottom: 32px;
      font-size: 14px;
    }
    .client-name {
      color: #0d9488;
      font-weight: 500;
    }
    .error {
      background: #7f1d1d;
      color: #fecaca;
      padding: 12px 16px;
      border-radius: 8px;
      margin-bottom: 24px;
      font-size: 14px;
    }
    .form-group {
      margin-bottom: 20px;
    }
    label {
      display: block;
      color: #94a3b8;
      margin-bottom: 8px;
      font-size: 14px;
      font-weight: 500;
    }
    input[type="text"], input[type="password"] {
      width: 100%;
      padding: 12px 16px;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #f1f5f9;
      font-size: 16px;
      transition: border-color 0.2s, box-shadow 0.2s;
    }
    input[type="text"]:focus, input[type="password"]:focus {
      outline: none;
      border-color: #0d9488;
      box-shadow: 0 0 0 3px rgba(13, 148, 136, 0.2);
    }
    input::placeholder {
      color: #64748b;
    }
    button {
      width: 100%;
      padding: 14px;
      background: #0d9488;
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: background-color 0.2s;
    }
    button:hover {
      background: #0f766e;
    }
    button:active {
      transform: translateY(1px);
    }
    .footer {
      margin-top: 24px;
      text-align: center;
      color: #64748b;
      font-size: 12px;
    }
    .server-name {
      color: #94a3b8;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <svg viewBox="0 0 24 24" fill="none" stroke="#0d9488" stroke-width="2">
        <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/>
      </svg>
    </div>
    <h1>Sign in</h1>
    <p class="subtitle">to continue to <span class="client-name">${escapeHtml(clientName)}</span></p>
    
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    
    <form method="POST" action="/oauth/authorize">
      <input type="hidden" name="auth_request_id" value="${escapeHtml(authRequestId)}">
      
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="Enter your username" required autocomplete="username" autofocus>
      </div>
      
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="current-password">
      </div>
      
      <button type="submit">Sign in</button>
    </form>
    
    <div class="footer">
      Signing in to <span class="server-name">${escapeHtml(serverName)}</span>
    </div>
  </div>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ============================================
// OAuth UIA (User-Interactive Auth) for Cross-Signing
// Per MSC3861/MSC2967, OIDC users use m.login.oauth for UIA
// ============================================

// GET /oauth/authorize/uia - Show approval page for UIA operations (e.g., cross-signing reset)
app.get('/oauth/authorize/uia', async (c) => {
  const sessionId = c.req.query('session');
  const action = c.req.query('action');
  const serverName = c.env.SERVER_NAME;

  if (!sessionId) {
    return c.html(generateUiaErrorPage('Missing Session', 'No UIA session specified.', serverName));
  }

  // Check if the UIA session exists
  const sessionJson = await c.env.CACHE.get(`uia_session:${sessionId}`);
  if (!sessionJson) {
    return c.html(generateUiaErrorPage('Session Expired', 'This session has expired. Please try again.', serverName));
  }

  const session = JSON.parse(sessionJson);

  // Determine what action is being requested
  let actionTitle = 'Approve Request';
  let actionDescription = 'An application is requesting your approval.';
  
  if (action === 'org.matrix.cross_signing_reset') {
    actionTitle = 'Reset Encryption Keys';
    actionDescription = 'An application is requesting to reset your encryption identity. This will allow you to set up encryption again, but you may lose access to old encrypted messages.';
  }

  // Generate approval page
  return c.html(generateUiaApprovalPage(sessionId, session.user_id, actionTitle, actionDescription, serverName));
});

// POST /oauth/authorize/uia - Handle approval
app.post('/oauth/authorize/uia', async (c) => {
  const serverName = c.env.SERVER_NAME;

  let body: any;
  try {
    body = await c.req.parseBody();
  } catch {
    return c.html(generateUiaErrorPage('Invalid Request', 'Could not parse request.', serverName));
  }

  const { session: sessionId, username, password, action: submitAction } = body;

  if (!sessionId) {
    return c.html(generateUiaErrorPage('Missing Session', 'No UIA session specified.', serverName));
  }

  // Check if the UIA session exists
  const sessionJson = await c.env.CACHE.get(`uia_session:${sessionId}`);
  if (!sessionJson) {
    return c.html(generateUiaErrorPage('Session Expired', 'This session has expired. Please try again.', serverName));
  }

  const session = JSON.parse(sessionJson);

  // Handle cancel action
  if (submitAction === 'cancel') {
    await c.env.CACHE.delete(`uia_session:${sessionId}`);
    return c.html(generateUiaCancelledPage(serverName));
  }

  // Validate credentials
  if (!username || !password) {
    return c.html(generateUiaApprovalPage(
      sessionId, 
      session.user_id, 
      'Reset Encryption Keys',
      'Please enter your credentials to approve this request.',
      serverName,
      'Username and password are required.'
    ));
  }

  // Verify the credentials
  const db = c.env.DB;
  const userId = formatUserId(username, serverName);
  
  // Check user exists
  const user = await getUserById(db, userId);
  if (!user) {
    return c.html(generateUiaApprovalPage(
      sessionId,
      session.user_id,
      'Reset Encryption Keys',
      'Please enter your credentials to approve this request.',
      serverName,
      'Invalid username or password.'
    ));
  }

  // Verify password
  const passwordHash = await db.prepare(`
    SELECT password_hash FROM users WHERE user_id = ?
  `).bind(userId).first<{ password_hash: string }>();

  if (!passwordHash?.password_hash) {
    // User might be OIDC-only - check if they have an IdP link
    const idpLink = await db.prepare(`
      SELECT COUNT(*) as count FROM idp_user_links WHERE user_id = ?
    `).bind(userId).first<{ count: number }>();

    if ((idpLink?.count || 0) > 0) {
      // OIDC user - just verify the user ID matches the session
      if (userId !== session.user_id) {
        return c.html(generateUiaApprovalPage(
          sessionId,
          session.user_id,
          'Reset Encryption Keys',
          'Please enter your credentials to approve this request.',
          serverName,
          'You must approve with the same account that started this request.'
        ));
      }
    } else {
      return c.html(generateUiaApprovalPage(
        sessionId,
        session.user_id,
        'Reset Encryption Keys',
        'Please enter your credentials to approve this request.',
        serverName,
        'Invalid username or password.'
      ));
    }
  } else {
    // Verify password
    const valid = await verifyPassword(password, passwordHash.password_hash);
    if (!valid) {
      return c.html(generateUiaApprovalPage(
        sessionId,
        session.user_id,
        'Reset Encryption Keys',
        'Please enter your credentials to approve this request.',
        serverName,
        'Invalid username or password.'
      ));
    }
  }

  // Verify user matches session
  if (userId !== session.user_id) {
    return c.html(generateUiaApprovalPage(
      sessionId,
      session.user_id,
      'Reset Encryption Keys',
      'Please enter your credentials to approve this request.',
      serverName,
      'You must approve with the same account that started this request.'
    ));
  }

  // Mark the cross-signing reset as approved per MSC4312
  // Use org.matrix.cross_signing_reset (unstable) as the primary marker
  // Also mark m.oauth (stable) and legacy m.login.oauth for compatibility
  session.completed_stages = session.completed_stages || [];
  const stagesToMark = ['org.matrix.cross_signing_reset', 'm.oauth', 'm.login.oauth'];
  for (const stage of stagesToMark) {
    if (!session.completed_stages.includes(stage)) {
      session.completed_stages.push(stage);
    }
  }
  session.oauth_completed_at = Date.now();

  // Save updated session
  await c.env.CACHE.put(`uia_session:${sessionId}`, JSON.stringify(session), { expirationTtl: 300 });

  console.log('[oauth/uia] OAuth UIA completed for session:', sessionId, 'user:', userId);

  // Show success page
  return c.html(generateUiaSuccessPage(sessionId, serverName));
});

// Generate UIA approval page
function generateUiaApprovalPage(
  sessionId: string, 
  userId: string, 
  title: string, 
  description: string, 
  serverName: string,
  error?: string
): string {
  const localpart = userId.split(':')[0].substring(1); // Extract localpart from @user:server
  
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - ${escapeHtml(serverName)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #f1f5f9;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: #1e293b;
      border-radius: 16px;
      padding: 40px;
      max-width: 440px;
      width: 100%;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid #334155;
    }
    .icon {
      width: 64px;
      height: 64px;
      background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
      border-radius: 16px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
    }
    .icon svg { width: 32px; height: 32px; color: white; }
    h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; text-align: center; }
    .description { color: #94a3b8; margin-bottom: 24px; text-align: center; line-height: 1.6; }
    .warning {
      background: rgba(245, 158, 11, 0.1);
      border: 1px solid rgba(245, 158, 11, 0.3);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 24px;
      color: #fbbf24;
      font-size: 14px;
    }
    .error {
      background: rgba(239, 68, 68, 0.1);
      border: 1px solid rgba(239, 68, 68, 0.3);
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 16px;
      color: #f87171;
      font-size: 14px;
    }
    .form-group { margin-bottom: 16px; }
    label { display: block; margin-bottom: 6px; color: #94a3b8; font-size: 14px; }
    input {
      width: 100%;
      padding: 12px 16px;
      background: #0f172a;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #f1f5f9;
      font-size: 16px;
      outline: none;
      transition: border-color 0.2s;
    }
    input:focus { border-color: #3b82f6; }
    .buttons { display: flex; gap: 12px; margin-top: 24px; }
    button {
      flex: 1;
      padding: 12px 24px;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.2s;
      border: none;
    }
    .btn-primary {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: white;
    }
    .btn-primary:hover { transform: translateY(-1px); box-shadow: 0 4px 12px rgba(59, 130, 246, 0.4); }
    .btn-secondary {
      background: transparent;
      border: 1px solid #475569;
      color: #94a3b8;
    }
    .btn-secondary:hover { background: rgba(71, 85, 105, 0.3); }
    .account-info {
      background: #0f172a;
      border-radius: 8px;
      padding: 12px 16px;
      margin-bottom: 24px;
      font-size: 14px;
      color: #94a3b8;
    }
    .account-info strong { color: #f1f5f9; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    </div>
    
    <h1>${escapeHtml(title)}</h1>
    <p class="description">${escapeHtml(description)}</p>
    
    <div class="warning">
      ⚠️ This is a sensitive operation. Please verify this is what you intended.
    </div>

    <div class="account-info">
      Approving as: <strong>${escapeHtml(userId)}</strong>
    </div>
    
    ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
    
    <form method="POST" action="/oauth/authorize/uia">
      <input type="hidden" name="session" value="${escapeHtml(sessionId)}">
      
      <div class="form-group">
        <label for="username">Username</label>
        <input type="text" id="username" name="username" placeholder="Enter your username" value="${escapeHtml(localpart)}" required autocomplete="username">
      </div>
      
      <div class="form-group">
        <label for="password">Password</label>
        <input type="password" id="password" name="password" placeholder="Enter your password" required autocomplete="current-password" autofocus>
      </div>
      
      <div class="buttons">
        <button type="submit" name="action" value="cancel" class="btn-secondary">Cancel</button>
        <button type="submit" name="action" value="approve" class="btn-primary">Approve</button>
      </div>
    </form>
  </div>
</body>
</html>`;
}

// Generate UIA success page
function generateUiaSuccessPage(sessionId: string, serverName: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Approved - ${escapeHtml(serverName)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #f1f5f9;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: #1e293b;
      border-radius: 16px;
      padding: 40px;
      max-width: 440px;
      width: 100%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid #334155;
    }
    .icon {
      width: 80px;
      height: 80px;
      background: linear-gradient(135deg, #22c55e 0%, #16a34a 100%);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 24px;
    }
    .icon svg { width: 40px; height: 40px; color: white; }
    h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; color: #22c55e; }
    p { color: #94a3b8; margin-bottom: 24px; }
    .session { font-family: monospace; background: #0f172a; padding: 8px 16px; border-radius: 8px; font-size: 12px; color: #64748b; }
  </style>
</head>
<body>
  <div class="container">
    <div class="icon">
      <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7" />
      </svg>
    </div>
    <h1>Request Approved</h1>
    <p>You can now return to your Matrix client. The operation will complete automatically.</p>
    <p class="session">Session: ${escapeHtml(sessionId)}</p>
    <script>
      // Try to notify the parent window/opener if this was opened as a popup
      if (window.opener) {
        window.opener.postMessage({ type: 'uia_complete', session: '${escapeHtml(sessionId)}' }, '*');
        setTimeout(() => window.close(), 2000);
      }
    </script>
  </div>
</body>
</html>`;
}

// Generate UIA cancelled page
function generateUiaCancelledPage(serverName: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cancelled - ${escapeHtml(serverName)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #f1f5f9;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: #1e293b;
      border-radius: 16px;
      padding: 40px;
      max-width: 440px;
      width: 100%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid #334155;
    }
    h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; color: #94a3b8; }
    p { color: #64748b; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Request Cancelled</h1>
    <p>You can close this window and return to your Matrix client.</p>
    <script>
      if (window.opener) {
        window.opener.postMessage({ type: 'uia_cancelled' }, '*');
        setTimeout(() => window.close(), 1000);
      }
    </script>
  </div>
</body>
</html>`;
}

// Generate UIA error page
function generateUiaErrorPage(title: string, message: string, serverName: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(title)} - ${escapeHtml(serverName)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
      color: #f1f5f9;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: #1e293b;
      border-radius: 16px;
      padding: 40px;
      max-width: 440px;
      width: 100%;
      text-align: center;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
      border: 1px solid #334155;
    }
    h1 { font-size: 24px; font-weight: 600; margin-bottom: 12px; color: #ef4444; }
    p { color: #94a3b8; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${escapeHtml(title)}</h1>
    <p>${escapeHtml(message)}</p>
  </div>
</body>
</html>`;
}

export default app;
