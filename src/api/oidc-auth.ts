// OIDC Authentication API endpoints
// Handles OAuth flow for external Identity Providers

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import {
  fetchOIDCDiscovery,
  fetchJWKS,
  buildAuthorizationUrl,
  exchangeCodeForTokens,
  validateIDToken,
  generateRandomString,
  deriveUsername,
} from '../services/oidc';
import { formatUserId } from '../utils/ids';
import { generateAccessToken, generateDeviceId } from '../utils/ids';
import { hashToken } from '../utils/crypto';
import { createUser, getUserById, createDevice, createAccessToken } from '../services/database';
import { requireAuth } from '../middleware/auth';
import { generateOpaqueId } from '../utils/ids';

const app = new Hono<AppEnv>();

interface IdPProvider {
  id: string;
  name: string;
  issuer_url: string;
  client_id: string;
  client_secret_encrypted: string;
  scopes: string;
  enabled: number;
  auto_create_users: number;
  username_claim: string;
  display_order: number;
  icon_url: string | null;
}

interface IdPUserLink {
  id: number;
  provider_id: string;
  external_id: string;
  user_id: string;
  external_email: string | null;
  external_name: string | null;
}

interface OAuthState {
  providerId: string;
  nonce: string;
  redirectUri: string;
  returnTo?: string;
}

// Version byte for encrypted secrets
// 0x01 = legacy (SERVER_NAME-based key) - INSECURE, kept for migration
// 0x02 = secure (OIDC_ENCRYPTION_KEY)
const ENCRYPTION_VERSION_LEGACY = 0x01;
const ENCRYPTION_VERSION_SECURE = 0x02;

// Get the encryption key (prefer OIDC_ENCRYPTION_KEY, fall back to SERVER_NAME for legacy)
async function getEncryptionKey(
  env: { SERVER_NAME: string; OIDC_ENCRYPTION_KEY?: string },
  version: number
): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  if (version === ENCRYPTION_VERSION_SECURE && env.OIDC_ENCRYPTION_KEY) {
    // Use the secure key (base64-encoded 32 bytes)
    const keyBytes = Uint8Array.from(atob(env.OIDC_ENCRYPTION_KEY), (c) => c.charCodeAt(0));
    if (keyBytes.length !== 32) {
      throw new Error('OIDC_ENCRYPTION_KEY must be 32 bytes (base64 encoded)');
    }
    return crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  // Legacy key derivation (INSECURE - only for decrypting old secrets)
  console.warn('Using legacy OIDC encryption - please set OIDC_ENCRYPTION_KEY');
  return crypto.subtle.importKey(
    'raw',
    encoder.encode(env.SERVER_NAME.padEnd(32, '0').slice(0, 32)),
    'AES-GCM',
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt a secret using AES-GCM
// Encrypt a secret using AES-GCM with the secure OIDC_ENCRYPTION_KEY.
// Refuses to encrypt with the legacy SERVER_NAME-based key — new secrets
// must use a proper encryption key.
async function encryptSecret(
  secret: string,
  env: { SERVER_NAME: string; OIDC_ENCRYPTION_KEY?: string }
): Promise<string> {
  const encoder = new TextEncoder();

  if (!env.OIDC_ENCRYPTION_KEY) {
    throw new Error(
      'OIDC_ENCRYPTION_KEY is required for OIDC client registration. ' +
      'Generate with: openssl rand -base64 32 | npx wrangler secret put OIDC_ENCRYPTION_KEY'
    );
  }

  const version = ENCRYPTION_VERSION_SECURE;
  const keyMaterial = await getEncryptionKey(env, version);

  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, keyMaterial, encoder.encode(secret));

  // Combine version byte, IV, and ciphertext
  const encryptedBytes = new Uint8Array(encrypted);
  const combined = new Uint8Array(1 + iv.length + encryptedBytes.length);
  combined[0] = version;
  combined.set(iv, 1);
  combined.set(encryptedBytes, 1 + iv.length);

  return btoa(String.fromCharCode(...combined));
}

// Decrypt a secret
// Automatically detects version and uses appropriate key
async function decryptSecret(
  encryptedSecret: string,
  env: { SERVER_NAME: string; OIDC_ENCRYPTION_KEY?: string }
): Promise<string> {
  const combined = Uint8Array.from(atob(encryptedSecret), (c) => c.charCodeAt(0));

  // Check if this is a versioned secret (starts with 0x01 or 0x02)
  let version: number;
  let iv: Uint8Array;
  let ciphertext: Uint8Array;

  if (combined[0] === ENCRYPTION_VERSION_LEGACY || combined[0] === ENCRYPTION_VERSION_SECURE) {
    // New format with version byte
    version = combined[0];
    iv = combined.slice(1, 13);
    ciphertext = combined.slice(13);
  } else {
    // Old format without version byte (legacy)
    version = ENCRYPTION_VERSION_LEGACY;
    iv = combined.slice(0, 12);
    ciphertext = combined.slice(12);
  }

  const keyMaterial = await getEncryptionKey(env, version);

  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, keyMaterial, ciphertext);

  return new TextDecoder().decode(decrypted);
}

// GET /auth/oidc/providers - List enabled IdP providers (public)
app.get('/auth/oidc/providers', async (c) => {
  const db = c.env.DB;

  const result = await db.prepare(`
    SELECT id, name, icon_url, display_order
    FROM idp_providers
    WHERE enabled = 1
    ORDER BY display_order ASC, name ASC
  `).all<{ id: string; name: string; icon_url: string | null; display_order: number }>();

  return c.json({
    providers: result.results.map(p => ({
      id: p.id,
      name: p.name,
      icon_url: p.icon_url,
      login_url: `/auth/oidc/${p.id}/login`,
    })),
  });
});

// GET /auth/oidc/:providerId/login - Initiate OAuth flow
app.get('/auth/oidc/:providerId/login', async (c) => {
  const providerId = c.req.param('providerId');
  const returnTo = c.req.query('return_to') || '/';
  const db = c.env.DB;

  // Get provider config
  const provider = await db.prepare(`
    SELECT * FROM idp_providers WHERE id = ? AND enabled = 1
  `).bind(providerId).first<IdPProvider>();

  if (!provider) {
    return c.json({ errcode: 'M_NOT_FOUND', error: 'Identity provider not found' }, 404);
  }

  try {
    // Fetch OIDC discovery
    const discovery = await fetchOIDCDiscovery(provider.issuer_url);

    // Generate state and nonce
    const state = generateRandomString(32);
    const nonce = generateRandomString(32);

    // Build redirect URI
    const host = c.req.header('host') || c.env.SERVER_NAME;
    const protocol = c.req.url.startsWith('https') ? 'https' : 'https';
    const redirectUri = `${protocol}://${host}/auth/oidc/${providerId}/callback`;

    // Store state in KV (expires in 10 minutes)
    const stateData: OAuthState = {
      providerId,
      nonce,
      redirectUri,
      returnTo,
    };
    await c.env.SESSIONS.put(`oidc_state:${state}`, JSON.stringify(stateData), {
      expirationTtl: 600,
    });

    // Build authorization URL and redirect
    const authUrl = buildAuthorizationUrl(
      discovery,
      provider.client_id,
      redirectUri,
      provider.scopes,
      state,
      nonce
    );

    return c.redirect(authUrl);
  } catch (err) {
    console.error('OIDC login error:', err);
    return c.json({ errcode: 'M_UNKNOWN', error: 'Failed to initiate login' }, 500);
  }
});

// GET /auth/oidc/:providerId/callback - Handle OAuth callback
app.get('/auth/oidc/:providerId/callback', async (c) => {
  const providerId = c.req.param('providerId');
  const code = c.req.query('code');
  const state = c.req.query('state');
  const error = c.req.query('error');
  const errorDescription = c.req.query('error_description');
  const db = c.env.DB;

  // Handle error from IdP
  if (error) {
    return c.html(generateErrorPage('Authentication Failed', errorDescription || error));
  }

  if (!code || !state) {
    return c.html(generateErrorPage('Invalid Request', 'Missing code or state parameter'));
  }

  // Retrieve and validate state
  const stateDataJson = await c.env.SESSIONS.get(`oidc_state:${state}`);
  if (!stateDataJson) {
    return c.html(generateErrorPage('Invalid State', 'The login session has expired. Please try again.'));
  }

  const stateData: OAuthState = JSON.parse(stateDataJson);

  // Delete state (one-time use)
  await c.env.SESSIONS.delete(`oidc_state:${state}`);

  // Validate provider matches
  if (stateData.providerId !== providerId) {
    return c.html(generateErrorPage('Invalid State', 'Provider mismatch'));
  }

  // Get provider config
  const provider = await db.prepare(`
    SELECT * FROM idp_providers WHERE id = ? AND enabled = 1
  `).bind(providerId).first<IdPProvider>();

  if (!provider) {
    return c.html(generateErrorPage('Provider Not Found', 'Identity provider not found or disabled'));
  }

  try {
    // Fetch OIDC discovery and JWKS
    const discovery = await fetchOIDCDiscovery(provider.issuer_url);
    const jwks = await fetchJWKS(discovery.jwks_uri);

    // Decrypt client secret
    const clientSecret = await decryptSecret(provider.client_secret_encrypted, c.env);

    // Exchange code for tokens
    const tokens = await exchangeCodeForTokens(
      discovery,
      provider.client_id,
      clientSecret,
      code,
      stateData.redirectUri
    );

    // Validate ID token and extract claims
    const claims = await validateIDToken(
      tokens.id_token,
      provider.issuer_url,
      provider.client_id,
      stateData.nonce,
      jwks
    );

    // Check if user link exists
    let userLink = await db.prepare(`
      SELECT * FROM idp_user_links WHERE provider_id = ? AND external_id = ?
    `).bind(providerId, claims.sub).first<IdPUserLink>();

    let userId: string;

    if (userLink) {
      // Existing user - update last login
      userId = userLink.user_id;
      await db.prepare(`
        UPDATE idp_user_links SET last_login_at = ?, external_email = ?, external_name = ?
        WHERE id = ?
      `).bind(Date.now(), claims.email || null, claims.name || null, userLink.id).run();
    } else {
      // New user
      if (!provider.auto_create_users) {
        return c.html(generateErrorPage(
          'Account Not Found',
          'No account is linked to this identity. Please contact your administrator.'
        ));
      }

      // Derive username from claims
      const username = deriveUsername(claims, provider.username_claim);
      userId = formatUserId(username, c.env.SERVER_NAME);

      // Check if Matrix user already exists
      const existingUser = await getUserById(db, userId);
      if (existingUser) {
        // User exists but not linked - check if we should auto-link or error
        // For now, auto-link if the user exists
        await db.prepare(`
          INSERT INTO idp_user_links (provider_id, external_id, user_id, external_email, external_name, last_login_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(providerId, claims.sub, userId, claims.email || null, claims.name || null, Date.now()).run();
      } else {
        // Create new Matrix user
        await createUser(db, userId, username, null, false);

        // Set display name if available
        if (claims.name) {
          await db.prepare(`
            UPDATE users SET display_name = ? WHERE user_id = ?
          `).bind(claims.name, userId).run();
        }

        // Create user link
        await db.prepare(`
          INSERT INTO idp_user_links (provider_id, external_id, user_id, external_email, external_name, last_login_at)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(providerId, claims.sub, userId, claims.email || null, claims.name || null, Date.now()).run();
      }
    }

    // Generate Matrix access token
    const deviceId = await generateDeviceId();
    await createDevice(db, userId, deviceId, `SSO Login (${provider.name})`);

    const accessToken = await generateAccessToken();
    const tokenHash = await hashToken(accessToken);
    const tokenId = await generateOpaqueId(16);
    await createAccessToken(db, tokenId, tokenHash, userId, deviceId);

    // Return success page with token (or redirect)
    return c.html(generateSuccessPage(userId, accessToken, deviceId, c.env.SERVER_NAME, stateData.returnTo));

  } catch (err) {
    console.error('OIDC callback error:', err);
    return c.html(generateErrorPage('Authentication Failed', String(err)));
  }
});

// Helper to generate error page HTML
function generateErrorPage(title: string, message: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .container { background: #1e293b; padding: 40px; border-radius: 12px; max-width: 400px; text-align: center; border: 1px solid #334155; }
    h1 { color: #ef4444; margin-bottom: 16px; }
    p { color: #94a3b8; margin-bottom: 24px; }
    a { color: #0d9488; text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <h1>${title}</h1>
    <p>${message}</p>
    <a href="/">Return to login</a>
  </div>
</body>
</html>`;
}

// Helper to generate success page HTML
function generateSuccessPage(userId: string, accessToken: string, deviceId: string, serverName: string, returnTo?: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login Successful</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0f172a; color: #f1f5f9; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
    .container { background: #1e293b; padding: 40px; border-radius: 12px; max-width: 500px; text-align: center; border: 1px solid #334155; }
    h1 { color: #22c55e; margin-bottom: 16px; }
    p { color: #94a3b8; margin-bottom: 24px; }
    .info { background: #0f172a; padding: 16px; border-radius: 8px; text-align: left; margin-bottom: 24px; }
    .info label { font-size: 12px; color: #64748b; display: block; margin-bottom: 4px; }
    .info .value { font-family: monospace; font-size: 13px; word-break: break-all; margin-bottom: 12px; }
    .btn { display: inline-block; background: #0d9488; color: white; padding: 12px 24px; border-radius: 8px; text-decoration: none; margin: 8px; }
    .btn:hover { background: #0f766e; }
    .btn-secondary { background: #334155; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Login Successful!</h1>
    <p>You are now logged in as:</p>
    <div class="info">
      <label>User ID</label>
      <div class="value">${userId}</div>
      <label>Homeserver</label>
      <div class="value">https://${serverName}</div>
      <label>Access Token</label>
      <div class="value">${accessToken}</div>
      <label>Device ID</label>
      <div class="value">${deviceId}</div>
    </div>
    <p style="font-size: 13px; color: #64748b;">Copy these credentials to configure your Matrix client.</p>
    <button class="btn" onclick="copyCredentials()">Copy Credentials</button>
    <a href="${returnTo || '/'}" class="btn btn-secondary">Continue</a>
  </div>
  <script>
    function copyCredentials() {
      const text = \`Homeserver: https://${serverName}
User ID: ${userId}
Access Token: ${accessToken}
Device ID: ${deviceId}\`;
      navigator.clipboard.writeText(text).then(() => {
        alert('Credentials copied to clipboard!');
      });
    }
  </script>
</body>
</html>`;
}

// GET /_matrix/client/v1/auth_metadata - Get authentication metadata
// Returns information about supported authentication methods (MSC2965 / Matrix v1.17)
// This is the STABLE endpoint as of Matrix v1.17
app.get('/_matrix/client/v1/auth_metadata', async (c) => {
  const serverName = c.env.SERVER_NAME;
  const baseUrl = `https://${serverName}`;

  // Return proper OIDC metadata for this server acting as its own OIDC provider
  // This is required for Element Web OIDC-native authentication to work
  // All fields must be present for Element Web to accept the configuration
  const response = {
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    // Required capabilities
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    // Additional optional fields that Element Web may check
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    scopes_supported: [
      'openid',
      'profile',
      'email',
      'urn:matrix:org.matrix.msc2967.client:api:*',
      'urn:matrix:org.matrix.msc2967.client:device:*',
    ],
    // Matrix authentication service extension (MSC3861/MSC4191)
    // account_management_uri is where users can manage their account
    account_management_uri: `${baseUrl}/admin`,
    // Supported account management actions per MSC4191
    // Element X uses these to determine what features are available
    account_management_actions_supported: [
      'org.matrix.profile',              // View/edit profile
      'org.matrix.sessions_list',        // View list of sessions  
      'org.matrix.session_view',         // View details of a specific session
      'org.matrix.session_end',          // End/logout a specific session
      'org.matrix.cross_signing_reset',  // Reset cross-signing keys (identity reset)
    ],
    // Device authorization endpoint for QR code login (MSC4108)
    device_authorization_endpoint: `${baseUrl}/oauth/device`,
    // Prompt values we support
    prompt_values_supported: ['create'],
  };

  return c.json(response);
});

// ============================================
// MSC3861 Identity Reset Endpoint
// ============================================

// Helper to get next stream position (same pattern as keys.ts)
async function getNextStreamPosition(db: D1Database, streamName: string): Promise<number> {
  await db.prepare(`
    UPDATE stream_positions SET position = position + 1 WHERE stream_name = ?
  `).bind(streamName).run();

  const result = await db.prepare(`
    SELECT position FROM stream_positions WHERE stream_name = ?
  `).bind(streamName).first<{ position: number }>();

  return result?.position || 1;
}

// Helper to get Durable Object for user keys
function getUserKeysDO(env: any, userId: string) {
  const id = env.USER_KEYS.idFromName(userId);
  return env.USER_KEYS.get(id);
}

// POST /_matrix/client/unstable/org.matrix.msc3861/account/identity/reset
// Allows OIDC users to reset their cross-signing identity
// Per MSC3861:
// 1. Requires OIDC re-authentication (valid access token)
// 2. Deletes all cross-signing keys for the user
// 3. Returns 200 on success
app.post('/_matrix/client/unstable/org.matrix.msc3861/account/identity/reset', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  try {
    // Delete cross-signing keys from Durable Object (primary storage)
    const stub = getUserKeysDO(c.env, userId);
    await stub.fetch(new Request('http://internal/cross-signing/delete', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
    }));

    // Delete cross-signing keys from D1 (backup storage)
    await db.prepare('DELETE FROM cross_signing_keys WHERE user_id = ?').bind(userId).run();

    // Delete cross-signing signatures
    await db.prepare('DELETE FROM cross_signing_signatures WHERE user_id = ? OR signer_user_id = ?').bind(userId, userId).run();

    // Delete from KV (cache)
    await c.env.CROSS_SIGNING_KEYS.delete(`user:${userId}`);

    // Record key change to trigger device list update for other users
    const streamPosition = await getNextStreamPosition(db, 'device_keys');
    await db.prepare(`
      INSERT INTO device_key_changes (user_id, device_id, change_type, stream_position)
      VALUES (?, NULL, 'cross_signing_reset', ?)
    `).bind(userId, streamPosition).run();

    console.log(`[OIDC] Cross-signing identity reset for user ${userId}`);

    // Return empty object on success per MSC3861
    return c.json({});
  } catch (err) {
    console.error(`[OIDC] Identity reset failed for ${userId}:`, err);
    return c.json({ errcode: 'M_UNKNOWN', error: 'Failed to reset identity' }, 500);
  }
});

// Export encryption helpers for admin API
export { encryptSecret, decryptSecret };

export default app;
