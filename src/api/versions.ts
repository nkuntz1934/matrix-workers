// Matrix Client-Server API version endpoints

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { getOrCreateOidcSigningKey } from '../services/oidc-keys';

const app = new Hono<AppEnv>();

// GET /.well-known/matrix/client
app.get('/.well-known/matrix/client', (c) => {
  const serverName = c.env.SERVER_NAME;
  const baseUrl = `https://${serverName}`;

  const response: Record<string, unknown> = {
    'm.homeserver': {
      base_url: baseUrl,
    },
    // Native sliding sync support - no proxy needed
    'org.matrix.msc3575.proxy': {
      url: baseUrl,
    },
  };

  // Add MatrixRTC (LiveKit) focus if configured
  if (c.env.LIVEKIT_URL && c.env.LIVEKIT_API_KEY) {
    response['org.matrix.msc4143.rtc_foci'] = [
      {
        type: 'livekit',
        livekit_service_url: `${baseUrl}/livekit/get_token`,
      },
    ];
  }

  return c.json(response);
});

// GET /.well-known/matrix/server
app.get('/.well-known/matrix/server', (c) => {
  const serverName = c.env.SERVER_NAME;
  return c.json({
    'm.server': `${serverName}:443`,
  });
});

// GET /.well-known/openid-configuration - OIDC Discovery endpoint
// This is required for Element Web OIDC-native authentication
// See: https://spec.matrix.org/v1.17/client-server-api/#oauth-20-api
app.get('/.well-known/openid-configuration', (c) => {
  const serverName = c.env.SERVER_NAME;
  const baseUrl = `https://${serverName}`;

  // Return standard OIDC discovery document
  // Element Web requires all these fields to be present
  return c.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    userinfo_endpoint: `${baseUrl}/oauth/userinfo`,
    jwks_uri: `${baseUrl}/.well-known/jwks.json`,
    registration_endpoint: `${baseUrl}/oauth/register`,
    revocation_endpoint: `${baseUrl}/oauth/revoke`,
    introspection_endpoint: `${baseUrl}/oauth/introspect`,
    scopes_supported: [
      'openid',
      'profile',
      'email',
      'urn:matrix:org.matrix.msc2967.client:api:*',
      'urn:matrix:org.matrix.msc2967.client:device:*',
    ],
    response_types_supported: ['code'],
    response_modes_supported: ['query', 'fragment'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256', 'plain'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'name', 'email'],
    // Matrix-specific extension
    'org.matrix.matrix-authentication-service': {
      graphql_endpoint: null,
      account: {
        issuer: baseUrl,
      },
    },
  });
});

// GET /.well-known/jwks.json - JSON Web Key Set for token verification
app.get('/.well-known/jwks.json', async (c) => {
  // Publish the OIDC id_token signing key so clients (e.g. Element Web/Desktop)
  // can verify id_tokens issued by /oauth/token.
  const signingKey = await getOrCreateOidcSigningKey(c.env.CACHE);
  return c.json({
    keys: [signingKey.publicKeyJwk],
  });
});

// GET /.well-known/matrix/support - Server support contact information
// Spec: https://spec.matrix.org/v1.17/client-server-api/#getwell-knownmatrixsupport
app.get('/.well-known/matrix/support', (c) => {
  const contacts: Array<{
    role: string;
    email_address?: string;
    matrix_id?: string;
  }> = [];

  // Add admin contact if configured
  if (c.env.ADMIN_CONTACT_EMAIL || c.env.ADMIN_CONTACT_MXID) {
    contacts.push({
      role: 'm.role.admin',
      email_address: c.env.ADMIN_CONTACT_EMAIL,
      matrix_id: c.env.ADMIN_CONTACT_MXID,
    });
  }

  const response: {
    contacts: typeof contacts;
    support_page?: string;
  } = {
    contacts,
  };

  if (c.env.SUPPORT_PAGE_URL) {
    response.support_page = c.env.SUPPORT_PAGE_URL;
  }

  return c.json(response);
});

// GET /_matrix/client/versions
app.get('/_matrix/client/versions', (c) => {
  return c.json({
    versions: [
      'r0.0.1',
      'r0.1.0',
      'r0.2.0',
      'r0.3.0',
      'r0.4.0',
      'r0.5.0',
      'r0.6.0',
      'r0.6.1',
      'v1.1',
      'v1.2',
      'v1.3',
      'v1.4',
      'v1.5',
      'v1.6',
      'v1.7',
      'v1.8',
      'v1.9',
      'v1.10',
      'v1.11',
      'v1.12',
    ],
    unstable_features: {
      'org.matrix.label_based_filtering': true,
      'org.matrix.e2e_cross_signing': true,
      'org.matrix.msc2432': true,
      'org.matrix.msc3440.stable': true,
      'uk.half-shot.msc2666.query_mutual_rooms': true,
      'io.element.e2ee_forced.public': false,
      'io.element.e2ee_forced.private': false,
      'io.element.e2ee_forced.trusted_private': false,
      'org.matrix.msc3026.busy_presence': false,
      'org.matrix.msc2285.stable': true,
      'org.matrix.msc3827.stable': true,
      'org.matrix.msc3881': true,
      'org.matrix.msc3882': false,
      // MatrixRTC - VoIP calls with LiveKit (MSC3401, MSC4143)
      'org.matrix.msc3401': true,
      'org.matrix.msc4143': true,
      // Sliding Sync (MSC3575) - native implementation
      'org.matrix.msc3575': true,
      // Simplified Sliding Sync (MSC4186)
      'org.matrix.simplified_msc3575': true,
      // Additional sliding sync related features
      'org.matrix.msc3575.e2ee': true,
      'org.matrix.msc3575.to_device': true,
      'org.matrix.msc3575.account_data': true,
      'org.matrix.msc3575.receipts': true,
      'org.matrix.msc3575.typing': true,
      'org.matrix.msc3575.presence': true,
    },
  });
});

// GET /_matrix/federation/v1/version
app.get('/_matrix/federation/v1/version', (c) => {
  return c.json({
    server: {
      name: 'matrix-worker',
      version: c.env.SERVER_VERSION,
    },
  });
});

export default app;
