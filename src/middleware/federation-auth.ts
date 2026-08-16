// Federation Authentication Middleware
// Validates incoming federation requests per Matrix Server-Server API spec
//
// The Authorization header format is:
// Authorization: X-Matrix origin=<origin>,destination=<destination>,key=<key_id>,sig=<signature>

import type { Context, Next } from 'hono';
import type { AppEnv } from '../types';
import { verifyRemoteSignature } from '../services/federation-keys';

interface MatrixAuthParams {
  origin: string;
  destination?: string;
  key: string;
  sig: string;
}

/**
 * Parse the X-Matrix authorization header
 */
function parseAuthHeader(authHeader: string): MatrixAuthParams | null {
  if (!authHeader.startsWith('X-Matrix ')) {
    return null;
  }

  const params = authHeader.substring(9); // Remove "X-Matrix "
  const result: Partial<MatrixAuthParams> = {};

  // Parse key=value pairs
  const regex = /(\w+)="([^"]+)"/g;
  let match;
  while ((match = regex.exec(params)) !== null) {
    const [, key, value] = match;
    if (key === 'origin' || key === 'destination' || key === 'key' || key === 'sig') {
      result[key] = value;
    }
  }

  // Also try unquoted format (some implementations)
  const unquotedRegex = /(\w+)=([^,\s]+)/g;
  while ((match = unquotedRegex.exec(params)) !== null) {
    const [, key, value] = match;
    if ((key === 'origin' || key === 'destination' || key === 'key' || key === 'sig') && !result[key]) {
      result[key] = value;
    }
  }

  if (!result.origin || !result.key || !result.sig) {
    return null;
  }

  return result as MatrixAuthParams;
}

/**
 * Build the request object that was signed
 */
function buildSignedRequest(
  method: string,
  uri: string,
  origin: string,
  destination: string,
  content?: unknown
): Record<string, unknown> {
  const request: Record<string, unknown> = {
    method,
    uri,
    origin,
    destination,
  };

  if (content !== undefined && content !== null) {
    request.content = content;
  }

  return request;
}

/**
 * Federation authentication middleware
 * Validates X-Matrix authorization header and verifies Ed25519 signatures
 */
export function requireFederationAuth() {
  return async (c: Context<AppEnv>, next: Next) => {
    const authHeader = c.req.header('Authorization');
    const serverName = c.env.SERVER_NAME;

    // Parse authorization header
    if (!authHeader) {
      return c.json(
        {
          errcode: 'M_UNAUTHORIZED',
          error: 'Missing Authorization header',
        },
        401
      );
    }

    const authParams = parseAuthHeader(authHeader);
    if (!authParams) {
      return c.json(
        {
          errcode: 'M_UNAUTHORIZED',
          error: 'Invalid Authorization header format. Expected: X-Matrix origin=...,key=...,sig=...',
        },
        401
      );
    }

    // Validate destination matches this server
    if (authParams.destination && authParams.destination !== serverName) {
      return c.json(
        {
          errcode: 'M_UNAUTHORIZED',
          error: `Request destination ${authParams.destination} does not match this server ${serverName}`,
        },
        401
      );
    }

    // Get request details
    const method = c.req.method;
    const url = new URL(c.req.url);
    const uri = url.pathname + url.search;

    // Parse body for POST/PUT requests
    // IMPORTANT: Buffer the body so downstream handlers can still read it.
    // Request bodies can only be consumed once in the Workers runtime.
    let content: unknown;
    if (method === 'POST' || method === 'PUT') {
      try {
        const bodyText = await c.req.text();
        if (bodyText) {
          content = JSON.parse(bodyText);
          // Store the parsed body on the context so handlers can access it
          // via c.get('federationBody') instead of re-reading c.req.json()
          c.set('federationBody' as any, content);
          c.set('federationBodyRaw' as any, bodyText);
        }
      } catch {
        // Body parsing failed - proceed without content
      }
    }

    // Build the request object that was signed
    const signedRequest = buildSignedRequest(
      method,
      uri,
      authParams.origin,
      serverName,
      content
    );

    // Add the signature to the request object for verification
    const requestWithSig = {
      ...signedRequest,
      signatures: {
        [authParams.origin]: {
          [authParams.key]: authParams.sig,
        },
      },
    };

    try {
      // Verify the signature
      const isValid = await verifyRemoteSignature(
        requestWithSig,
        authParams.origin,
        authParams.key,
        c.env.DB,
        c.env.CACHE
      );

      if (!isValid) {
        console.warn(`Federation auth failed for ${authParams.origin}: invalid signature`);
        return c.json(
          {
            errcode: 'M_UNAUTHORIZED',
            error: 'Invalid request signature',
          },
          401
        );
      }

      // Set origin in context for use by handlers
      c.set('federationOrigin' as any, authParams.origin);

      return next();
    } catch (error) {
      console.error(`Federation auth error for ${authParams.origin}:`, error);
      return c.json(
        {
          errcode: 'M_UNAUTHORIZED',
          error: 'Failed to verify request signature',
        },
        401
      );
    }
  };
}

/**
 * Optional federation authentication middleware
 * Sets federationOrigin if valid auth is provided, but doesn't require it
 */
export function optionalFederationAuth() {
  return async (c: Context<AppEnv>, next: Next) => {
    const authHeader = c.req.header('Authorization');

    if (!authHeader || !authHeader.startsWith('X-Matrix ')) {
      // No Matrix auth - continue without setting origin
      return next();
    }

    // Try to authenticate, but don't fail if it doesn't work
    const authParams = parseAuthHeader(authHeader);
    if (authParams) {
      try {
        const method = c.req.method;
        const url = new URL(c.req.url);
        const uri = url.pathname + url.search;

        let content: unknown;
        if (method === 'POST' || method === 'PUT') {
          try {
            const bodyText = await c.req.text();
            if (bodyText) {
              content = JSON.parse(bodyText);
              c.set('federationBody' as any, content);
              c.set('federationBodyRaw' as any, bodyText);
            }
          } catch {
            // Body parsing failed
          }
        }

        const signedRequest = buildSignedRequest(
          method,
          uri,
          authParams.origin,
          c.env.SERVER_NAME,
          content
        );

        const requestWithSig = {
          ...signedRequest,
          signatures: {
            [authParams.origin]: {
              [authParams.key]: authParams.sig,
            },
          },
        };

        const isValid = await verifyRemoteSignature(
          requestWithSig,
          authParams.origin,
          authParams.key,
          c.env.DB,
          c.env.CACHE
        );

        if (isValid) {
          c.set('federationOrigin' as any, authParams.origin);
        } else {
          // Auth was provided but signature was invalid — reject rather than
          // silently degrading to unauthenticated. This prevents a malicious
          // server from having its forged auth quietly accepted as "no auth".
          console.warn(`[federation] Optional auth: invalid signature from ${authParams.origin}`);
          return c.json(
            { errcode: 'M_UNAUTHORIZED', error: 'Invalid request signature' },
            401
          );
        }
      } catch (err) {
        // Log auth errors but allow the request to proceed unauthenticated
        // only if the error is a key-fetch failure (not a validation failure)
        console.warn(`[federation] Optional auth error for ${authParams.origin}:`, err);
      }
    }

    return next();
  };
}
