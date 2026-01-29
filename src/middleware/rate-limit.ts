// Rate Limiting Middleware
// Implements rate limiting using Durable Objects for persistence
// Uses a sliding window algorithm with different limits for different endpoints

import type { Context, Next } from 'hono';
import type { AppEnv } from '../types';

// Rate limit configurations for different endpoint types
const RATE_LIMITS: Record<string, { requests: number; windowMs: number }> = {
  login: { requests: 10, windowMs: 60 * 1000 }, // 10 per minute
  register: { requests: 5, windowMs: 60 * 1000 }, // 5 per minute
  default: { requests: 100, windowMs: 60 * 1000 }, // 100 per minute
  sync: { requests: 300, windowMs: 60 * 1000 }, // 300 per minute (long-polling)
  e2ee: { requests: 500, windowMs: 60 * 1000 }, // 500 per minute (key uploads)
  media_upload: { requests: 30, windowMs: 60 * 1000 }, // 30 per minute
  media_download: { requests: 200, windowMs: 60 * 1000 }, // 200 per minute
  search: { requests: 30, windowMs: 60 * 1000 }, // 30 per minute
  federation: { requests: 500, windowMs: 60 * 1000 }, // 500 per minute
  send_message: { requests: 60, windowMs: 60 * 1000 }, // 60 per minute
  create_room: { requests: 10, windowMs: 60 * 1000 }, // 10 per minute
};

function getRateLimitType(path: string, method: string): string {
  if (path.includes('/login') && method === 'POST') return 'login';
  if (path.includes('/register') && method === 'POST') return 'register';
  if (path.includes('/sync')) return 'sync';
  if (path.includes('/keys/')) return 'e2ee';
  if (path.includes('/media') || path.includes('/upload')) {
    return method === 'POST' || method === 'PUT' ? 'media_upload' : 'media_download';
  }
  if (path.includes('/search')) return 'search';
  if (path.includes('/_matrix/federation') || path.includes('/_matrix/key')) return 'federation';
  if (path.includes('/createRoom') && method === 'POST') return 'create_room';
  if (path.match(/\/rooms\/[^/]+\/send/) && method === 'PUT') return 'send_message';
  return 'default';
}

// Get client identifier (IP or user ID)
function getClientId(c: Context<AppEnv>): string {
  // Try to get user ID first (for authenticated requests)
  const userId = c.get('userId');
  if (userId) {
    return `user:${userId}`;
  }

  // Fall back to IP address
  const cfConnectingIp = c.req.header('CF-Connecting-IP');
  const xForwardedFor = c.req.header('X-Forwarded-For');
  const ip = cfConnectingIp || xForwardedFor?.split(',')[0]?.trim() || 'unknown';

  return `ip:${ip}`;
}

// Rate limiter using Durable Objects
export async function rateLimitMiddleware(c: Context<AppEnv>, next: Next) {
  const path = c.req.path;
  const method = c.req.method;

  // Skip rate limiting for OPTIONS (CORS preflight)
  if (method === 'OPTIONS') {
    return next();
  }

  // Skip rate limiting for sync endpoints with long timeout
  // These have natural rate limiting via the timeout parameter
  if (path.includes('/sync')) {
    return next();
  }

  const limitType = getRateLimitType(path, method);
  const config = RATE_LIMITS[limitType];
  const clientId = getClientId(c);

  // Use rate limit type as the DO ID to distribute load
  // Each limit type gets its own DO instance
  const doId = c.env.RATE_LIMIT.idFromName(limitType);
  const stub = c.env.RATE_LIMIT.get(doId);

  try {
    const response = await stub.fetch(
      new Request('https://internal/check', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'check',
          clientId,
          limit: config.requests,
          windowMs: config.windowMs,
        }),
      })
    );

    const result = (await response.json()) as {
      allowed: boolean;
      remaining: number;
      retryAfterMs?: number;
      resetAt?: number;
    };

    // Set rate limit headers
    c.header('X-RateLimit-Limit', String(config.requests));
    c.header('X-RateLimit-Remaining', String(result.remaining));
    if (result.resetAt) {
      c.header('X-RateLimit-Reset', String(Math.ceil(result.resetAt / 1000)));
    }

    if (!result.allowed) {
      // Rate limited
      const retryAfter = Math.ceil((result.retryAfterMs || config.windowMs) / 1000);
      c.header('Retry-After', String(retryAfter));

      return c.json(
        {
          errcode: 'M_LIMIT_EXCEEDED',
          error: 'Too many requests',
          retry_after_ms: result.retryAfterMs || config.windowMs,
        },
        429
      );
    }
  } catch (error) {
    // If rate limiting fails, allow the request (fail open)
    // Log the error but don't block the request
    console.error('Rate limiting error:', error);
  }

  return next();
}

// Stricter rate limiter for specific endpoints (can be used as route-specific middleware)
export function strictRateLimit(requests: number, windowMs: number) {
  return async (c: Context<AppEnv>, next: Next) => {
    const clientId = getClientId(c);
    const path = c.req.path;

    // Use a unique DO ID for strict rate limits
    const doId = c.env.RATE_LIMIT.idFromName(`strict:${path}`);
    const stub = c.env.RATE_LIMIT.get(doId);

    try {
      const response = await stub.fetch(
        new Request('https://internal/check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: 'check',
            clientId,
            limit: requests,
            windowMs,
          }),
        })
      );

      const result = (await response.json()) as {
        allowed: boolean;
        remaining: number;
        retryAfterMs?: number;
      };

      if (!result.allowed) {
        const retryAfter = Math.ceil((result.retryAfterMs || windowMs) / 1000);
        c.header('Retry-After', String(retryAfter));

        return c.json(
          {
            errcode: 'M_LIMIT_EXCEEDED',
            error: 'Too many requests',
            retry_after_ms: result.retryAfterMs || windowMs,
          },
          429
        );
      }
    } catch (error) {
      console.error('Strict rate limiting error:', error);
    }

    return next();
  };
}
