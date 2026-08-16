// Rate Limiting Durable Object
// Uses in-memory counters to avoid KV rate limit issues
//
// Each instance handles rate limiting for a specific category (login, register, etc.)
// Counters are stored in memory and automatically cleaned up when they expire

import { DurableObject } from 'cloudflare:workers';

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

interface CheckLimitRequest {
  action: 'check';
  clientId: string;
  limit: number;
  windowMs: number;
}

interface ResetRequest {
  action: 'reset';
  clientId: string;
}

interface CleanupRequest {
  action: 'cleanup';
}

type RateLimitRequest = CheckLimitRequest | ResetRequest | CleanupRequest;

interface CheckLimitResponse {
  allowed: boolean;
  remaining: number;
  retryAfterMs?: number;
  resetAt?: number;
}

export class RateLimitDurableObject extends DurableObject<Record<string, unknown>> {
  private counters: Map<string, RateLimitEntry> = new Map();
  private cleanupAlarm: number | null = null;

  async fetch(request: Request): Promise<Response> {
    try {
      const body: RateLimitRequest = await request.json();

      switch (body.action) {
        case 'check':
          return Response.json(await this.checkLimit(body.clientId, body.limit, body.windowMs));
        case 'reset':
          this.counters.delete(body.clientId);
          return Response.json({ success: true });
        case 'cleanup':
          this.cleanupExpiredEntries();
          return Response.json({ success: true });
        default:
          return Response.json({ error: 'Unknown action' }, { status: 400 });
      }
    } catch (error) {
      console.error('RateLimitDurableObject error:', error);
      return Response.json({ error: 'Internal error' }, { status: 500 });
    }
  }

  private async checkLimit(clientId: string, limit: number, windowMs: number): Promise<CheckLimitResponse> {
    const now = Date.now();
    const entry = this.counters.get(clientId);

    // Schedule cleanup if not already scheduled
    await this.scheduleCleanup();

    // Check if entry exists and is within the window
    if (entry && entry.windowStart > now - windowMs) {
      // Still in window
      if (entry.count >= limit) {
        // Rate limited
        const retryAfterMs = entry.windowStart + windowMs - now;
        return {
          allowed: false,
          remaining: 0,
          retryAfterMs,
          resetAt: entry.windowStart + windowMs,
        };
      }

      // Increment count
      entry.count++;
      return {
        allowed: true,
        remaining: limit - entry.count,
        resetAt: entry.windowStart + windowMs,
      };
    }

    // New window or expired - start fresh
    this.counters.set(clientId, { count: 1, windowStart: now });
    return {
      allowed: true,
      remaining: limit - 1,
      resetAt: now + windowMs,
    };
  }

  private cleanupExpiredEntries() {
    const now = Date.now();
    // Clean up entries older than 2 minutes (max window is 60 seconds)
    const maxAge = 2 * 60 * 1000;

    for (const [clientId, entry] of this.counters) {
      if (entry.windowStart < now - maxAge) {
        this.counters.delete(clientId);
      }
    }
  }

  private async scheduleCleanup() {
    const now = Date.now();
    const fiveMinutes = 5 * 60 * 1000;

    if (!this.cleanupAlarm || this.cleanupAlarm < now) {
      this.cleanupAlarm = now + fiveMinutes;
      // Schedule a real DO alarm so cleanup runs even without incoming requests
      const currentAlarm = await this.ctx.storage.getAlarm();
      if (!currentAlarm) {
        await this.ctx.storage.setAlarm(now + fiveMinutes);
      }
    }
  }

  async alarm() {
    this.cleanupExpiredEntries();
    // Reschedule if there are still entries to track
    if (this.counters.size > 0) {
      await this.ctx.storage.setAlarm(Date.now() + 5 * 60 * 1000);
      this.cleanupAlarm = Date.now() + 5 * 60 * 1000;
    } else {
      this.cleanupAlarm = null;
    }
  }
}
