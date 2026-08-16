# Issue 007: Rate Limiting & DoS Protection — IP Spoofing, Missing Endpoint Coverage, and Unbounded Operations

**Severity:** High  
**Domain:** Security, Availability  
**Affected files:** `src/middleware/rate-limit.ts`, `src/durable-objects/RateLimitDurableObject.ts`, `src/api/sliding-sync.ts`, `src/api/oidc-auth.ts`, `src/services/server-discovery.ts`

---

## Problem Statement

The rate limiting system has structural weaknesses that allow attackers to bypass protections and exhaust server resources. The IP detection relies on spoofable headers, the rate limit DO never cleans up its counters (broken alarm scheduling), several sensitive endpoints lack additional rate limits, and certain API operations accept unbounded input sizes. Together these create multiple denial-of-service vectors — an attacker can overwhelm the server through un-rate-limited endpoints, bypass existing limits through IP header spoofing, or cause resource exhaustion through oversized requests.

---

## Detailed Breakdown

### 1. Rate Limiting IP Detection Uses Spoofable Headers

**File:** `src/middleware/rate-limit.ts` (lines ~39-51)  
**Severity:** High

The rate limiter extracts the client IP from headers that can be forged:

```typescript
const cfConnectingIp = c.req.header('CF-Connecting-IP');
const xForwardedFor = c.req.header('X-Forwarded-For');
const ip = cfConnectingIp || xForwardedFor?.split(',')[0]?.trim() || 'unknown';
```

When running behind Cloudflare (the production deployment), `CF-Connecting-IP` is set by Cloudflare and is reliable. However:
- If the worker is accessed directly (bypassing Cloudflare), `CF-Connecting-IP` can be forged by the client
- `X-Forwarded-For` is always client-spoofable in the first position
- The fallback to `'unknown'` means all unidentifiable requests share a single rate limit bucket — either they're all limited together (DoS on legitimate unknown-IP clients) or the bucket is sized generously (no protection)

**Step-by-step fix:**
1. When running on Cloudflare Workers, only trust `CF-Connecting-IP` (set it in code comments as the authoritative source)
2. Remove `X-Forwarded-For` from the fallback chain in production — it's only useful in development
3. For authenticated requests, rate limit by `user_id` instead of IP (users behind the same NAT shouldn't share limits)
4. Replace the `'unknown'` fallback with a strict rate limit bucket (e.g., 10 req/min) to discourage headerless requests
5. Add request signing validation (Cloudflare Workers can check `cf.tlsClientAuth` or similar signals)

---

### 2. Rate Limit Durable Object Never Runs Cleanup (Broken Alarm)

**File:** `src/durable-objects/RateLimitDurableObject.ts` (lines ~104-126)  
**Severity:** High

As documented in Issue 005 (section 3), the `scheduleCleanup()` method sets a flag but never calls `this.ctx.storage.setAlarm()`. This means rate limit counters accumulate indefinitely in memory. Over hours of operation:

- Memory usage grows linearly with the number of unique IPs seen
- The DO becomes progressively slower as it iterates larger counter maps
- Eventually the DO hits memory limits and is evicted, resetting ALL rate limits simultaneously
- After eviction, all previously-limited IPs get a clean slate

This creates a cyclic vulnerability: counters build → DO eviction → all limits reset → burst of previously-limited traffic → counters build again.

**Step-by-step fix:**
1. Call `await this.ctx.storage.setAlarm(Date.now() + CLEANUP_INTERVAL_MS)` in the schedule method
2. Implement the `alarm()` handler to evict expired windows from the counter map
3. Add a `MAX_TRACKED_IPS = 10000` cap — when exceeded, evict the oldest entries
4. After cleanup, reschedule the next alarm

---

### 3. Identity Reset Endpoint Lacks Strict Rate Limiting

**File:** `src/api/oidc-auth.ts` (lines ~517-559)  
**Severity:** Medium

The cross-signing key reset endpoint is protected only by the global rate limiter. Cross-signing key resets are a high-impact operation — they affect end-to-end encryption trust for all of a user's verified sessions. Rapid resets could be used to disrupt encrypted communication.

**Step-by-step fix:**
1. Add a per-user rate limit of 3 resets per hour:
   ```typescript
   app.post('/.../identity/reset', requireAuth(), async (c) => {
     const recentResets = await checkResetCount(c.env.DB, userId, 3600000);
     if (recentResets >= 3) {
       return Errors.limitExceeded('Too many identity resets', 3600000).toResponse();
     }
     // ... proceed
   });
   ```
2. Log all identity reset events for security monitoring
3. Optionally notify the user's other sessions about the reset (via to-device messages)

---

### 4. Sliding Sync Accepts Unbounded Subscription Lists

**File:** `src/api/sliding-sync.ts` (lines ~32-34)  
**Severity:** High

The sliding sync endpoint processes `room_subscriptions` and `unsubscribe_rooms` from the request body without validating their size:

```typescript
// No limit on how many rooms can be subscribed in a single request
const subscriptions = body.room_subscriptions;  // Could be 100,000 entries
```

An attacker can send a single sync request subscribing to 100,000 rooms, forcing the server to:
- Look up each room in the database
- Check membership for each
- Fetch state for each
- Build responses for each

This single request could take minutes to process and consume significant database resources.

**Step-by-step fix:**
1. Cap `room_subscriptions` to 100 per request
2. Cap `lists` to 10 per request with `ranges` capped at 200 rooms per range
3. Cap `unsubscribe_rooms` to 100 per request
4. Return `M_TOO_LARGE` if limits are exceeded
5. Add overall response size limits — if the response would exceed 1MB, truncate and indicate partial results

---

### 5. Sliding Sync Connection State Never Expires

**File:** `src/api/sliding-sync.ts` (lines ~180-200)  
**Severity:** Medium

Connection state (which tracks a client's sync position, subscriptions, and cached data) is stored in the Sync Durable Object with no TTL or expiry mechanism:

```typescript
connectionState = await getConnectionState(syncDO, userId, connId);
```

Clients that disconnect without cleanly ending their sync session leave connection state permanently stored. Over time, each user accumulates stale connection objects from every browser tab, mobile app, and desktop client they've ever used.

**Step-by-step fix:**
1. Track `last_active_at` timestamp on each connection state
2. In the Sync DO's alarm handler, evict connection states not accessed in 24 hours
3. Limit active connections per user to 10 — reject new connections when exceeded (return `M_LIMIT_EXCEEDED`)
4. Provide an API endpoint for clients to explicitly close connections

---

### 6. Well-Known Delegation Cached for 1 Hour (Amplification Risk)

**File:** `src/services/server-discovery.ts` (lines ~127-191)  
**Severity:** Medium

The `.well-known` lookup is cached via Cloudflare cache for 1 hour:

```typescript
const response = await fetch(wellKnownUrl, {
  cf: { cacheTtl: 3600, cacheEverything: true },
});
```

An attacker controlling DNS for `attacker-matrix.com` can:
1. Return a `.well-known` pointing to `victim-service.com:8448`
2. Send federation traffic to `attacker-matrix.com` rooms
3. This server caches the delegation for 1 hour
4. For 1 hour, all federation requests to `attacker-matrix.com` hit `victim-service.com` — amplified DoS

**Step-by-step fix:**
1. Reduce initial cache TTL to 5 minutes for first-seen servers
2. Only extend to 1 hour after the delegation has been stable for multiple lookups
3. Rate-limit well-known lookups per domain (max 1 per minute)
4. Validate that the delegated target responds as a Matrix server before caching

---

### 7. Numeric Parameter Parsing Allows Negative Values

**Files:** `src/api/admin.ts` (~lines 135-136), `src/api/federation.ts` (~line 1135), multiple route files  
**Severity:** Low

Multiple endpoints parse `limit` and `offset` query parameters without lower-bound validation:

```typescript
const limit = Math.min(parseInt(c.req.query('limit') || '50'), 100);
// parseInt('-50') = -50; Math.min(-50, 100) = -50
const offset = parseInt(c.req.query('offset') || '0');
// Could be negative
```

Negative limits produce unexpected SQL behavior (`LIMIT -50` in SQLite returns all rows). Negative offsets are meaningless but may cause errors.

**Step-by-step fix:**
1. Apply consistent parsing everywhere:
   ```typescript
   const limit = Math.max(1, Math.min(parseInt(c.req.query('limit') || '50', 10) || 50, 100));
   const offset = Math.max(0, parseInt(c.req.query('offset') || '0', 10) || 0);
   ```
2. Create a shared `parsePositiveInt(value, defaultVal, maxVal)` utility
3. Apply it in all route files that accept pagination parameters

---

## Ideal Resolution

After these fixes:
- **Rate limiting uses trustworthy IP sources** and authenticates users for per-user limits
- **Rate limit counters are cleaned up on schedule** — no memory leak, no cyclic eviction
- **High-impact operations have operation-specific rate limits** beyond global IP limits
- **Sync requests are bounded** — no single request can subscribe to unlimited rooms
- **Stale connection state is cleaned up** — no unbounded growth in Sync DOs
- **Well-known delegation has short initial TTL** — reducing amplification window
- **All numeric parameters are bounded** — no negative values, no unbounded queries
