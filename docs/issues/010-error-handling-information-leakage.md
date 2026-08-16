# Issue 010: Error Handling & Information Leakage — Empty Catches, Exposed Internals, and Missing Response Headers

**Severity:** Medium  
**Domain:** Error Handling, Security, Observability  
**Affected files:** `src/api/admin.ts`, `src/api/rooms.ts`, `src/api/sliding-sync.ts`, `src/api/media.ts`, `src/api/federation.ts`, multiple route files

---

## Problem Statement

Error handling across the codebase follows three problematic patterns simultaneously: (1) errors are silently swallowed via empty catch blocks, making bugs invisible; (2) internal error details are exposed in API responses, leaking implementation information to attackers; and (3) fire-and-forget promises lose errors from important background operations. These issues compound — when something goes wrong, the server either tells the attacker too much or tells the operator too little. The result is a system that is both insecure (information leakage) and undebuggable (silent failures).

---

## Detailed Breakdown

### 1. Internal Error Details Exposed in API Responses

**File:** `src/api/admin.ts` (line ~1447), `src/api/federation.ts` (multiple catch blocks)  
**Severity:** Medium-High

Several catch blocks include raw exception messages in the response body:

```typescript
// admin.ts ~line 1447
return c.json({
  errcode: 'M_INVALID_PARAM',
  error: `Failed to fetch OIDC discovery from issuer: ${err}`,
}, 400);
```

The `${err}` interpolation can include:
- Full stack traces with file paths and line numbers
- Database error messages revealing schema details
- Network error messages revealing internal hostnames/IPs
- Third-party service error messages revealing integration details

An attacker probing endpoints can map the internal architecture by triggering different error paths.

**Step-by-step fix:**
1. Create a standardized error response utility:
   ```typescript
   function safeErrorResponse(errcode: string, publicMessage: string, internalError: unknown) {
     console.error(`[${errcode}] ${publicMessage}:`, internalError);
     return { errcode, error: publicMessage };
   }
   ```
2. Never include `err`, `err.message`, or `err.stack` in response bodies
3. Use generic messages for client-facing errors: "Failed to fetch OIDC discovery" (not "...from issuer: Connection refused to 10.0.1.5:443")
4. Log the full error server-side for debugging
5. Audit all catch blocks in route handlers for information leakage

---

### 2. Empty Catch Blocks Silently Swallow Errors

**Files:** `src/api/sliding-sync.ts` (~line 903), `src/api/media.ts`, `src/api/rooms.ts`, multiple files  
**Severity:** Medium

The codebase has many instances of empty catch blocks:

```typescript
try { ... } catch { }
// or
try { ... } catch { /* ignore */ }
// or
somePromise.catch(() => {});
```

These make failures invisible. When a sliding sync operation silently fails to parse a `fully_read` marker, the user sees stale read positions with no indication that anything went wrong. When cache invalidation silently fails, subsequent requests serve stale data. When a notification fails to send, the user misses important messages.

**Step-by-step fix:**
1. Replace every empty catch with at minimum a `console.warn()`:
   ```typescript
   try { ... } catch (err) {
     console.warn('[sliding-sync] Failed to parse fully_read marker:', err);
   }
   ```
2. For operations where the failure is truly ignorable (rare), add a comment explaining WHY:
   ```typescript
   try { ... } catch {
     // Safe to ignore: cache invalidation is best-effort; TTL handles staleness
   }
   ```
3. For operations where failure affects correctness (notification sending, state updates), propagate the error or implement retry logic
4. Set up structured logging so these warnings are aggregable and alertable

---

### 3. Fire-and-Forget Promises Lose Errors

**File:** `src/api/rooms.ts` (~line 823, ~1025), multiple files  
**Severity:** Medium

Background operations are started without awaiting completion or tracking failure:

```typescript
// Room state change notification
invalidateRoomCache(c.env.CACHE, roomId).catch(() => {});

// Sync notification
notifySyncDO(c.env.SYNC, userId).catch(err => {
  console.error('Failed to notify sync:', err);
});
```

The first example silently drops failures. The second logs but doesn't retry or track. For operations that affect user experience (sync notifications, cache invalidation, push notifications), these lost errors mean degraded service with no operational visibility.

**Step-by-step fix:**
1. For user-impacting background operations, use `ctx.waitUntil()` to ensure they complete before the Worker shuts down:
   ```typescript
   c.executionCtx.waitUntil(
     invalidateRoomCache(c.env.CACHE, roomId)
       .catch(err => console.error('[rooms] Cache invalidation failed:', err))
   );
   ```
2. Track failure rates via a counter or metric
3. For critical operations (push notifications), implement at-least-once delivery via a queue

---

### 4. Promise.all Without Error Isolation

**File:** `src/api/rooms.ts` (~line 859), `src/api/admin.ts` (~lines 1407-1418)  
**Severity:** Low-Medium

Some endpoints use `Promise.all()` to fetch multiple pieces of data in parallel, but if ANY promise rejects, the entire response fails:

```typescript
const [members, state, timeline] = await Promise.all([
  getMembers(db, roomId),
  getState(db, roomId),
  getTimeline(db, roomId),
]);
```

If `getTimeline` fails (e.g., database timeout), the client gets a 500 error even though members and state were successfully fetched. For partial-availability scenarios, returning partial data is better than returning nothing.

**Step-by-step fix:**
1. Use `Promise.allSettled()` for non-critical parallel fetches:
   ```typescript
   const results = await Promise.allSettled([getMembers(), getState(), getTimeline()]);
   const members = results[0].status === 'fulfilled' ? results[0].value : [];
   ```
2. For critical data (where partial response would be misleading), keep `Promise.all()` but wrap in try-catch with a meaningful error response
3. Log which sub-queries failed for debugging

---

### 5. Admin Password Reset Has No Audit Trail

**File:** `src/api/admin.ts` (lines ~269-298)  
**Severity:** Medium

The admin password reset endpoint changes a user's password and revokes their sessions, but:
- No audit log entry is created
- The affected user receives no notification that their password was changed
- There's no record of which admin performed the reset

A malicious or compromised admin account can silently take over any user account by resetting their password, with no trail for investigation.

**Step-by-step fix:**
1. Log all admin actions to an `admin_audit_log` table: `(timestamp, admin_user_id, action, target_user_id, details)`
2. Send a to-device message or notification to the affected user's devices informing them of the password change
3. Include the admin's user ID in the audit entry
4. Make the audit log read-only (no DELETE permission for the admin API)

---

### 6. Login Tokens Returned in Plaintext Response

**File:** `src/api/admin.ts` (line ~1366)  
**Severity:** Medium

The admin QR login endpoint returns the raw login token in the response:

```typescript
return c.json({
  token: loginToken,
  qr_url: `${protocol}://${host}/login/qr/${loginToken}`,
});
```

The token appears in:
- HTTP response bodies (logged by proxies, CDN logs, browser DevTools)
- Browser history (if opened as a URL)
- Server access logs (if the QR URL is visited)

**Step-by-step fix:**
1. Return only a short-lived reference ID that can be exchanged for the actual token via a separate endpoint
2. Set a very short TTL on login tokens (5 minutes)
3. Make tokens single-use — invalidate after first use
4. Include `Cache-Control: no-store` on the response to prevent caching

---

## Ideal Resolution

After these fixes:
- **Error responses contain only generic messages** — internal details are logged server-side only
- **No error is silently swallowed** — every catch block at minimum logs the failure
- **Background operations are tracked** — failures are visible in logs and metrics
- **Parallel fetches degrade gracefully** — partial data is preferred over total failure
- **Admin actions have an audit trail** — every sensitive operation is logged with who, what, when
- **Sensitive tokens are not exposed** in logs, responses, or URLs
