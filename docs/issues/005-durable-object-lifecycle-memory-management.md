# Issue 005: Durable Object Lifecycle & Memory Management — Unbounded Growth, Missing Cleanup, and Alarm Failures

**Severity:** High  
**Domain:** Infrastructure, Durable Objects, Scalability  
**Affected files:** `src/durable-objects/SyncDurableObject.ts`, `src/durable-objects/RoomDurableObject.ts`, `src/durable-objects/RateLimitDurableObject.ts`, `src/durable-objects/FederationDurableObject.ts`, `src/durable-objects/call-room.ts`, `src/durable-objects/AdminDurableObject.ts`, `src/durable-objects/PushDurableObject.ts`

---

## Problem Statement

Durable Objects (DOs) are the coordination backbone for real-time features — WebSocket presence, sync long-polling, federation queues, rate limiting, and video calls. Multiple DOs have unbounded in-memory data structures with no size limits or cleanup, broken alarm scheduling that prevents garbage collection, race conditions in concurrent resolver lists, and silent broadcast failures. Under sustained load, these issues cause progressive memory exhaustion, service degradation, and eventually DO eviction — which for a Matrix homeserver means dropped connections, lost events, and broken real-time features.

---

## Detailed Breakdown

### 1. SyncDurableObject: Race Condition in Long-Polling Wait List

**File:** `src/durable-objects/SyncDurableObject.ts` (lines ~240-262)  
**Severity:** Critical

The sync DO maintains a `waitingResolvers` array for long-polling clients. When a new event arrives, `handleNotify()` resolves all waiting promises and clears the array. Simultaneously, the cleanup logic in `handleWaitForEvents()` removes individual resolvers by index when their timeout expires.

```typescript
// handleNotify:
this.waitingResolvers = [];  // Clears entire array

// handleWaitForEvents cleanup (concurrent):
this.waitingResolvers.splice(index, 1);  // Removes by index
```

If `handleNotify()` runs between the timeout firing and the splice executing, the index is stale — it may remove the wrong resolver or throw. Conversely, if a timeout and notify race, the resolver might be called twice or not at all.

**Step-by-step fix:**
1. Replace the array with a `Map<string, Resolver>` keyed by a unique request ID
2. On notify, iterate the map and resolve all, then clear
3. On timeout, delete by key (safe even if already removed by notify)
4. Add a flag per resolver: `resolved: boolean` — check before resolving to prevent double-resolution

---

### 2. SyncDurableObject: Unbounded Storage Iteration in getPendingEvents

**File:** `src/durable-objects/SyncDurableObject.ts` (lines ~289-304)  
**Severity:** High

The `getPendingEvents()` method loads all stored events with a prefix scan:

```typescript
await this.ctx.storage.list({ prefix: 'event:' })  // No limit!
```

If a DO accumulates thousands of events (e.g., during a client's extended offline period), this loads all of them into memory in a single call. Cloudflare DO storage `list()` returns up to 128 keys by default, but the code may iterate to get all entries.

**Step-by-step fix:**
1. Add a limit parameter: `list({ prefix: 'event:', limit: 1000 })`
2. If more events exist than the limit, return the newest 1000 and include a "gap" indicator so the client knows to do an initial sync
3. Implement event compaction: after delivering events to a client, delete them from storage

---

### 3. RateLimitDurableObject: Alarm Never Actually Scheduled

**File:** `src/durable-objects/RateLimitDurableObject.ts` (lines ~104-126)  
**Severity:** High

The `scheduleCleanup()` method sets a flag (`this.cleanupAlarm`) but never calls the actual DO alarm API:

```typescript
scheduleCleanup() {
  this.cleanupAlarm = true;
  // Missing: this.ctx.storage.setAlarm(Date.now() + CLEANUP_INTERVAL);
}
```

Without `ctx.storage.setAlarm()`, no alarm ever fires. The in-memory rate limit counters accumulate indefinitely. Over hours of operation, memory grows unbounded until the DO is evicted.

**Step-by-step fix:**
1. Add `await this.ctx.storage.setAlarm(Date.now() + CLEANUP_INTERVAL_MS)` in the schedule method
2. Implement the `alarm()` handler to iterate counters and remove expired windows
3. After cleanup, reschedule the next alarm if counters remain
4. Cap the counter map size with a `MAX_TRACKED_IPS` limit as a safety valve

---

### 4. FederationDurableObject: Queue Grows Without Bound

**File:** `src/durable-objects/FederationDurableObject.ts` (lines ~62-87, ~238-308)  
**Severity:** High

Each outbound federation event is added to storage without any queue size check:

```typescript
handleSend(event) {
  await this.ctx.storage.put(`outbound:${key}`, event);
  // No check: how many events are already queued?
}
```

If a remote server goes offline (common in federation), events accumulate indefinitely. The retry logic uses exponential backoff but never drops events after maximum retries. A single unresponsive remote server can cause its federation DO to consume ever-increasing storage.

**Step-by-step fix:**
1. Before enqueuing, check queue size: `const keys = await this.ctx.storage.list({ prefix: 'outbound:', limit: 1 }); if (count > 10000) return 429`
2. Add a maximum retry count (e.g., 32 retries ≈ several days with exponential backoff). After max retries, move to a dead-letter queue or discard.
3. Cap the backoff delay: `Math.min(60000 * Math.pow(2, retryCount - 1), 86400000)` (1 day max)
4. Parse federation response bodies — a 200 response may contain partial failures that should be re-queued individually

---

### 5. FederationDurableObject: Response Not Validated Before Event Deletion

**File:** `src/durable-objects/FederationDurableObject.ts` (lines ~282-286)  
**Severity:** High

After successfully sending a federation transaction (HTTP 200), the code deletes all events from the queue without checking whether the remote server actually accepted the PDUs:

```typescript
// HTTP 200 received
for (const key of batchKeys) {
  await this.ctx.storage.delete(key);  // Events gone forever
}
```

A remote server can return 200 with a body indicating partial failures (e.g., `{ "pdus": { "$event1": { "error": "..." } } }`). The current code treats any 200 as full success and permanently deletes all events, including those the remote server rejected.

**Step-by-step fix:**
1. Parse the response body and check per-PDU results
2. Only delete events that were explicitly accepted
3. Re-queue events that were rejected with retryable errors
4. Log events rejected with permanent errors and move to dead-letter storage

---

### 6. CallRoomDurableObject: Broadcast Failures Are Silent

**File:** `src/durable-objects/call-room.ts` (lines ~516-523)  
**Severity:** Medium

The `broadcast()` function iterates all participants and sends a message to each WebSocket, but individual send failures are not caught:

```typescript
for (const participant of this.participants.values()) {
  this.send(participant.webSocket, msg);  // Can throw — not caught
}
```

If one WebSocket send throws (disconnected client, buffer full), the exception may abort the loop, preventing the message from reaching subsequent participants.

**Step-by-step fix:**
1. Wrap each send in try-catch:
   ```typescript
   for (const participant of this.participants.values()) {
     try { this.send(participant.webSocket, msg); }
     catch { failedParticipants.push(participant.id); }
   }
   ```
2. After the loop, clean up failed participants (close WebSocket, remove from map)
3. Log broadcast failure rates for monitoring

---

### 7. RoomDurableObject: In-Memory Maps Not Capped

**File:** `src/durable-objects/RoomDurableObject.ts` (lines ~25-34)  
**Severity:** Medium

The Room DO maintains several in-memory maps — WebSocket sessions, typing users, read receipts — with no size limits:

```typescript
sessions: Map<WebSocket, RoomSession>    // Unbounded
typingUsers: Map<string, number>          // Unbounded
receipts: Map<string, ReceiptData>        // Unbounded
```

For a large room (10K+ members) with many active connections, these maps can grow to consume significant memory, risking DO eviction.

**Step-by-step fix:**
1. Cap WebSocket connections per room (e.g., 500 concurrent) — return 503 when exceeded
2. Implement TTL-based eviction for typing users (they already have timeouts, but ensure the map is cleaned)
3. For receipts, keep only the most recent per-user (already likely the case, but enforce with a cap)
4. Monitor DO memory usage and alert on thresholds

---

### 8. SyncDurableObject: Event Storage Cleanup Depends on Fragile Alarms

**File:** `src/durable-objects/SyncDurableObject.ts` (lines ~349-363)  
**Severity:** Medium

Event cleanup is triggered by an alarm scheduled 1 hour in the future:

```typescript
setAlarm(Date.now() + 3600000);  // 1 hour
```

If the DO is evicted before the alarm fires, the alarm is lost. Cloudflare DOs do persist alarms across restarts, but if the DO is hibernated and no wake event arrives, events accumulate indefinitely until a client reconnects.

**Step-by-step fix:**
1. Use bounded storage with key rotation: prefix event keys with a time-based bucket (e.g., `event:2024-01-15T12:` )
2. On each write, check if old buckets exist and delete them
3. This ensures cleanup happens on every write, not just on alarm ticks
4. Keep the alarm as a secondary cleanup mechanism for truly idle DOs

---

### 9. PushDurableObject: JWT Token Cache TTL Too Close to Expiry

**File:** `src/durable-objects/PushDurableObject.ts` (lines ~206-224)  
**Severity:** Medium

JWT tokens for APNs are cached for 50 minutes, but they expire after 60 minutes. This leaves only a 10-minute buffer. If clock skew, network latency, or key rotation occurs, push notifications fail silently with expired tokens.

**Step-by-step fix:**
1. Reduce cache TTL to 30 minutes (50% of token lifetime)
2. Add error handling for 401/403 responses from APNs that invalidates the cache and retries with a fresh token
3. Log token refresh events for monitoring

---

### 10. Workflow Fetch Calls Lack Timeouts

**File:** `src/workflows/RoomJoinWorkflow.ts` (lines ~153-158, ~248-254)  
**Severity:** Medium

All outbound HTTP calls in workflows use bare `fetch()` without timeouts:

```typescript
const response = await fetch(url, { method: 'GET', headers: { ... } });
```

If a remote server hangs (accepts TCP connection but never responds), the workflow step hangs until the platform-level timeout (which may be 30 seconds or more). This wastes workflow execution time and can cascade.

**Step-by-step fix:**
1. Add `AbortSignal.timeout()` to all fetch calls: `fetch(url, { signal: AbortSignal.timeout(10000) })`
2. Handle `AbortError` in catch blocks with appropriate retry logic
3. Apply this pattern to all workflows, not just RoomJoinWorkflow

---

## Ideal Resolution

After these fixes:
- **All in-memory data structures have size caps** — no unbounded growth possible
- **Rate limit cleanup actually runs** — alarms are properly scheduled and fire
- **Federation queues have bounded size and maximum retry limits** — unresponsive servers don't cause infinite growth
- **Broadcast operations are resilient** — one failed WebSocket doesn't block others
- **Long-polling resolvers are race-free** — Map-based keying prevents stale index corruption
- **Workflow HTTP calls have timeouts** — no single slow server can stall an entire workflow
