# Issue 009: Room Operations Race Conditions — Concurrent Joins, State Writes, and TOCTOU Permission Checks

**Severity:** High  
**Domain:** Rooms, Data Integrity  
**Affected files:** `src/api/rooms.ts`, `src/api/account-data.ts`

---

## Problem Statement

Room operations — joining, leaving, sending state events, and updating power levels — perform multi-step sequences of database reads and writes without any form of locking or atomicity. Under concurrent access (which is normal for active Matrix rooms), these sequences are vulnerable to time-of-check-time-of-use (TOCTOU) race conditions. Two users can join simultaneously and create duplicate membership events. Two state event writes can interleave and produce an inconsistent state snapshot. Power level checks can pass at check time but be stale by write time. These issues produce corrupted room state that is difficult to detect and impossible to automatically repair.

---

## Detailed Breakdown

### 1. Join Operation Race Condition — Duplicate Membership Events

**File:** `src/api/rooms.ts` (lines ~435-492)  
**Severity:** High

The join flow follows a check-then-act pattern with no atomicity:

```
Step 1: Read current membership for (user, room)      → null (not a member)
Step 2: ... another concurrent request also reads ...  → null (not a member)
Step 3: Create join event in events table
Step 4: Update membership in room_memberships table
Step 5: ... other request also creates join event ...
Step 6: ... other request also updates membership ...
```

Result: Two join events for the same user in the same room. The `room_memberships` table might end up with the second write winning (last-write-wins), but the `events` table has two join events — confusing clients and breaking event ordering assumptions.

This can happen when:
- A user rapidly clicks "join" in a slow-loading UI
- A client retries a join request that it thought timed out
- Federation and local join attempt the same join simultaneously

**Step-by-step fix:**
1. Add a unique constraint on `room_memberships(room_id, user_id)` with `ON CONFLICT REPLACE`
2. Use D1's `batch()` to atomically check membership and insert event in one operation
3. Generate the join event ID deterministically (based on room_id + user_id + timestamp) so duplicate inserts produce the same event
4. Use `INSERT OR IGNORE` for the event insertion to silently skip duplicates
5. Return the existing membership event if a join is already in progress

---

### 2. State Event Write Interleaving

**File:** `src/api/rooms.ts` (lines ~775-843)  
**Severity:** High

Sending state events follows a multi-step sequence:
1. Fetch current room state (power levels, auth events)
2. Validate sender has permission for this state event type
3. Build the new state event
4. Store the event
5. Update the `room_state` table to point to the new event

Between steps 1 and 5, another request can:
- Change power levels (making step 2's permission check stale)
- Write a different state event of the same type (step 5 overwrites it)
- Join or leave the room (changing the auth context)

For critical state events like `m.room.power_levels`, interleaving can produce incoherent power configurations — e.g., two admins simultaneously reducing each other's power level, resulting in a room where nobody has admin power.

**Step-by-step fix:**
1. Route all state event writes through the Room Durable Object, which provides single-threaded execution per room
2. The DO serializes all state changes: only one state event is processed at a time per room
3. After each state event, the DO updates its cached state snapshot and uses it for the next check
4. Alternatively, use optimistic concurrency: include the current state event ID in the write, and fail with `M_CONFLICT` if it changed between check and write

---

### 3. TOCTOU in Power Level Checks

**File:** `src/api/rooms.ts` (pattern throughout, e.g., lines ~757-843)  
**Severity:** Medium

Every permission check follows the same pattern:
1. Load power levels from database
2. Compare user's power level against the required level
3. If authorized, proceed with the operation

Between step 2 and step 3, a concurrent request can change the power levels (demoting the user, promoting someone else, changing the required levels). This is especially dangerous for operations that themselves change power levels — a user could be demoted by one request but the demotion doesn't take effect until after the user has already submitted a state change.

**Step-by-step fix:**
1. Use the Room DO for serialization (preferred) — same fix as issue 2
2. Or implement versioned power levels: include the power level event ID in each state change, and reject if it has changed since the check
3. For non-state operations (sending messages), the race window is acceptable since the worst case is a message sent by a just-demoted user

---

### 4. Cache Invalidation Failures Silently Swallowed

**File:** `src/api/rooms.ts` (line ~823)  
**Severity:** Low-Medium

After state changes, cache invalidation errors are silently ignored:

```typescript
invalidateRoomCache(c.env.CACHE, roomId).catch(() => {});
```

If cache invalidation fails, subsequent reads may serve stale state — including stale power levels, stale membership lists, and stale room names. This creates a window where the system believes outdated state is current.

**Step-by-step fix:**
1. Log cache invalidation failures (don't just discard the error)
2. Add a cache generation counter: increment on writes, include in cached data, reject cached data with stale generation
3. Set short TTLs on critical cached data (power levels, membership) — e.g., 60 seconds — so stale cache self-heals quickly

---

### 5. Account Data Race Condition

**File:** `src/api/account-data.ts`  
**Severity:** Low-Medium

Account data PUT operations follow the same check-then-write pattern. Two concurrent writes to the same account data key can interleave, with the last write winning and no merge logic. This is less critical than room state races because account data is typically user-private, but it can still cause data loss if a client writes rapidly (e.g., updating notification settings from multiple devices).

**Step-by-step fix:**
1. Use `INSERT OR REPLACE` (upsert) to make writes idempotent
2. Include a `version` field in account data and reject writes with stale versions
3. Return the stored version in the response so clients can detect conflicts

---

## Ideal Resolution

After these fixes:
- **Room joins are idempotent** — duplicate join requests produce the same result, not duplicate events
- **State event writes are serialized** — either through the Room DO or optimistic concurrency control
- **Permission checks are atomic with the authorized operation** — no TOCTOU window
- **Cache invalidation failures are logged and bounded** — stale cache self-heals via TTL
- **Account data writes are conflict-aware** — clients can detect and resolve concurrent modifications
