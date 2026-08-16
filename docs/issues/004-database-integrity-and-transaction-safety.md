# Issue 004: Database Integrity & Transaction Safety — Race Conditions, Missing Foreign Keys, and D1 Limitations

**Severity:** Critical / High  
**Domain:** Database, Data Integrity  
**Affected files:** `src/services/database.ts`, `src/api/rooms.ts`, `src/api/sliding-sync.ts`, `migrations/*.sql`

---

## Problem Statement

The D1 database layer is the canonical source of truth for all room state, events, memberships, and user data. This layer has a critical race condition in event ordering, widespread missing foreign key constraints leading to orphaned data, no transaction wrapping for multi-step operations, and unaddressed D1-specific platform limitations. Under concurrent load — which is the normal operating condition for a Matrix homeserver — these issues can cause events to appear out of order, rooms to be partially created, and data to become permanently inconsistent.

---

## Detailed Breakdown

### 1. Stream Ordering Race Condition (Critical)

**File:** `src/services/database.ts` (lines ~255-261)

The `storeEvent()` function determines the next stream ordering value by reading `MAX(stream_ordering)` and then incrementing it:

```typescript
const lastOrdering = await db.prepare(
  `SELECT MAX(stream_ordering) as max_ordering FROM events`
).first<{ max_ordering: number | null }>();

const streamOrdering = (lastOrdering?.max_ordering ?? 0) + 1;

await db.prepare(
  `INSERT INTO events (...stream_ordering...) VALUES (..., ?)`
).bind(..., streamOrdering).run();
```

This is a classic read-then-write race condition. When two events are stored concurrently:
1. Request A reads `MAX(stream_ordering)` → gets 100
2. Request B reads `MAX(stream_ordering)` → also gets 100
3. Request A inserts with `stream_ordering = 101`
4. Request B inserts with `stream_ordering = 101` (DUPLICATE!)

Impact: Duplicate stream orderings break the `/sync` endpoint's ability to deliver events in order. Clients may skip events entirely or see them duplicated. This is the most fundamental data integrity invariant for a Matrix homeserver, and it is violated under concurrent writes.

The codebase already has the correct pattern elsewhere — `src/api/to-device.ts` uses atomic `UPDATE ... RETURNING`:

```typescript
const result = await db.prepare(`
  UPDATE stream_positions
  SET position = position + 1
  WHERE stream_name = ?
  RETURNING position
`).bind(streamName).first<{ position: number }>();
```

**Step-by-step fix:**
1. Add a row to the `stream_positions` table for `'events'` stream
2. Replace the `SELECT MAX` + manual increment with the atomic `UPDATE ... RETURNING` pattern
3. Add a unique constraint on `events(stream_ordering)` as a safety net
4. Verify all callers of `storeEvent()` handle the new pattern correctly
5. Add a migration to backfill the `stream_positions` row with the current MAX value

---

### 2. No Transaction Wrapping for Room Creation (Critical)

**File:** `src/api/rooms.ts` (lines ~82-235)

The `createInitialRoomEvents()` function creates 5+ events in sequence — create event, creator join, power levels, join rules, history visibility, and optionally name/topic/alias. Each is a separate `INSERT` with no transaction boundary:

```typescript
const createEventId = await createEvent('m.room.create', ...);
const joinEventId = await createEvent('m.room.member', ...);
await updateMembership(db, roomId, creatorId, 'join', joinEventId);
const plEventId = await createEvent('m.room.power_levels', ...);
// ... more events
```

If any step fails (D1 timeout, quota exceeded, constraint violation), the room exists in a partially-created state with missing fundamental state events. A room without power levels, for example, becomes ungovernable. A room without join rules may be inaccessible.

D1 does not support explicit `BEGIN`/`COMMIT`/`ROLLBACK` transactions. This is a fundamental platform limitation.

**Step-by-step fix:**
1. Use D1's `batch()` API to submit all room creation queries in a single batch (D1 executes batches atomically)
2. Build all event objects first, compute all IDs, then submit the entire batch:
   ```typescript
   const statements = [
     db.prepare('INSERT INTO events ...').bind(...createEvent),
     db.prepare('INSERT INTO events ...').bind(...joinEvent),
     db.prepare('INSERT INTO room_memberships ...').bind(...),
     // ... all statements
   ];
   await db.batch(statements);
   ```
3. If batch fails, no partial state is committed
4. Add a health check that detects rooms with missing required state events and flags them for repair

---

### 3. Missing Foreign Key Constraints Across Multiple Tables (High)

**Files:** `migrations/002_phase1_e2ee.sql`, `migrations/010_fix_reports_schema.sql`, `migrations/schema.sql`

Multiple tables reference users, rooms, and events without foreign key constraints, allowing orphaned records to accumulate when the referenced entities are deleted:

| Table | Column | Missing FK Target | Impact |
|-------|--------|-------------------|--------|
| `notification_queue` | `room_id` | `rooms(room_id)` | Room deletion leaves orphaned notifications |
| `notification_queue` | `event_id` | `events(event_id)` | Event deletion leaves orphaned notifications |
| `event_relations` | `relates_to_id` | `events(event_id)` | Event deletion leaves orphaned relations |
| `to_device_messages` | `recipient_user_id` | `users(user_id)` | User deletion leaves undelivered messages |
| `to_device_messages` | `sender_user_id` | `users(user_id)` | Sender deletion doesn't cascade |
| `content_reports` | `reported_user_id` | `users(user_id)` | Reports survive user deletion |
| `key_backup_keys` | `room_id` | `rooms(room_id)` | Room deletion leaves orphaned backup keys |

Existing tables also have inconsistent cascade behavior — some tables cascade on user deletion, others don't, creating unpredictable cleanup behavior.

**Step-by-step fix:**
1. Create a new migration (`012_add_foreign_keys.sql`) that adds the missing constraints
2. Since SQLite doesn't support `ALTER TABLE ADD CONSTRAINT`, use the recreate-table pattern:
   - Create new table with correct constraints
   - Copy data from old table (cleaning orphaned rows)
   - Drop old table
   - Rename new table
3. Add `ON DELETE CASCADE` for all user/room/event references where the child data has no value without the parent
4. Add indexes on all foreign key columns (SQLite doesn't auto-index FKs)
5. Ensure `PRAGMA foreign_keys = ON` is set (D1 may need this verified)

---

### 4. Duplicate Migration File Numbering

**Files:** `migrations/005_server_config.sql` and `migrations/005_idp_providers.sql`

Both files share the migration number 005. Migration runners process files alphabetically within the same number, making the execution order fragile and platform-dependent.

**Step-by-step fix:**
1. Rename `005_server_config.sql` to `005b_server_config.sql` (or re-number to `006` and shift subsequent files)
2. Verify the rename doesn't break any existing deployments by checking D1's migration tracking table

---

### 5. N+1 Query Pattern in Sliding Sync Required State

**File:** `src/api/sliding-sync.ts` (lines ~493-534)  
**Severity:** High (Performance)

When a client requests `required_state` with multiple event types, the code executes a separate database query for each type inside a loop:

```typescript
for (const [eventType, stateKey] of config.requiredState) {
  let stateQuery = `SELECT ... FROM room_state rs JOIN events e ...`;
  const stateEvents = await db.prepare(stateQuery).bind(...stateParams).all();
}
```

If a client requests 20 state types (typical for Element X), this runs 20 sequential database queries per room per sync. For a user in 100 rooms, that's 2,000 database round-trips per sync request.

**Step-by-step fix:**
1. Build a single query with OR conditions:
   ```sql
   SELECT ... FROM room_state rs JOIN events e ...
   WHERE rs.room_id = ? AND (
     (rs.event_type = ? AND rs.state_key = ?) OR
     (rs.event_type = ? AND rs.state_key = ?) OR ...
   )
   ```
2. Or use `db.batch()` to execute all queries in a single network round-trip
3. For wildcard state keys (`*`), use a single `WHERE rs.event_type = ?` without the state_key condition

---

### 6. D1-Specific Platform Limitations Not Addressed

**File:** `src/services/database.ts` (lines ~263-282)  
**Severity:** Medium

Large events are stored as JSON in TEXT columns with no size validation:

```typescript
await db.prepare('INSERT INTO events ...').bind(
  ...,
  JSON.stringify(event.content),      // Unbounded
  JSON.stringify(event.unsigned),     // Unbounded
  JSON.stringify(event.auth_events),
  JSON.stringify(event.prev_events),
  JSON.stringify(event.signatures),
);
```

D1 has documented limits: 1MB per row (approximate), 20MB response size per query, and batch read limits. None of these are validated before writes, leading to silent failures.

Additionally, the `getAuthChain()` function (`database.ts` ~lines 687-704) iterates through auth chains with no maximum depth, potentially fetching thousands of events in a recursive pattern.

**Step-by-step fix:**
1. Add pre-insert validation: `if (JSON.stringify(event).length > 500_000) reject with M_TOO_LARGE`
2. Cap auth chain traversal depth: add `MAX_AUTH_CHAIN_SIZE = 500` and abort traversal when reached
3. Add pagination to `getEventsByIds()` when the ID list exceeds 100 entries
4. Document D1 limits in code comments alongside each affected query

---

## Ideal Resolution

After these fixes:
- **Event stream ordering is atomically assigned** — no duplicates possible under concurrent writes
- **Room creation is atomic** — either all state events are created or none are
- **All referential relationships are enforced** at the database level — no orphaned records
- **Sync queries execute in bounded time** with batch queries instead of N+1 loops
- **D1 platform limits are validated** before writes — operations fail gracefully with meaningful errors instead of silently corrupting data
