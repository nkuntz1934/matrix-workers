# Issue 006: Federation Event Validation & State Resolution — Incomplete Auth Rules, Backfill Exposure, and Join Rule Bypass

**Severity:** High  
**Domain:** Federation, Spec Compliance  
**Affected files:** `src/api/federation.ts`, `src/workflows/RoomJoinWorkflow.ts`, `src/utils/url-validator.ts`

---

## Problem Statement

Beyond the authentication failures documented in Issue 001, the federation event processing pipeline has critical gaps in how it validates, authorizes, and resolves inbound events. State resolution is incomplete, backfill endpoints expose room history without membership checks, invite processing doesn't verify sender authority, join rule enforcement is missing, and the SSRF protections have IPv6 coverage gaps. These issues allow a federated peer to extract room data it shouldn't have access to, inject events that bypass room governance rules, and potentially probe the internal network.

---

## Detailed Breakdown

### 1. State Resolution Is Incomplete and Incorrectly Invoked

**File:** `src/api/federation.ts` (lines ~654-695)  
**Severity:** High

The `/send/:txnId` endpoint attempts state resolution only when a PDU has multiple `prev_events`:

```typescript
if (prevEvents.length > 1 && room) {
  const resolved = resolveState(room.room_version, [currentState, [newEvent]]);
}
```

Problems:
- State resolution should also apply for single `prev_events` when the event conflicts with current state
- The function call signature appears incorrect — `resolveState()` should receive state sets (arrays of state events), not `[currentState, [newEvent]]`
- If state resolution throws (line ~683), the code silently falls back without applying auth rules — accepting the event without governance
- There's no verification that the room version is supported or that the events conform to that room version's format

**Step-by-step fix:**
1. Implement state resolution for ALL inbound state events, regardless of `prev_events` count
2. Correct the `resolveState()` invocation to pass proper state sets per the algorithm specification
3. On state resolution failure, REJECT the event rather than silently accepting it
4. Validate room version support before attempting resolution
5. Implement room version-specific event format validation (v1-v11 have different requirements)

---

### 2. Backfill Endpoint Serves Room History Without Membership Check

**File:** `src/api/federation.ts` (lines ~1132-1199)  
**Severity:** High

The `/backfill/:roomId` endpoint returns events ordered by depth without checking whether the requesting server has any legitimate reason to access this room's history:

```typescript
app.get('/_matrix/federation/v1/backfill/:roomId', async (c) => {
  // Just returns events — no membership check
  return c.json({ origin: c.env.SERVER_NAME, pdus });
});
```

Any authenticated federation server can enumerate ALL events in any room by:
1. Discovering a room_id (from any federated interaction)
2. Calling backfill with various `v` parameters to walk the event DAG
3. Extracting the complete message history of private rooms

The same issue affects `/get_missing_events/:roomId` (lines ~1201-1291) — no ownership or membership check.

Additionally, the backfill endpoint doesn't validate its query parameters:
- `limit` can be negative (`parseInt('-50')`)
- The `v` parameter (starting event IDs) accepts unbounded comma-separated lists, potentially causing large IN queries

**Step-by-step fix:**
1. Before serving backfill, verify the requesting server has at least one user in the room's membership list
2. Apply the same check to `/get_missing_events`
3. Validate `limit` is positive and bounded: `Math.max(1, Math.min(parseInt(limit), 100))`
4. Limit the number of `v` event IDs to 20
5. Validate event ID format matches `$<base64url>` pattern

---

### 3. Invite Processing Doesn't Verify Sender Authority

**File:** `src/api/federation.ts` (lines ~1708-1903)  
**Severity:** High

The federation invite endpoints (`/invite/:roomId/:eventId` v1 and v2) accept invite events from authenticated remote servers but don't verify:
- Whether the invite event's sender has invite power level in the room
- Whether the sender's server has authority over the sender user ID
- Whether the invite is for a user that belongs to the local server

An authenticated-but-malicious server could forge an invite event, have this server sign and return it, and then use that signed event elsewhere as if this server endorsed the invite.

**Step-by-step fix:**
1. Verify the invite event's `sender` field belongs to the authenticated origin server (`@user:origin`)
2. Verify the `state_key` (invited user) belongs to the local server
3. Check current room state to verify the sender has sufficient power level for invites
4. Validate the invite event structure before signing and returning it
5. Rate-limit invite processing per origin server

---

### 4. make_join Doesn't Check Join Rules

**File:** `src/api/federation.ts` (lines ~1293-1441)  
**Severity:** Medium

The `/make_join/:roomId/:userId` endpoint prepares a join event template without checking the room's join rules:

```typescript
const eventTemplate = {
  room_id: roomId,
  sender: userId,
  type: 'm.room.member',
  state_key: userId,
  content: { membership: 'join' },
};
return c.json({ room_version: room.room_version, event: eventTemplate });
```

This serves a valid-looking join template even when:
- The room's join rules are set to `private` (should only allow invited users)
- The user is banned from the room
- The room uses restricted joins (room version 8+) requiring membership in a linked space
- The room is set to `knock` (should require a knock, not direct join)

**Step-by-step fix:**
1. Fetch the current `m.room.join_rules` state event for the room
2. If `join_rule === 'private'` or `join_rule === 'invite'`: verify the user has a pending invite
3. If `join_rule === 'knock'`: return an error directing the server to use `make_knock` instead
4. If `join_rule === 'restricted'`: verify the user meets the `allow` conditions
5. Check the ban list: reject if the user is banned
6. Return appropriate Matrix error codes for each rejection reason

---

### 5. Room Join Workflow Doesn't Validate the Remote Template

**File:** `src/workflows/RoomJoinWorkflow.ts` (lines ~74, ~184-188)  
**Severity:** Medium

When this server receives a join template from a remote server's `make_join` response, it uses the template's `auth_events`, `prev_events`, and `depth` without validation:

```typescript
if (remoteEventTemplate?.event) {
  authEvents = remoteEventTemplate.event.auth_events || [];
  prevEvents = remoteEventTemplate.event.prev_events || [];
  depth = remoteEventTemplate.event.depth || 1;
}
```

A malicious remote server could return:
- Empty `auth_events` — bypassing authorization
- A `depth` of 0 or negative — causing ordering issues
- `prev_events` pointing to non-existent events — creating a broken DAG
- Fields from an incompatible room version

**Step-by-step fix:**
1. Validate `auth_events` is a non-empty array of valid event ID strings
2. Validate `depth` is a positive integer greater than 0
3. Validate `prev_events` contains at least one valid event ID
4. Cross-check the room version matches what was expected
5. Verify the template's `room_id` matches the room being joined

---

### 6. Content Hash Verification Is Optional

**File:** `src/api/federation.ts` (lines ~583-597)  
**Severity:** Medium

Content hash verification only runs if the `hashes` field is present in the PDU:

```typescript
if (pdu.hashes?.sha256) {
  const hashValid = await verifyContentHash(pdu, pdu.hashes.sha256);
  if (!hashValid) { /* reject */ }
}
// If hashes field is absent, no verification happens
```

An attacker can omit the `hashes` field entirely, and the event is accepted without content integrity verification. While the signature covers the content, hash verification is an additional defense-in-depth layer required by the spec.

**Step-by-step fix:**
1. For room versions 1-3, hashes are optional (legacy)
2. For room versions 4+, require the `hashes` field — reject events without it
3. Log a warning for room version 1-3 events missing hashes

---

### 7. Auth Chain Traversal Is Unbounded

**File:** `src/api/federation.ts` (lines ~1076-1130)  
**Severity:** Medium

The auth chain collection uses a while-loop with a visited set but no maximum depth or size limit:

```typescript
while (toProcess.length > 0) {
  const authId = toProcess.shift()!;
  if (visited.has(authId)) continue;
  visited.add(authId);
  // ... fetch and add more auth events to toProcess ...
}
```

For rooms with deep auth chains (which grow linearly with the number of state changes), this can fetch thousands of events, each requiring a database query. No limit on `authChain` array size means unbounded memory consumption.

**Step-by-step fix:**
1. Add `const MAX_AUTH_CHAIN_SIZE = 500;` and break when reached
2. Use batch queries instead of one-at-a-time fetching
3. Return a partial auth chain with a warning header if truncated
4. Cache auth chains for rooms that don't change frequently

---

### 8. SSRF Protection Missing IPv6 Ranges

**File:** `src/utils/url-validator.ts` (lines ~70-101)  
**Severity:** Medium

The URL validator blocks common private IPv4 and IPv6 ranges but misses:
- Multicast addresses (`ff00::/8`)
- Deprecated site-local addresses (`fec0::/10`)
- Documentation prefix (`2001:db8::/32`)
- IPv4-mapped IPv6 addresses (`::ffff:127.0.0.1`)

**Step-by-step fix:**
1. Add the missing ranges to `isBlockedIPv6()`:
   ```typescript
   if (normalized.startsWith('ff')) return true;  // Multicast
   if (normalized.startsWith('fec') || normalized.startsWith('fed') || 
       normalized.startsWith('fee') || normalized.startsWith('fef')) return true;  // Site-local
   if (normalized.startsWith('2001:0db8') || normalized.startsWith('2001:db8')) return true;  // Documentation
   ```
2. Add detection for IPv4-mapped IPv6: check if the address matches `::ffff:x.x.x.x` and validate the IPv4 portion
3. Consider using a well-tested IP validation library rather than maintaining a manual blocklist

---

## Ideal Resolution

After these fixes:
- **State resolution runs for ALL inbound state events** and failures result in rejection
- **Backfill and missing events require room membership proof** from the requesting server
- **Invite events are validated for sender authority** before being signed and returned
- **Join rules are enforced at the make_join stage** — banned users, private rooms, and restricted joins are properly handled
- **Content hashes are required** for modern room versions
- **Auth chain traversal is bounded** — no memory exhaustion possible
- **SSRF protections cover all private address ranges** including IPv6 edge cases
