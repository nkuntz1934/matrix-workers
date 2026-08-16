# Issue 001: Federation Authentication & Outbound Signing Are Critically Broken

**Severity:** Critical  
**Domain:** Federation, Security  
**Affected files:** `src/workflows/RoomJoinWorkflow.ts`, `src/middleware/federation-auth.ts`, `src/api/federation.ts`, `src/services/federation-keys.ts`

---

## Problem Statement

The federation layer — the backbone of Matrix interoperability — has multiple critical authentication and signing failures that collectively mean this server cannot securely participate in the federated Matrix network. Inbound requests may bypass signature verification, and outbound requests are sent without any authentication at all. A malicious or compromised remote homeserver can exploit these gaps to forge events, impersonate users, or poison room state.

These are not theoretical concerns; any server in a federated room with this homeserver can actively exploit them today.

---

## Detailed Breakdown

### 1. Outbound Federation Requests Lack X-Matrix Authentication

**Files:** `src/workflows/RoomJoinWorkflow.ts` (lines ~143-167, ~238-263)

When this server initiates a room join via federation, it sends `make_join` and `send_join` HTTP requests to the remote server. These requests are sent as plain unauthenticated HTTP — no `Authorization` header, no X-Matrix signature, nothing.

```typescript
// RoomJoinWorkflow.ts ~line 153
const response = await fetch(url, {
  method: 'GET',
  headers: {
    'Content-Type': 'application/json',
  },
});
```

The Matrix spec requires all server-to-server requests to carry an `Authorization: X-Matrix` header containing an Ed25519 signature over the request. Without it:

- The remote server has no way to verify who is making the request
- An attacker performing a DNS hijack or MITM can impersonate this server to any remote server
- The remote server may (correctly) reject the request entirely, breaking federation joins

**Step-by-step fix:**
1. Create a utility function `signFederationRequest(method, uri, origin, destination, signingKey, content?)` that produces the X-Matrix `Authorization` header per the spec
2. Apply it to every outbound `fetch()` call in `RoomJoinWorkflow.ts` — both the GET `make_join` and the PUT `send_join`
3. Apply it to all outbound calls in `FederationDurableObject.ts` where PDUs are sent to remote servers
4. Add integration tests that verify the header is present and correctly signed

---

### 2. Request Body Not Re-Readable After Federation Auth Middleware Consumes It

**File:** `src/middleware/federation-auth.ts` (line ~130)

The federation auth middleware reads the request body with `await c.req.text()` to include it in signature verification. In the Workers/Hono runtime, the request body is a ReadableStream that can only be consumed once. After the middleware reads it, downstream route handlers receive an empty body.

```typescript
// federation-auth.ts ~line 130
const bodyText = await c.req.text();
if (bodyText) {
  content = JSON.parse(bodyText);
}
```

This means every POST/PUT federation endpoint (including the critical `/send/:txnId` transaction endpoint) silently receives no body, causing:
- Inbound PDU transactions to be empty (events silently dropped)
- Invite, join, and leave operations to fail or process with missing data
- No error raised — handlers just see `undefined` or `{}`

**Step-by-step fix:**
1. Buffer the body in the middleware: read it once, store on the Hono context (`c.set('federationBody', bodyText)`)
2. Parse and use the buffered body in the signature verification
3. Either re-attach the body to the request (if Hono supports it) or have downstream handlers read from `c.get('federationBody')` instead of `c.req.json()`
4. Add a test that verifies a POST to `/_matrix/federation/v1/send/:txnId` with a body actually receives that body in the handler

---

### 3. Third-Party PDU Signature Validation Has a Logic Error

**File:** `src/api/federation.ts` (lines ~544-580)

When processing inbound PDU transactions, the code checks whether a PDU's origin matches the sending server's origin. If they match, the signature check result is ignored:

```typescript
if (!signatureValid && pduOrigin !== origin) {
  pduResults[eventId] = { error: 'Invalid signature' };
  continue;
}
```

The conditional `pduOrigin !== origin` means: if the PDU claims to originate from the same server that sent the transaction, it is accepted even with an invalid signature. A malicious server simply needs to set the PDU's `origin` field to match its own server name, and it can submit arbitrarily forged events.

**Step-by-step fix:**
1. Change the condition to reject ALL unsigned PDUs: `if (!signatureValid) { reject }`
2. Third-party PDUs (where `pduOrigin !== origin`) should additionally have their origin server's key fetched and verified
3. Add test cases for: valid signature from origin, invalid signature from origin (must reject), valid third-party signature, invalid third-party signature

---

### 4. Optional Federation Auth Silently Swallows All Errors

**File:** `src/middleware/federation-auth.ts` (lines ~200-262)

The `optionalFederationAuth()` middleware catches ALL exceptions and silently continues:

```typescript
} catch {
  // Silently ignore auth errors for optional auth
}
```

This means if a remote server provides authentication headers but the signature is invalid, forged, or expired, the request proceeds as if no auth was provided — rather than being rejected.

**Step-by-step fix:**
1. Distinguish between "no auth headers present" (proceed unauthenticated) and "auth headers present but invalid" (reject with 401)
2. Only catch the specific "no Authorization header" case as a non-error
3. Log all authentication failures for security monitoring
4. Return a 401 response when auth is attempted but fails

---

### 5. Stale Federation Keys Accepted When Network Fails

**File:** `src/services/federation-keys.ts` (lines ~56-97)

When fetching a remote server's signing keys fails (network error, DNS failure, timeout), the code falls back to previously cached keys regardless of age:

```typescript
} catch (error) {
  if (dbKeys.results.length > 0) {
    return dbKeys.results;  // Stale keys accepted
  }
}
```

And expired keys are accepted with only a warning:

```typescript
if (key.valid_until && key.valid_until < Date.now()) {
  console.warn(`Key ${serverName}:${keyId} has expired`);
  // Still try to verify
}
```

An attacker who has compromised an old (now-rotated) key can cause a targeted network failure (e.g., DNS poisoning the key server endpoint), forcing this code to accept the compromised key.

**Step-by-step fix:**
1. Add a maximum staleness threshold (e.g., 7 days). Keys older than this are never accepted as fallback.
2. Reject keys past their `valid_until` timestamp for new signatures. Only accept them for verifying events that were created before the key expired.
3. Implement key pinning: once a server's new key is seen, the old key should not be accepted for new events.
4. Log stale key fallback events as security warnings.

---

### 6. Key Self-Signature Not Enforced in Notary Response

**File:** `src/services/federation-keys.ts` (lines ~318-342)

When acting as a key notary, the code verifies the remote server's self-signature but continues to serve the keys even if verification fails:

```typescript
if (!hasValidSignature) {
  console.warn(`No valid self-signature found for ${serverName}`);
  // Still return the keys
}
```

**Step-by-step fix:**
1. Return an error when self-signature verification fails — do not cache or serve unsigned keys
2. Implement a negative cache to prevent repeated lookups of the same failing server
3. Rate-limit key notary queries per server to prevent abuse

---

## Ideal Resolution

After these fixes, the federation layer should satisfy these invariants:
- **Every outbound request carries a valid X-Matrix signature** verifiable by the remote server
- **Every inbound request with an auth header has that signature cryptographically verified** before any processing occurs
- **Invalid, expired, or missing signatures result in rejection**, not silent acceptance
- **No PDU is accepted without a valid signature from its origin server**, regardless of which server delivered it
- **Key material is never accepted without cryptographic self-signature verification**

These are foundational security properties for a federated system. Without them, federation is effectively operating on a trust-everyone model.
