# Issue 008: RTC/WebRTC Authentication Gap — Unauthenticated Token Endpoints and Weak OpenID Verification

**Severity:** Critical  
**Domain:** Security, WebRTC  
**Affected files:** `src/api/rtc.ts`

---

## Problem Statement

The real-time communication (RTC) endpoints for LiveKit-based video/voice calls have two critical authentication failures. The token generation endpoints require no Matrix authentication whatsoever, and the OpenID token verification that is supposed to provide an alternative trust mechanism is explicitly disabled with a development comment. Together, these allow any unauthenticated client to generate valid LiveKit tokens and join any call in any room, bypassing all room membership and permission checks.

---

## Detailed Breakdown

### 1. LiveKit Token Endpoints Require No Authentication

**File:** `src/api/rtc.ts` (lines ~102-180, ~196-281)  
**Severity:** Critical

Both LiveKit token endpoints lack `requireAuth()` middleware:

```typescript
// Line ~102 — no auth middleware
app.post('/livekit/get_token', async (c) => {
  // Generates a valid LiveKit JWT token for anyone who asks
});

// Line ~196 — no auth middleware
app.post('/livekit/get_token/sfu/get', async (c) => {
  // Same — generates tokens without authentication
});
```

These endpoints accept a room ID and user ID in the request body and return a signed JWT token that grants access to the LiveKit room. Without authentication:

- Any anonymous client can request a token for any room
- The client can specify any user ID, impersonating any user in the call
- Room membership is never checked — private room calls are accessible to anyone
- No rate limiting specific to token generation

**Step-by-step fix:**
1. Add `requireAuth()` middleware to both endpoints:
   ```typescript
   app.post('/livekit/get_token', requireAuth(), async (c) => { ... });
   ```
2. Use the authenticated user's ID from the context instead of accepting it from the request body
3. Verify the authenticated user is a member of the specified room before issuing a token
4. Rate-limit token requests to prevent abuse (e.g., 10 tokens per user per minute)

---

### 2. OpenID Token Verification Is Explicitly Disabled

**File:** `src/api/rtc.ts` (lines ~68-91)  
**Severity:** Critical

The `verifyOpenIDToken()` function is supposed to verify the Matrix OpenID token provided by the client. Instead, it's stubbed out:

```typescript
async function verifyOpenIDToken(token: any): Promise<{ sub: string } | null> {
  // OpenID token verification skipped for development
  if (token.matrix_server_name === serverName) {
    return { sub: token.access_token };
  }
  return null;
}
```

This "verification":
- Only checks if the server name matches (public knowledge)
- Returns `token.access_token` as the subject (trusting client input)
- Doesn't verify the token cryptographically
- Doesn't check if the token is valid, expired, or belongs to the claimed user
- Is labeled as a development shortcut but is deployed to production

A proper OpenID token verification should call the Matrix homeserver's `/_matrix/federation/v1/openid/userinfo` endpoint to validate the token.

**Step-by-step fix:**
1. Implement real OpenID token verification:
   ```typescript
   async function verifyOpenIDToken(token: OpenIDToken): Promise<{ sub: string } | null> {
     const response = await fetch(
       `https://${token.matrix_server_name}/_matrix/federation/v1/openid/userinfo?access_token=${token.access_token}`
     );
     if (!response.ok) return null;
     const data = await response.json();
     return { sub: data.sub };
   }
   ```
2. For local users, validate against the local token store directly (faster, no network call)
3. Cache verified tokens briefly (5 minutes) to reduce verification overhead
4. Add timeout and error handling for the verification request

---

### 3. CORS Headers Only on OPTIONS, Not Actual Responses

**File:** `src/api/rtc.ts` (lines ~183-191)  
**Severity:** Medium

The RTC module adds CORS headers to OPTIONS preflight responses but not to the actual POST responses:

```typescript
app.options('/livekit/*', (c) => {
  return new Response(null, {
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
});
// Actual POST handlers don't set CORS headers
```

Browsers will successfully preflight the request but then block the actual response because it lacks CORS headers.

**Step-by-step fix:**
1. Add CORS headers to the actual response in each POST handler, or
2. Apply CORS middleware to the entire RTC route group:
   ```typescript
   app.use('/livekit/*', cors({ origin: '*', allowMethods: ['POST', 'OPTIONS'] }));
   ```

---

## Ideal Resolution

After these fixes:
- **All RTC token endpoints require Matrix authentication** — only logged-in users can request call tokens
- **Room membership is verified** before issuing tokens — private calls stay private
- **OpenID tokens are cryptographically verified** — not just trusted from client input
- **CORS headers are present on all responses** — browser-based clients can access the endpoints
- **Token generation is rate-limited** — preventing abuse and resource exhaustion
