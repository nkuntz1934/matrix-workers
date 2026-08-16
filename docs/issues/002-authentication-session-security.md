# Issue 002: Authentication & Session Security — Impersonation, Brute Force, and Weak Credential Handling

**Severity:** Critical / High  
**Domain:** Authentication, Security  
**Affected files:** `src/middleware/auth.ts`, `src/api/login.ts`, `src/api/account.ts`, `src/api/admin.ts`, `src/api/oauth.ts`, `src/utils/crypto.ts`, `src/admin/dashboard.ts`, `src/index.ts`

---

## Problem Statement

The authentication layer has multiple compounding weaknesses that create a progressively degraded security posture. Individually, some of these are moderate concerns. Together, they form an attack chain: an attacker can brute-force a weak password (no policy enforcement, no lockout), steal tokens from browser storage (XSS + localStorage), impersonate arbitrary users through the AppService API, and verify credentials via timing side-channels. This issue documents each gap and prescribes specific fixes.

---

## Detailed Breakdown

### 1. AppService `user_id` Parameter Allows Arbitrary User Impersonation

**File:** `src/middleware/auth.ts` (lines ~76-90)  
**Severity:** Critical

When an application service authenticates, the middleware accepts an arbitrary `user_id` query parameter and sets it as the authenticated user identity with no validation:

```typescript
const asUserId = url.searchParams.get('user_id');
const senderUserId = asUserId || `@${appservice.sender_localpart}:${serverName}`;
auth = {
  userId: senderUserId,  // Attacker-controlled
  deviceId: null,
  accessToken: token,
};
```

Any holder of a valid AppService token can act as any user on the server — read their messages, send messages on their behalf, change their profile, leave rooms, or modify account data. The Matrix spec requires that AppServices can only impersonate users within their registered namespace (e.g., `@_bridge_.*:server`).

**Step-by-step fix:**
1. Store the AppService's registered user namespace regex in the `appservices` database table (e.g., a `user_namespaces` JSON column)
2. In the auth middleware, after extracting `user_id`, validate it matches the AppService's namespace: `if (!namespaceRegex.test(asUserId)) return 403`
3. Always validate that the user_id belongs to the local server domain
4. Add tests: valid namespace user (accept), out-of-namespace user (reject), user on different server (reject)

---

### 2. No Password Policy Enforcement

**Files:** `src/api/login.ts` (~lines 327-351), `src/api/admin.ts` (~lines 269-292, 1001-1032), `src/api/account.ts` (~lines 26-89)  
**Severity:** High

No registration or password-change endpoint validates password strength. A user can register with an empty string, a single character, or "password123". There is no minimum length, no complexity requirement, and no check against known-breached password lists.

**Step-by-step fix:**
1. Create a `validatePasswordStrength(password: string)` utility in `src/utils/crypto.ts`
2. Enforce minimum 8 characters (configurable via server config)
3. Reject passwords that match the username or common patterns
4. Apply this validation in: registration (`login.ts`), password change (`account.ts`), admin password reset (`admin.ts`)
5. Return Matrix-standard `M_WEAK_PASSWORD` errcode when validation fails

---

### 3. No Per-Account Brute Force Protection

**File:** `src/api/login.ts` (lines ~47-116)  
**Severity:** High

The login endpoint checks the password against the stored hash and returns a generic error on failure, but never tracks failed attempts per account. The global rate limiter constrains requests per IP, but an attacker using rotating IPs (botnets, Tor, proxies) can make unlimited password guesses against any account.

```typescript
const valid = await verifyPassword(password, storedHash);
if (!valid) {
  return Errors.forbidden('Invalid username or password').toResponse();
  // No counter incremented, no lockout triggered
}
```

**Step-by-step fix:**
1. Add a `failed_login_attempts` and `locked_until` column to the `users` table (or use KV with TTL)
2. On each failed login, increment the counter for that user_id
3. After 5 consecutive failures within 15 minutes, lock the account for 15 minutes (return `M_LIMIT_EXCEEDED` with `retry_after_ms`)
4. On successful login, reset the counter
5. Log all failed attempts with IP address for security monitoring
6. Consider implementing exponential backoff: 1st failure = 0s delay, 5th = 30s, 10th = 5min lockout

---

### 4. PBKDF2 Stored Iteration Count Not Bounds-Checked

**File:** `src/utils/crypto.ts` (lines ~39-71)  
**Severity:** Medium

Password verification parses the iteration count from the stored hash string and uses it directly:

```typescript
const iterations = parseInt(parts[2], 10);
// Used directly — could be 1, 0, or negative
```

If an attacker gains write access to the database, they can change a user's stored hash to use `iterations=1`, making it trivially crackable while still appearing valid to the verification function.

**Step-by-step fix:**
1. Add bounds validation: `if (iterations < 100000 || iterations > 2000000) throw new Error('Invalid iteration count')`
2. On successful login with an iteration count below the current standard (100,000), re-hash the password with the current iteration count and update the stored hash (progressive strengthening)

---

### 5. OAuth Client Secret Comparison Vulnerable to Timing Attacks

**File:** `src/api/oauth.ts` (line ~376)  
**Severity:** Medium

Client secret validation uses JavaScript's `!==` string comparison:

```typescript
if (secretHash !== client.client_secret_hash) {
```

String comparison in JavaScript short-circuits on the first differing character, creating measurable timing differences.

**Step-by-step fix:**
1. Implement constant-time comparison using `crypto.subtle.timingSafeEqual()` (available in Workers runtime) or a manual XOR-based comparison
2. Apply the same fix to any other secret/hash comparisons in the codebase

---

### 6. OIDC Encryption Fallback Uses Server Name as AES Key

**File:** `src/api/oidc-auth.ts` (lines ~54-84)  
**Severity:** High

When no `OIDC_ENCRYPTION_KEY` environment variable is set, the code derives the AES-GCM encryption key from the public server name, padded with zeros:

```typescript
return crypto.subtle.importKey(
  'raw',
  encoder.encode(env.SERVER_NAME.padEnd(32, '0').slice(0, 32)),
  'AES-GCM',
  false,
  ['encrypt', 'decrypt']
);
```

The server name is public knowledge. Anyone who knows it (which is everyone — it's in every event) can decrypt all stored OIDC client secrets.

**Step-by-step fix:**
1. Remove the fallback entirely — require `OIDC_ENCRYPTION_KEY` to be set
2. Fail with a clear error at startup if the key is missing
3. Use HKDF or PBKDF2 to derive the actual encryption key from the configured secret
4. Document key rotation procedure

---

### 7. Admin Token Stored in localStorage (XSS Extraction Risk)

**File:** `src/admin/dashboard.ts` (lines ~2312-2409)  
**Severity:** Medium

The embedded admin dashboard stores the admin access token in `localStorage`, which is accessible to any JavaScript running on the same origin. Combined with the `unsafe-inline` CSP policy, any XSS vulnerability allows immediate token exfiltration.

**Step-by-step fix:**
1. Switch to `sessionStorage` (cleared when tab closes) as an immediate improvement
2. Better: implement HTTP-only cookie-based authentication for the admin dashboard endpoints
3. Add CSRF token validation for all state-changing admin operations
4. Implement token rotation — issue short-lived tokens (15 min) with refresh capability

---

### 8. CSP Allows `unsafe-inline` for Scripts

**File:** `src/index.ts` (lines ~82-86)  
**Severity:** Low-Medium

```
script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
style-src 'self' 'unsafe-inline';
```

This negates much of CSP's XSS protection.

**Step-by-step fix:**
1. Generate a per-request nonce: `const nonce = crypto.randomUUID()`
2. Set CSP to `script-src 'self' 'nonce-${nonce}' https://cdn.jsdelivr.net`
3. Apply the nonce attribute to all `<script>` tags in the admin dashboard HTML
4. Remove `unsafe-inline` from both `script-src` and `style-src`

---

## Ideal Resolution

After these fixes:
- **AppService impersonation is namespace-scoped** — an AppService can only act as users matching its registered pattern
- **Weak passwords are rejected at registration** — minimum strength requirements enforced everywhere passwords are set
- **Brute force attacks are throttled per-account** — not just per-IP
- **Credential comparison is constant-time** — no timing side-channels
- **OIDC secrets are protected by a proper encryption key** — not derivable from public information
- **Admin sessions use secure storage** — not extractable via XSS
- **CSP prevents inline script execution** — XSS payloads cannot run
