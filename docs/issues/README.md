# Tuwunel Issue Registry

> **Audit snapshot (2026-04-13):** This registry documents findings from an April 2026 codebase audit. Per-issue file/line references are suspects — the tree has moved; treat line numbers as historical pointers, not current navigation.

Comprehensive issue documentation from that audit. Each issue document contains a detailed problem narrative, per-finding breakdowns with file/line references, step-by-step remediation plans, and ideal resolution criteria.

**Last updated:** 2026-08-16 (status table aligned to landed PRs on `main`)

---

## Resolution Status

Of the 64 original findings, **most have landed on `main`**. Counts below reflect code that shipped (not the over-claims in some PR bodies). Line-level verification of every sub-finding is out of scope for this docs pass.

| Status | Count (approx.) |
|--------|-----------------|
| Done (issue closed by landed PRs) | 7 issues (001–004, 006, 008–009) |
| Mostly done (key sub-findings on `main`) | 3 issues (005, 007, 010) |

---

## Issue Index

| # | Title | Severity | Findings | Resolved (landed) | Status |
|---|-------|----------|----------|-------------------|--------|
| [001](./001-federation-authentication-and-signing.md) | Federation Auth & Outbound Signing | **Critical** | 6 | 6 | **Done** |
| [002](./002-authentication-session-security.md) | Authentication & Session Security | **Critical/High** | 8 | 8 | **Done** |
| [003](./003-media-upload-download-security.md) | Media Upload & Download Security | **High** | 5 | 5 | **Done** |
| [004](./004-database-integrity-and-transaction-safety.md) | Database Integrity & Transaction Safety | **Critical/High** | 6 | 6 | **Done** (PR #8) |
| [005](./005-durable-object-lifecycle-memory-management.md) | Durable Object Lifecycle & Memory | **High** | 10 | 8+ | Mostly done — **005.1** & **005.7** on `main` (PR #11); earlier commits covered more |
| [006](./006-federation-event-validation-state-resolution.md) | Federation Event Validation | **High** | 8 | 8 | **Done** (PR #9) |
| [007](./007-rate-limiting-dos-protection.md) | Rate Limiting & DoS Protection | **High** | 7 | 6 | Mostly done — **007.1** on `main` (PR #11); earlier commits covered more |
| [008](./008-rtc-webrtc-authentication-gap.md) | RTC/WebRTC Auth Gap | **Critical** | 3 | 3 | **Done** |
| [009](./009-room-operations-race-conditions.md) | Room Operations Race Conditions | **High** | 5 | 5 | **Done** — PR #10 + `migrations/018_room_memberships_unique.sql` |
| [010](./010-error-handling-information-leakage.md) | Error Handling & Information Leakage | **Medium** | 6 | 5 | Mostly done — **010.5** admin audit trail on `main` (PR #11) |

---

## What Was Fixed

### Commit 1: Initial security fixes (8 files)
- **008**: All 3 findings — requireAuth() on LiveKit, OpenID verification, CORS
- **003**: All 5 findings — MIME whitelist, body size, filename sanitization, security headers, NaN parsing
- **002**: Items 1, 4, 5, 7 — AppService namespace validation, PBKDF2 bounds, timing-safe comparison, CSP note
- **005**: Item 3 — RateLimit alarm scheduling
- **007**: Item 7 — Pagination parameter bounds
- **010**: Item 2 — Cache invalidation error logging

### Commit 2: Federation signing and body buffering (4 files)
- **001**: Items 1, 2, 4 — Outbound signing on workflows/DOs, body buffering in auth middleware, optional auth fix
- **005**: Items 4, 5 — FederationDO queue bounds (10k cap), response body validation, max retry cap (32), fetch timeouts

### Commit 3: Database integrity (2 files)
- **004**: Items 1, 3 — Stream ordering atomic UPDATE, data integrity migration with indexes and unique constraints

### Commit 4: Federation event validation (1 file)
- **006**: Items 1, 2, 3, 7, 4 — PDU signature logic fix, backfill/missing-events membership checks, auth chain cap, invite sender validation

### Commit 5: Durable Object reliability (3 files)
- **005**: Items 2, 8, 9 — SyncDO bounded scans, connection state expiry, PushDO JWT TTL reduction, push fetch timeout

### Commit 6: Password and brute force protection (5 files)
- **002**: Items 2, 3, 6 — Password strength validation, per-account lockout after 5 failures, OIDC encryption key required for new secrets
- **007**: Item 4 — Sliding sync subscription cap (100 per request)

### Commit 7: SSRF and error sanitization (2 files)
- **006**: Item 8 — IPv6 multicast, site-local, documentation prefix ranges added to SSRF blocklist
- **010**: Item 1 — Raw error details removed from admin API OIDC responses, logged server-side instead

### Commit 8: Stale-key rejection, join template validation, content hash enforcement (4 files)
- **001**: Item 5 — Federation key staleness threshold (default 7 days past `valid_until`); fallback to D1 cache and `verifyRemoteSignature` both reject keys past the threshold
- **006**: Item 5 — `make_join` template from remote validated for room_id, sender, state_key, type, content.membership, non-empty auth_events / prev_events with valid IDs, supported room version, and positive depth before signing
- **006**: Item 6 — `hashes.sha256` required for room versions ≥ 3; legacy room versions (1-2) still accepted without hash but logged

### PR #8: Database integrity remainder
- **004**: Remaining atomicity / row-size / N+1 / index items

### PR #9: Federation validation remainder
- **001** / **006**: Stale-key, join-template, and content-hash follow-through (see commit 8)

### PR #10: Room operation race conditions (issue 009 — all 5)
- **009.1** Join race — D1 batch + unique `room_memberships(room_id, user_id)` (also `migrations/018_room_memberships_unique.sql`, renumbered from a conflicting `017_*` name)
- **009.2** / **009.3** State write interleaving / TOCTOU — idempotent store + optimistic concurrency (`M_CONFLICT`)
- **009.4** Cache invalidation logging + generation bump
- **009.5** Account data upsert / version awareness

### PR #11: DO bounds, rate-limit IP trust, admin audit
- **005.1** SyncDO resolver map keyed by waiter id
- **005.7** RoomDO in-memory caps
- **007.1** Prefer `CF-Connecting-IP`; `X-Forwarded-For` only when `TRUST_FORWARDED_FOR=true`
- **010.5** `admin_audit_log` (migration 019) + `src/services/admin-audit.ts`

---

## Remaining Work

Issue **009 is done** on `main` (PR #10 + migration 018). Residual open work is mostly medium/low leftovers under **005**, **007**, and **010** (for example identity-reset rate limits, well-known cache TTL hardening, and admin QR login token handling) — re-audit against current line numbers before picking them up. Do not treat PR body “N/N Done” claims as a substitute for reading the tree.
