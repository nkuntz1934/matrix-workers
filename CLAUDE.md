# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Tuwunel is a Matrix homeserver (spec v1.17) running entirely on Cloudflare Workers edge infrastructure. It uses D1 (SQLite), KV, R2, Durable Objects, and Workflows. The live instance runs at `m.easydemo.org`.

## Development Commands

```bash
npm run dev              # Local dev server (wrangler dev)
npm run deploy           # Deploy to Cloudflare
npm run typecheck        # TypeScript type checking (tsc --noEmit)
npm run lint             # ESLint on src/
npm run test             # Vitest
npm run db:migrate       # Run D1 migrations (remote)
npm run db:migrate:local # Run D1 migrations (local)
```

## Architecture

**Framework:** Hono web framework with typed `AppEnv` bindings for Cloudflare resources.

**Entry point:** `src/index.ts` — creates the Hono app, applies global middleware (CORS → Logger → Rate Limit), mounts all route modules, and exports Durable Objects + Workflows.

**Layered structure:**
- `src/api/` — Route handlers (30+ modules). Each exports a Hono instance mounted in the main app. Largest: `federation.ts` (103KB), `sliding-sync.ts` (81KB), `admin.ts` (80KB), `rooms.ts` (73KB).
- `src/middleware/` — Auth (`requireAuth()`), rate limiting (DO-based sliding window), federation auth (Ed25519 X-Matrix), idempotency.
- `src/services/` — Business logic: `database.ts` (D1 queries, no ORM), `federation-keys.ts`, `server-discovery.ts`, `email.ts` (Cloudflare Email Service), `oidc.ts`, `turn.ts`, `livekit.ts`, `cloudflare-calls.ts`, `room-cache.ts`, `transactions.ts`.
- `src/durable-objects/` — 8 DOs: Room (WebSocket coordination), Sync, Federation (queue), CallRoom (video), Admin, UserKeys (E2EE), Push, RateLimit.
- `src/workflows/` — `RoomJoinWorkflow` (federation handshake with retry), `PushNotificationWorkflow`.
- `src/types/` — `env.ts` (Cloudflare bindings), `matrix.ts` (PDU/event types).
- `src/utils/` — `crypto.ts` (hashing/signing), `ids.ts` (Matrix ID generation), `errors.ts` (MatrixApiError + Errors factory).
- `src/admin/dashboard.ts` — Embedded admin web UI at `/admin`.
- `migrations/` — D1 schema files (schema.sql + numbered migrations 002–011).

**Storage bindings (defined in `wrangler.jsonc`):**
- D1 `tuwunel-db` — Relational data (users, rooms, events, memberships, etc.)
- KV namespaces: `SESSIONS`, `DEVICE_KEYS`, `ONE_TIME_KEYS`, `CROSS_SIGNING_KEYS`, `CACHE`, `ACCOUNT_DATA`
- R2 `MEDIA` — Media file storage

**Key patterns:**
- Auth: token from `Authorization: Bearer` or `?access_token=`, SHA-256 hashed, looked up in D1 `access_tokens`. Middleware sets `userId`/`deviceId` on context.
- Errors: Use `MatrixApiError` class and `Errors` factory for standardized Matrix JSON responses (`errcode`, `error`).
- Database: Direct D1 prepared statements — no ORM. All queries in `src/services/database.ts` or inline in route handlers.
- IDs follow Matrix format: `@user:domain`, `!room_id:domain`, `$event_id:domain`, `#alias:domain`.
- Federation: Ed25519 signing, X-Matrix header validation, server key caching in KV.
- Real-time: Hibernatable WebSockets via RoomDurableObject, long-polling `/sync`, Sliding Sync (MSC3575/MSC4186) for Element X.
- Passwords hashed with PBKDF2-SHA256 (100,000 iterations).

**TypeScript config:** Strict mode, ES2022 target, `@/*` path alias maps to `src/*`, `@cloudflare/workers-types`.

## Git Commit Rules

- Never include Claude attribution (e.g., `Co-Authored-By`) in commit messages.
