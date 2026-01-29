# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Matrix Worker is a Matrix homeserver implementation running entirely on Cloudflare Workers edge infrastructure. It implements the Matrix Client-Server API v1.17 and Server-Server (Federation) API.

## Commands

```bash
# Development
npm run dev                    # Start local dev server with wrangler

# Type checking and linting
npm run typecheck              # Run TypeScript type checking (tsc --noEmit)
npm run lint                   # ESLint on src/

# Testing
npm run test                   # Run vitest

# Database migrations (local)
npm run db:migrate:local       # Apply schema.sql to local D1

# Database migrations (remote) - run in order for new deployments
wrangler d1 execute tuwunel-db --remote --file=migrations/schema.sql
wrangler d1 execute tuwunel-db --remote --file=migrations/002_phase1_e2ee.sql
wrangler d1 execute tuwunel-db --remote --file=migrations/003_account_management.sql
wrangler d1 execute tuwunel-db --remote --file=migrations/004_reports_and_notices.sql

# Deployment
npm run deploy                 # Deploy to Cloudflare Workers
```

## Architecture

### Cloudflare Bindings
- **DB** (D1): SQLite database for users, rooms, events, memberships
- **SESSIONS** (KV): Session/access token storage
- **DEVICE_KEYS** (KV): E2EE device key storage
- **CACHE** (KV): General caching
- **MEDIA** (R2): Media file storage
- **ROOMS** (Durable Object): Real-time room coordination
- **SYNC** (Durable Object): Client sync state
- **FEDERATION** (Durable Object): Federation coordination

### Code Organization
- `src/index.ts`: Main Hono app, routes all API modules
- `src/api/`: Matrix Client-Server API endpoints (one file per feature area)
- `src/durable-objects/`: Durable Object classes for real-time coordination
- `src/middleware/auth.ts`: Token authentication middleware
- `src/middleware/rate-limit.ts`: Rate limiting with sliding window
- `src/services/database.ts`: D1 database operations
- `src/types/env.ts`: Environment bindings (`Env`, `AppEnv`, `Variables` types)
- `src/types/matrix.ts`: Matrix protocol type definitions

### Request Flow
1. Request hits `src/index.ts` Hono app
2. Global middleware: logger, rate limiting (for `/_matrix/*`), CORS
3. Routes dispatch to appropriate `src/api/*.ts` module
4. Auth middleware (`src/middleware/auth.ts`) validates access tokens for protected routes
5. Handlers use `c.env` for bindings, `c.get('userId')` for authenticated user

### Key Patterns
- Hono framework with typed environment (`AppEnv`)
- Matrix error responses use `{ errcode: 'M_*', error: string }` format
- Auth middleware sets `userId`, `deviceId`, `accessToken` on context via `c.set()`
- D1 queries use parameterized `.bind()` for SQL injection prevention
