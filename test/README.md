# Issue #16 regression tests

With Node.js 22.13 or newer and dependencies installed:

```sh
npx vitest run test/issue16.test.ts
npm run typecheck
```

The tests exercise the production Hono route handlers and SQL using an in-memory
SQLite database initialized from `migrations/schema.sql`. A small adapter supplies
the D1 response shape and an in-memory map supplies KV. JWT signatures are checked
independently with Node's crypto implementation.

Coverage includes encrypted event context, the issued OpenID token/userinfo round
trip, legacy and member-based RTC identities, invalid/expired credentials,
cross-user and device claims, room membership restrictions, and ordinary password
login. These tests do not connect to external services or change any Cloudflare
account. They are not an end-to-end Element Web login or LiveKit media test.
