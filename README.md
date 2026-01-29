# Matrix Homeserver on Cloudflare Workers

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/SilentHeroes/matrix-worker)

This is a proof of concept Matrix homeserver implementation running entirely on Cloudflare's edge infrastructure. This was built to prove E2EE utilizing Matrix protocols over Element X on the Cloudflare Workers Platform. It is meant to serve as an example prototype and not endorsed as ready for production at this point.

I was assisted by Claude Code Opus 4.5 for this implementation to speed up showing that you could message over Cloudflare Workers utilizing the Element Web and Element X App.  Feel free to submit issues, fork the project to make it your own, or continue to build on this example!

## Live Demo

A live instance is running at `m.easydemo.org`. You can verify federation compatibility using the [Matrix Federation Tester](https://federationtester.matrix.org/api/report?server_name=m.easydemo.org).

## Spec Compliance

**Matrix Specification v1.17 Compliance: ~100%**

| Spec Section | Coverage |
|--------------|----------|
| Client-Server API | ~100% |
| Server-Server (Federation) API | ~100% |
| Room Versions | v1-v12 (100%) |
| E2EE (Keys) | ~100% |
| Discovery | 100% |
| 3PID (Identity) | ~100% |

## Features

- **Full E2EE Support**: Device keys, cross-signing, key backup, one-time keys, federation key queries
- **Token Refresh**: Secure token rotation with single-use refresh tokens (KV-backed with auto-expiry)
- **Sliding Sync**: MSC3575 and MSC4186 (Simplified Sliding Sync for Element X)
- **Real-time**: Sync coordination via Durable Objects, presence with KV caching
- **Federation**: Complete server-to-server communication including E2EE, knock protocol, media, and directory
- **Media Storage**: R2-backed media with thumbnail generation and authenticated media (MSC3916)
- **Push Notifications**: APNs support (iOS direct push)
- **Video Calling**: MatrixRTC with LiveKit and Cloudflare Calls SFU integration
- **Knock Protocol**: Support for knock-to-join rooms via federation
- **Room Versions**: Full support for room versions 1-12

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Cloudflare Edge Network                           │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   Workers   │  │  Durable    │  │     D1      │  │         R2          │ │
│  │   (Hono)    │──│  Objects    │──│  (SQLite)   │  │   (Object Storage)  │ │
│  │             │  │             │  │             │  │                     │ │
│  │ • Routing   │  │ • Room DO   │  │ • users     │  │ • Media files       │ │
│  │ • Auth      │  │ • Sync DO   │  │ • rooms     │  │ • Thumbnails        │ │
│  │ • API       │  │ • Fed DO    │  │ • events    │  │ • Avatars           │ │
│  │ • Rate Lim  │  │ • Keys DO   │  │ • keys      │  │                     │ │
│  └─────────────┘  │ • Push DO   │  │ • tokens    │  └─────────────────────┘ │
│         │         │ • Admin DO  │  └─────────────┘            │             │
│         │         │ • Call DO   │                             │             │
│         │         │ • Rate DO   │                             │             │
│         │         └─────────────┘         │                   │             │
│  ┌──────┴─────────────────────────────────┴───────────────────┴───────────┐ │
│  │                          KV Namespaces                                 │ │
│  │  SESSIONS · DEVICE_KEYS · CACHE · ONE_TIME_KEYS · CROSS_SIGNING_KEYS   │ │
│  │  ACCOUNT_DATA                                                          │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                     Workflows (Durable Execution)                      │ │
│  │  RoomJoinWorkflow · PushNotificationWorkflow                           │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## API Coverage

### Client-Server API

| Category | Endpoints | Status |
|----------|-----------|--------|
| Authentication | `/login`, `/register`, `/logout`, `/refresh`, `/auth_metadata`, `/login/get_token` | ✅ |
| Sync | `/sync`, Sliding Sync (MSC3575/MSC4186), filter persistence & application | ✅ |
| Rooms | Create, join, leave, invite, kick, ban, knock, upgrade, summary | ✅ |
| Messaging | Send, redact, edit, reply | ✅ |
| State | Room state, power levels | ✅ |
| E2EE | Device keys, OTKs, cross-signing, key backup | ✅ |
| To-Device | Encrypted message relay | ✅ |
| Push | Push rules, pushers (APNs/FCM) | ✅ |
| Media | Upload, download, thumbnails (MSC3916 auth) | ✅ |
| Profile | Display name, avatar, custom profile keys | ✅ |
| Presence | Online/offline status with KV caching | ✅ |
| Typing | Typing indicators | ✅ |
| Receipts | Read receipts | ✅ |
| Account Data | User settings, room tags | ✅ |
| Directory | Room directory, aliases | ✅ |
| Discovery | `.well-known/matrix/*` (client, server, support) | ✅ |
| Reporting | Report events, rooms, users | ✅ |
| Admin | User session info (`/admin/whois`) | ✅ |
| 3PID | Email verification, 3PID management | ✅ (Resend) |
| Timestamps | `timestamp_to_event` for event lookup | ✅ |

### Server-Server (Federation) API

| Category | Endpoint | Purpose | Status |
|----------|----------|---------|--------|
| **Discovery** | `GET /_matrix/federation/v1/version` | Server version info | ✅ |
| **Keys** | `GET /_matrix/key/v2/server` | Server signing keys | ✅ |
| | `GET /_matrix/key/v2/server/{keyId}` | Specific signing key | ✅ |
| | `POST /_matrix/key/v2/query` | Batch key query | ✅ |
| | `GET /_matrix/key/v2/query/{serverName}` | Notary key query | ✅ |
| | `GET /_matrix/key/v2/query/{serverName}/{keyId}` | Specific notary key | ✅ |
| **E2EE** | `POST /_matrix/federation/v1/user/keys/query` | Query device keys | ✅ |
| | `POST /_matrix/federation/v1/user/keys/claim` | Claim one-time keys | ✅ |
| | `GET /_matrix/federation/v1/user/devices/{userId}` | Get user devices | ✅ |
| **Events** | `PUT /_matrix/federation/v1/send/{txnId}` | Receive PDUs/EDUs | ✅ |
| | `GET /_matrix/federation/v1/event/{eventId}` | Fetch single event | ✅ |
| | `GET /_matrix/federation/v1/state/{roomId}` | Get room state | ✅ |
| | `GET /_matrix/federation/v1/state_ids/{roomId}` | Get state event IDs | ✅ |
| | `GET /_matrix/federation/v1/event_auth/{roomId}/{eventId}` | Get auth chain | ✅ |
| | `GET /_matrix/federation/v1/backfill/{roomId}` | Fetch historical events | ✅ |
| | `POST /_matrix/federation/v1/get_missing_events/{roomId}` | Fill event gaps | ✅ |
| | `GET /_matrix/federation/v1/timestamp_to_event/{roomId}` | Find event by timestamp | ✅ |
| **Joining** | `GET /_matrix/federation/v1/make_join/{roomId}/{userId}` | Prepare join | ✅ |
| | `PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}` | Complete join (v1) | ✅ |
| | `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}` | Complete join (v2) | ✅ |
| **Leaving** | `GET /_matrix/federation/v1/make_leave/{roomId}/{userId}` | Prepare leave | ✅ |
| | `PUT /_matrix/federation/v1/send_leave/{roomId}/{eventId}` | Complete leave (v1) | ✅ |
| | `PUT /_matrix/federation/v2/send_leave/{roomId}/{eventId}` | Complete leave (v2) | ✅ |
| **Knocking** | `GET /_matrix/federation/v1/make_knock/{roomId}/{userId}` | Prepare knock | ✅ |
| | `PUT /_matrix/federation/v1/send_knock/{roomId}/{eventId}` | Complete knock | ✅ |
| **Inviting** | `PUT /_matrix/federation/v1/invite/{roomId}/{eventId}` | Receive invite (v1) | ✅ |
| | `PUT /_matrix/federation/v2/invite/{roomId}/{eventId}` | Receive invite (v2) | ✅ |
| **Media** | `GET /_matrix/federation/v1/media/download/{mediaId}` | Download media | ✅ |
| | `GET /_matrix/federation/v1/media/thumbnail/{mediaId}` | Get thumbnail | ✅ |
| **Directory** | `GET /_matrix/federation/v1/query/directory` | Resolve room alias | ✅ |
| | `GET /_matrix/federation/v1/query/profile` | Query user profile | ✅ |
| | `GET /_matrix/federation/v1/publicRooms` | List public rooms | ✅ |
| | `POST /_matrix/federation/v1/publicRooms` | Search public rooms | ✅ |
| **Spaces** | `GET /_matrix/federation/v1/hierarchy/{roomId}` | Get space hierarchy | ✅ |
| **OpenID** | `GET /_matrix/federation/v1/openid/userinfo` | Validate OpenID token | ✅ |

### Matrix v1.17 Compliance Additions

The following endpoints were added to achieve full Matrix Specification v1.17 compliance:

| Category | Endpoint | Purpose |
|----------|----------|---------|
| **Room Summary** | `GET /_matrix/client/v1/room_summary/{roomIdOrAlias}` | Preview room without joining |
| **Auth Metadata** | `GET /_matrix/client/v1/auth_metadata` | Authentication method discovery |
| **Login Token** | `POST /_matrix/client/v1/login/get_token` | Generate short-lived login token (QR code login) |
| **Custom Profile** | `GET /_matrix/client/v3/profile/{userId}/{keyName}` | Get custom profile attribute |
| | `PUT /_matrix/client/v3/profile/{userId}/{keyName}` | Set custom profile attribute |
| | `DELETE /_matrix/client/v3/profile/{userId}/{keyName}` | Delete custom profile attribute |
| **Reporting** | `POST /_matrix/client/v3/rooms/{roomId}/report` | Report a room |
| | `POST /_matrix/client/v3/users/{userId}/report` | Report a user |
| **Admin** | `GET /_matrix/client/v3/admin/whois/{userId}` | Get user session/device info |
| **Timestamps** | `GET /_matrix/client/v3/rooms/{roomId}/timestamp_to_event` | Find event by timestamp |
| **3PID** | `POST /_matrix/client/v3/account/3pid/email/requestToken` | Request email verification |
| | `POST /_matrix/client/v3/account/3pid/submit_token` | Submit verification code |
| | `POST /_matrix/client/v3/account/3pid/add` | Add verified 3PID to account |
| **Federation** | `PUT /_matrix/federation/v1/exchange_third_party_invite/{roomId}` | Third-party invite exchange |
| **Sync Filters** | Filter loading and application | Filters are now applied during sync |

## Quick Start

### One-Click Deploy

The fastest way to deploy is using the Deploy to Cloudflare button at the top of this README. After clicking:

1. Cloudflare provisions all resources automatically
2. You need to update `SERVER_NAME` to your domain
3. Run database migrations
4. Configure your custom domain

**See [DEPLOYMENT.md](./DEPLOYMENT.md) for complete instructions.**

### Manual Deploy

```bash
# Clone and install
git clone https://github.com/SilentHeroes/matrix-worker
cd matrix-worker
npm install

# Create resources (save IDs from output)
npx wrangler d1 create my-matrix-db
npx wrangler kv namespace create SESSIONS
npx wrangler kv namespace create DEVICE_KEYS
npx wrangler kv namespace create ONE_TIME_KEYS
npx wrangler kv namespace create CROSS_SIGNING_KEYS
npx wrangler kv namespace create CACHE
npx wrangler kv namespace create ACCOUNT_DATA
npx wrangler r2 bucket create my-matrix-media

# Update wrangler.jsonc with your resource IDs and SERVER_NAME
# Then run migrations and deploy (see DEPLOYMENT.md for details)
```

**See [DEPLOYMENT.md](./DEPLOYMENT.md) for the complete step-by-step guide.**

### Email Verification (Optional)

For 3PID email verification support, configure [Resend](https://resend.com):

```bash
# Set your Resend API key
npx wrangler secret put RESEND_API_KEY

# Set the from email address (must match your verified domain)
npx wrangler secret put EMAIL_FROM
# Example: noreply@m.easydemo.org
```

> **Note:** Cloudflare's native [Email Workers](https://developers.cloudflare.com/email-routing/email-workers/send-email-workers/) currently only support sending to pre-verified destination addresses, making them unsuitable for verification emails to arbitrary users. Resend is used as a workaround until Cloudflare releases transactional email support for Workers.

## Development

```bash
# Install dependencies
npm install

# Run locally
npm run dev

# Type check
npm run typecheck

# Run tests
npm run test

# Apply migrations locally
npm run db:migrate:local
```

## Cloudflare Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `DB` | D1 | SQLite database for persistent data |
| `SESSIONS` | KV | Access tokens and refresh tokens (with TTL) |
| `DEVICE_KEYS` | KV | E2EE device keys |
| `ONE_TIME_KEYS` | KV | Olm prekeys |
| `CROSS_SIGNING_KEYS` | KV | Cross-signing keys |
| `CACHE` | KV | General caching (presence, federation txns, sync filters) |
| `ACCOUNT_DATA` | KV | User account data |
| `MEDIA` | R2 | Media file storage |
| `ROOMS` | Durable Object | Room coordination |
| `SYNC` | Durable Object | Sync state management |
| `FEDERATION` | Durable Object | Federation queue |
| `CALL_ROOMS` | Durable Object | Video call room coordination |
| `USER_KEYS` | Durable Object | E2EE key operations |
| `PUSH` | Durable Object | Push notification queue |
| `ADMIN` | Durable Object | Admin operations |
| `RATE_LIMIT` | Durable Object | Rate limiting |
| `ROOM_JOIN_WORKFLOW` | Workflow | Async room join processing |
| `PUSH_NOTIFICATION_WORKFLOW` | Workflow | Async push delivery |

## Security

- **Password Hashing**: PBKDF2-SHA256 (100,000 iterations)
- **Token Format**: Secure random with user binding
- **Token Refresh**: Single-use refresh tokens with automatic rotation
- **Rate Limiting**: Sliding window per-IP and per-user via Durable Objects
- **Federation Auth**: Ed25519 request signing with X-Matrix header validation
- **PDU Validation**: Signature verification on incoming federation events
- **Media Auth**: Authenticated media endpoints (MSC3916)

## Compatibility

Tested with:
- Element Web
- Element X (iOS)
- Element X (Android)

Federation tested with:
- matrix.org ([view test results](https://federationtester.matrix.org/api/report?server_name=m.easydemo.org))

## Limitations

| Constraint | Limit | Notes |
|------------|-------|-------|
| Worker CPU | 30s | Use Workflows for long operations |
| Worker Memory | 128MB | Stream large responses |
| D1 Database | 10GB | Archive old events if needed |
| R2 Object | 5GB | Chunked upload supported |
| KV Value | 25MB | Split large datasets |

## License

MIT
