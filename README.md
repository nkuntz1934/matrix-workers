# Matrix Homeserver on Cloudflare Workers

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nkuntz1934/matrix-workers)

This is a proof of concept Matrix homeserver implementation running entirely on Cloudflare's edge infrastructure. This was built to prove E2EE utilizing Matrix protocols over Element X on the Cloudflare Workers Platform. It is meant to serve as an example prototype and not endorsed as ready for production at this point.

I was assisted by Claude Code Opus 4.5 for this implementation to speed up showing that you could message over Cloudflare Workers utilizing the Element Web and Element X App.  Feel free to submit issues, fork the project to make it your own, or continue to build on this example!

## Table of Contents

- [Architecture](#architecture)
- [Cloudflare Bindings](#cloudflare-bindings)
- [Request Flow](#request-flow)
- [Durable Object Architecture](#durable-object-architecture)
- [Database Schema](#database-schema)
- [API Implementation](#api-implementation)
- [Performance Optimizations](#performance-optimizations)
- [Security](#security)
- [Deployment](#deployment)
- [Limitations](#limitations)
- [Compatibility](#compatibility)
- [License](#license)

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
│         │         └─────────────┘  └─────────────┘            │             │
│         │                │                │                   │             │
│  ┌──────┴────────────────┴────────────────┴───────────────────┴───────────┐ │
│  │                          KV Namespaces                                 │ │
│  │  SESSIONS: Access tokens, refresh tokens                               │ │
│  │  DEVICE_KEYS: E2EE device keys, cross-signing keys                     │ │
│  │  CACHE: Room metadata, federation server keys                          │ │
│  │  ONE_TIME_KEYS: Olm one-time keys for E2EE                             │ │
│  │  CROSS_SIGNING_KEYS: Master, self-signing, user-signing keys           │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌────────────────────────────────────────────────────────────────────────┐ │
│  │                          Workflows (Durable Execution)                 │ │
│  │  RoomJoinWorkflow: Federation handshake with retries                   │ │
│  │  PushNotificationWorkflow: Batched push delivery                       │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Cloudflare Bindings

| Binding | Type | Purpose |
|---------|------|---------|
| `DB` | D1 | Primary SQLite database (users, rooms, events, memberships, keys) |
| `SESSIONS` | KV | Access token → user_id mapping, session metadata |
| `DEVICE_KEYS` | KV | Device key storage for E2EE |
| `ONE_TIME_KEYS` | KV | Olm one-time prekeys |
| `CROSS_SIGNING_KEYS` | KV | Cross-signing key material |
| `CACHE` | KV | Room metadata cache, federation server keys |
| `MEDIA` | R2 | Media file storage (images, videos, files) |
| `ROOMS` | Durable Object | Real-time room coordination, typing, receipts |
| `SYNC` | Durable Object | Per-user sync state, long-polling |
| `FEDERATION` | Durable Object | Federation queue, server key caching |
| `USER_KEYS` | Durable Object | E2EE key management, atomic operations |
| `PUSH` | Durable Object | Push notification queue management |
| `ROOM_JOIN_WORKFLOW` | Workflow | Durable room join with federation retry |
| `PUSH_WORKFLOW` | Workflow | Durable push notification delivery |

## Request Flow

```
Client Request
     │
     ▼
┌─────────────────┐
│  Hono Router    │ src/index.ts
│  (Workers)      │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│ Auth  │ │ Rate  │ src/middleware/
│ Check │ │ Limit │
└───┬───┘ └───┬───┘
    └────┬────┘
         ▼
┌─────────────────┐
│  API Handler    │ src/api/*.ts
│  (rooms, sync,  │
│   keys, etc.)   │
└────────┬────────┘
         │
    ┌────┼────┬────────┐
    ▼    ▼    ▼        ▼
┌─────┐┌───┐┌────┐┌─────────┐
│ D1  ││KV ││ R2 ││Durable  │
│     ││   ││    ││Objects  │
└─────┘└───┘└────┘└─────────┘
```

## Durable Object Architecture

### RoomDurableObject
- **Location**: Colocated with room's primary region
- **State**: Active members, typing users, receipt positions
- **WebSocket**: Real-time event broadcast to connected clients
- **Alarms**: Typing timeout cleanup (5s intervals)

### SyncDurableObject
- **Location**: Per-user, follows user's primary region
- **State**: Since tokens, room positions, pending events
- **Long-poll**: Efficient sync with 30s timeout
- **Batching**: Coalesces events for efficient delivery

### FederationDurableObject
- **Location**: Per-remote-server
- **State**: Transaction queue, retry state, server keys
- **Alarms**: Exponential backoff retry (1min → 1hr)
- **Signing**: Ed25519 event signatures

### UserKeysDurableObject
- **Location**: Per-user
- **State**: Device keys, cross-signing keys, OTK counts
- **Atomicity**: Single-threaded key operations
- **Consistency**: Source of truth for E2EE state

## Database Schema

### Core Tables
```sql
users (user_id PK, password_hash, display_name, avatar_url, admin, created_at)
rooms (room_id PK, version, creator, created_at, tombstone_event_id)
events (event_id PK, room_id, type, state_key, sender, content, origin_server_ts)
room_memberships (room_id, user_id, membership, display_name, avatar_url)
room_state (room_id, event_type, state_key, event_id) -- current state snapshot
```

### E2EE Tables
```sql
devices (user_id, device_id, display_name, keys, signatures)
cross_signing_keys (user_id, key_type, key_data, signatures)
cross_signing_signatures (user_id, key_id, signer_user_id, signature)
key_backup_versions (version PK, user_id, algorithm, auth_data)
key_backup_keys (user_id, version, room_id, session_id, session_data)
one_time_keys (user_id, device_id, key_id, algorithm, key_data)
fallback_keys (user_id, device_id, key_id, algorithm, key_data, used)
```

### Sync & Messaging
```sql
access_tokens (token PK, user_id, device_id, created_at)
sync_tokens (user_id, device_id, since_token, room_positions)
to_device_messages (id, user_id, device_id, sender, type, content)
typing (room_id, user_id, timeout_at)
receipts (room_id, user_id, event_id, receipt_type, ts)
```

## API Implementation

### Client-Server API (/_matrix/client)

| Endpoint | Status | Notes |
|----------|--------|-------|
| `/v3/login` | ✅ | Password auth, device creation |
| `/v3/register` | ✅ | UIA flow, username validation |
| `/v3/sync` | ✅ | Full sync, incremental, filtered |
| `/unstable/org.matrix.simplified_msc3575/sync` | ✅ | Sliding sync |
| `/v3/rooms/{roomId}/send` | ✅ | With txn deduplication |
| `/v3/rooms/{roomId}/state` | ✅ | State events, power levels |
| `/v3/keys/upload` | ✅ | Device keys, OTKs |
| `/v3/keys/query` | ✅ | Cross-user key fetch |
| `/v3/keys/claim` | ✅ | OTK claiming |
| `/v3/room_keys/*` | ✅ | Key backup CRUD |
| `/v3/keys/signatures/upload` | ✅ | Cross-signing |
| `/v3/sendToDevice` | ✅ | E2EE key exchange |
| `/v3/pushrules` | ✅ | Full push rule API |
| `/v3/pushers` | ✅ | APNs, FCM registration |

### Server-Server API (/_matrix/federation)

| Endpoint | Status | Notes |
|----------|--------|-------|
| `/v1/version` | ✅ | Server version |
| `/v1/key/server` | ✅ | Ed25519 server keys |
| `/v1/make_join` | ✅ | Join template |
| `/v1/send_join` | ✅ | Room join completion |
| `/v1/send` | ✅ | PDU reception |
| `/v1/backfill` | ✅ | Event backfill |

## Performance Optimizations

### Query Optimization
- **Batched D1 queries**: `db.batch()` for parallel query execution
- **Consolidated JOINs**: Single query for room metadata vs N+1
- **Indexed columns**: `room_state(room_id, event_type)`, `room_memberships(room_id, membership)`

### Caching Strategy
- **Room metadata**: KV cache with 5-minute TTL
- **Server keys**: KV cache with 24-hour TTL
- **Device keys**: KV primary, D1 backup

### Sync Optimization
- **Sliding sync**: Returns only requested room ranges
- **Delta sync**: Only changed rooms/events since token
- **Parallel fetching**: Room data fetched concurrently

## Security

### Authentication
- **Password hashing**: Argon2id via `@noble/hashes`
- **Token format**: `syt_{userId}_{random}_{timestamp}`
- **Token storage**: KV with user_id → token mapping

### Rate Limiting
- **Sliding window**: Per-IP, per-user limits
- **Endpoint tiers**: Auth (stricter), API (standard)
- **Headers**: `X-RateLimit-Limit`, `X-RateLimit-Remaining`

### E2EE
- **Device verification**: Cross-signing key chain
- **Key backup**: Encrypted with recovery key
- **OTK management**: Atomic claim to prevent reuse

## Deployment

### Prerequisites
- Cloudflare account (Workers Paid plan for Durable Objects)
- `wrangler` CLI authenticated

### Quick Deploy
```bash
# Clone and install
git clone https://github.com/nkuntz1934/matrix-workers
cd matrix-workers
npm install

# Create resources (copy the IDs from output)
wrangler d1 create matrix-db
wrangler kv namespace create SESSIONS
wrangler kv namespace create DEVICE_KEYS
wrangler kv namespace create ONE_TIME_KEYS
wrangler kv namespace create CROSS_SIGNING_KEYS
wrangler kv namespace create CACHE
wrangler kv namespace create ACCOUNT_DATA
wrangler r2 bucket create matrix-media

# Deploy
wrangler deploy
```

### Configuration

**You must update `wrangler.jsonc` before deploying.** Replace all placeholder values:

| Placeholder | Description | How to Get |
|-------------|-------------|------------|
| `YOUR_ACCOUNT_ID` | Cloudflare account ID | Dashboard URL or `wrangler whoami` |
| `YOUR_DATABASE_ID` | D1 database ID | Output from `wrangler d1 create` |
| `YOUR_*_KV_ID` | KV namespace IDs | Output from `wrangler kv namespace create` |
| `SERVER_NAME` | Your Matrix domain | e.g., `matrix.example.com` |
| `TURN_KEY_ID` | Cloudflare TURN key | Cloudflare Dashboard → Calls → TURN |
| `LIVEKIT_*` | LiveKit credentials | Optional, for video calls |

### Environment Variables
```jsonc
{
  "vars": {
    "SERVER_NAME": "matrix.example.com",
    "REGISTRATION_ENABLED": "true"
  }
}
```

## Limitations

| Constraint | Limit | Workaround |
|------------|-------|------------|
| Worker CPU time | 30s (paid) | Workflows for long operations |
| Worker memory | 128MB | Streaming for large responses |
| D1 database | 10GB | Archive old events |
| D1 query | 100ms soft | Indexed queries, batching |
| R2 object | 5GB | Chunked upload for large media |
| KV value | 25MB | Split large key sets |
| Durable Object | Single-threaded | Partition by room/user |

## Compatibility

Tested with:
- Element Web
- Element X (iOS/Android)

## License

MIT
