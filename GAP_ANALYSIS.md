# Tuwunel Full Port - Gap Analysis

## Executive Summary

This document analyzes the gap between our current Cloudflare Workers implementation and the full tuwunel Matrix homeserver. Tuwunel has **22 service modules**, **45+ client API endpoints**, and **25 federation API endpoints**. Our current implementation covers approximately **30%** of the full feature set.

---

## Services Comparison

### Tuwunel Services (22 total)

| Service | Our Status | Priority | Description |
|---------|-----------|----------|-------------|
| `account_data` | ⚠️ Stub | HIGH | User account data (settings, preferences) |
| `admin` | ✅ Partial | MEDIUM | Admin API for server management |
| `appservice` | ❌ Missing | LOW | Application service (bot) integration |
| `client` | ✅ Partial | HIGH | Client-facing services |
| `config` | ⚠️ Basic | LOW | Server configuration |
| `deactivate` | ⚠️ Stub | MEDIUM | Account deactivation |
| `emergency` | ❌ Missing | LOW | Emergency server operations |
| `federation` | ⚠️ Stub | HIGH | Server-to-server federation |
| `globals` | ⚠️ Basic | MEDIUM | Global server state |
| `key_backups` | ❌ Missing | HIGH | E2E encryption key backups |
| `media` | ✅ Partial | MEDIUM | Media upload/download |
| `membership` | ✅ Partial | HIGH | Room membership management |
| `presence` | ⚠️ Stub | MEDIUM | User online/offline status |
| `pusher` | ❌ Missing | HIGH | Push notifications |
| `resolver` | ❌ Missing | MEDIUM | Server name resolution |
| `rooms` | ✅ Partial | HIGH | Room management (19 submodules) |
| `sending` | ⚠️ Basic | HIGH | Event sending infrastructure |
| `server_keys` | ⚠️ Stub | HIGH | Server signing keys |
| `sync` | ✅ Partial | HIGH | Client sync (traditional + sliding) |
| `transaction_ids` | ❌ Missing | MEDIUM | Idempotency for requests |
| `uiaa` | ⚠️ Basic | HIGH | User-Interactive Auth |
| `users` | ✅ Partial | HIGH | User management |

---

## Client API Endpoints Comparison (45+ in tuwunel)

### Authentication & Registration
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `POST /register` | ✅ | Basic registration |
| `POST /login` | ✅ | Password login |
| `POST /logout` | ✅ | Session logout |
| `POST /logout/all` | ❌ | Logout all devices |
| `GET /login` | ⚠️ | Login flows |
| `POST /refresh` | ❌ | Token refresh |
| `POST /register/available` | ❌ | Username availability |
| `GET /register/m.login.registration_token/validity` | ❌ | Registration tokens |

### Account Management
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /account/whoami` | ✅ | Current user info |
| `POST /account/password` | ❌ | Change password |
| `POST /account/deactivate` | ⚠️ | Deactivate account |
| `GET /account/3pid` | ❌ | Third-party IDs |
| `POST /account/3pid/add` | ❌ | Add 3PID |
| `POST /account/3pid/delete` | ❌ | Delete 3PID |
| `POST /account/3pid/email/requestToken` | ❌ | Email verification |

### Profile
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /profile/:userId` | ✅ | Get profile |
| `GET /profile/:userId/displayname` | ✅ | Get display name |
| `PUT /profile/:userId/displayname` | ✅ | Set display name |
| `GET /profile/:userId/avatar_url` | ✅ | Get avatar |
| `PUT /profile/:userId/avatar_url` | ✅ | Set avatar |

### Rooms
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `POST /createRoom` | ✅ | Create room |
| `GET /joined_rooms` | ✅ | List joined rooms |
| `POST /rooms/:roomId/join` | ✅ | Join room |
| `POST /join/:roomIdOrAlias` | ✅ | Join by alias |
| `POST /rooms/:roomId/leave` | ✅ | Leave room |
| `POST /rooms/:roomId/forget` | ❌ | Forget room |
| `POST /rooms/:roomId/kick` | ❌ | Kick user |
| `POST /rooms/:roomId/ban` | ❌ | Ban user |
| `POST /rooms/:roomId/unban` | ❌ | Unban user |
| `POST /rooms/:roomId/invite` | ⚠️ | Invite user |
| `GET /rooms/:roomId/members` | ✅ | Get members |
| `GET /rooms/:roomId/joined_members` | ❌ | Get joined members |
| `GET /rooms/:roomId/state` | ✅ | Get all state |
| `GET /rooms/:roomId/state/:type/:stateKey` | ✅ | Get specific state |
| `PUT /rooms/:roomId/state/:type/:stateKey` | ✅ | Set state |
| `GET /rooms/:roomId/messages` | ✅ | Get messages |
| `PUT /rooms/:roomId/send/:type/:txnId` | ✅ | Send message |
| `PUT /rooms/:roomId/redact/:eventId/:txnId` | ❌ | Redact event |
| `GET /rooms/:roomId/context/:eventId` | ❌ | Event context |
| `POST /rooms/:roomId/report/:eventId` | ❌ | Report event |
| `POST /rooms/:roomId/upgrade` | ❌ | Upgrade room |

### Room Directory & Aliases
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /publicRooms` | ✅ | Public rooms |
| `POST /publicRooms` | ⚠️ | Search public rooms |
| `GET /directory/room/:alias` | ❌ | Resolve alias |
| `PUT /directory/room/:alias` | ❌ | Create alias |
| `DELETE /directory/room/:alias` | ❌ | Delete alias |
| `GET /rooms/:roomId/aliases` | ❌ | List aliases |

### Typing & Receipts
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `PUT /rooms/:roomId/typing/:userId` | ⚠️ Stub | Typing notification |
| `POST /rooms/:roomId/receipt/:type/:eventId` | ⚠️ Stub | Read receipt |
| `POST /rooms/:roomId/read_markers` | ⚠️ Stub | Read markers |

### Account Data
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /user/:userId/account_data/:type` | ⚠️ Stub | Get account data |
| `PUT /user/:userId/account_data/:type` | ⚠️ Stub | Set account data |
| `GET /user/:userId/rooms/:roomId/account_data/:type` | ⚠️ Stub | Room account data |
| `PUT /user/:userId/rooms/:roomId/account_data/:type` | ⚠️ Stub | Set room account data |

### Presence
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /presence/:userId/status` | ⚠️ Stub | Get presence |
| `PUT /presence/:userId/status` | ⚠️ Stub | Set presence |

### Sync
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /sync` | ✅ | Traditional sync |
| `POST /...msc3575/sync` | ✅ | Sliding sync (MSC3575) |
| `POST /...simplified_msc3575/sync` | ✅ | Simplified sliding sync |

### Devices
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /devices` | ⚠️ Stub | List devices |
| `GET /devices/:deviceId` | ⚠️ Stub | Get device |
| `PUT /devices/:deviceId` | ⚠️ Stub | Update device |
| `DELETE /devices/:deviceId` | ⚠️ Stub | Delete device |
| `POST /delete_devices` | ❌ | Delete multiple |

### End-to-End Encryption
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `POST /keys/upload` | ⚠️ Basic | Upload keys |
| `POST /keys/query` | ⚠️ Basic | Query keys |
| `POST /keys/claim` | ⚠️ Basic | Claim one-time keys |
| `GET /keys/changes` | ❌ | Key changes |
| `POST /keys/signatures/upload` | ❌ | Upload signatures |
| `GET /keys/device_signing/upload` | ❌ | Cross-signing setup |

### Key Backups
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `POST /room_keys/version` | ❌ | Create backup |
| `GET /room_keys/version` | ❌ | Get backup info |
| `GET /room_keys/version/:version` | ❌ | Get specific version |
| `PUT /room_keys/version/:version` | ❌ | Update backup |
| `DELETE /room_keys/version/:version` | ❌ | Delete backup |
| `PUT /room_keys/keys` | ❌ | Upload keys |
| `GET /room_keys/keys` | ❌ | Download keys |
| `DELETE /room_keys/keys` | ❌ | Delete keys |

### To-Device Messages
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `PUT /sendToDevice/:type/:txnId` | ❌ | Send to device |

### Push Notifications
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /pushers` | ❌ | List pushers |
| `POST /pushers/set` | ❌ | Set pusher |
| `GET /pushrules` | ⚠️ Stub | Get push rules |
| `GET /pushrules/:scope/:kind/:ruleId` | ❌ | Get specific rule |
| `PUT /pushrules/:scope/:kind/:ruleId` | ❌ | Set rule |
| `DELETE /pushrules/:scope/:kind/:ruleId` | ❌ | Delete rule |
| `GET /notifications` | ❌ | Get notifications |

### Search
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `POST /search` | ⚠️ Stub | Search messages |
| `POST /user_directory/search` | ❌ | Search users |

### Media
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `POST /media/upload` | ✅ | Upload media |
| `GET /media/download/:serverName/:mediaId` | ✅ | Download media |
| `GET /media/thumbnail/:serverName/:mediaId` | ✅ | Get thumbnail |
| `GET /media/preview_url` | ❌ | URL preview |
| `GET /media/config` | ✅ | Media config |

### Spaces
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /rooms/:roomId/hierarchy` | ❌ | Space hierarchy |

### Threads
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /rooms/:roomId/threads` | ❌ | List threads |
| Relations for threads | ❌ | Thread relations |

### Relations
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /rooms/:roomId/relations/:eventId` | ❌ | Get relations |
| `GET /rooms/:roomId/relations/:eventId/:relType` | ❌ | Get by type |

### Tags
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /user/:userId/rooms/:roomId/tags` | ❌ | Get tags |
| `PUT /user/:userId/rooms/:roomId/tags/:tag` | ❌ | Set tag |
| `DELETE /user/:userId/rooms/:roomId/tags/:tag` | ❌ | Delete tag |

### VoIP
| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /voip/turnServer` | ✅ | TURN credentials |

---

## Federation API Endpoints (25 in tuwunel)

| Endpoint | Our Status | Notes |
|----------|-----------|-------|
| `GET /_matrix/federation/v1/version` | ✅ | Server version |
| `GET /.well-known/matrix/server` | ✅ | Server discovery |
| `GET /_matrix/key/v2/server` | ⚠️ Stub | Server keys |
| `GET /_matrix/key/v2/server/:keyId` | ❌ | Specific key |
| `POST /_matrix/key/v2/query` | ❌ | Query keys |
| `GET /_matrix/federation/v1/query/profile` | ❌ | Query profile |
| `GET /_matrix/federation/v1/query/directory` | ❌ | Query directory |
| `PUT /_matrix/federation/v1/send/:txnId` | ⚠️ Stub | Send events |
| `GET /_matrix/federation/v1/event/:eventId` | ❌ | Get event |
| `GET /_matrix/federation/v1/state/:roomId` | ❌ | Get room state |
| `GET /_matrix/federation/v1/state_ids/:roomId` | ❌ | Get state IDs |
| `GET /_matrix/federation/v1/backfill/:roomId` | ❌ | Backfill events |
| `POST /_matrix/federation/v1/get_missing_events/:roomId` | ❌ | Missing events |
| `GET /_matrix/federation/v1/event_auth/:roomId/:eventId` | ❌ | Event auth |
| `GET /_matrix/federation/v1/make_join/:roomId/:userId` | ❌ | Prepare join |
| `PUT /_matrix/federation/v2/send_join/:roomId/:eventId` | ❌ | Complete join |
| `GET /_matrix/federation/v1/make_leave/:roomId/:userId` | ❌ | Prepare leave |
| `PUT /_matrix/federation/v2/send_leave/:roomId/:eventId` | ❌ | Complete leave |
| `PUT /_matrix/federation/v2/invite/:roomId/:eventId` | ❌ | Send invite |
| `GET /_matrix/federation/v1/make_knock/:roomId/:userId` | ❌ | Prepare knock |
| `PUT /_matrix/federation/v1/send_knock/:roomId/:eventId` | ❌ | Complete knock |
| `GET /_matrix/federation/v1/publicRooms` | ⚠️ Stub | Public rooms |
| `POST /_matrix/federation/v1/publicRooms` | ❌ | Search public rooms |
| `GET /_matrix/federation/v1/hierarchy/:roomId` | ❌ | Space hierarchy |
| `GET /_matrix/federation/v1/openid/userinfo` | ❌ | OpenID userinfo |
| `GET /_matrix/federation/v1/media/download/:mediaId` | ❌ | Media download |
| `GET /_matrix/federation/v1/media/thumbnail/:mediaId` | ❌ | Media thumbnail |

---

## Room Services Submodules (19 in tuwunel)

| Submodule | Our Status | Notes |
|-----------|-----------|-------|
| `alias` | ⚠️ Basic | Room alias management |
| `auth_chain` | ❌ | Event authentication |
| `delete` | ❌ | Room deletion |
| `directory` | ⚠️ Basic | Room directory |
| `event_handler` | ⚠️ Basic | Event processing |
| `lazy_loading` | ❌ | Lazy member loading |
| `metadata` | ⚠️ Basic | Room metadata |
| `pdu_metadata` | ❌ | PDU handling |
| `read_receipt` | ⚠️ Stub | Read receipts |
| `search` | ❌ | Room search |
| `short` | ❌ | Short IDs |
| `spaces` | ❌ | Spaces support |
| `state` | ✅ Partial | State management |
| `state_accessor` | ⚠️ Basic | State access |
| `state_cache` | ❌ | State caching |
| `state_compressor` | ❌ | State compression |
| `threads` | ❌ | Threading |
| `timeline` | ✅ Partial | Timeline |
| `typing` | ⚠️ Stub | Typing indicators |

---

## Priority Implementation Order

### Phase 1: Critical for Element X (HIGH)
1. **Key Backups** - Required for E2EE
2. **To-Device Messages** - Required for E2EE
3. **Full E2EE Keys API** - Cross-signing, signatures
4. **Push Notifications** - Mobile app background sync
5. **Account Data** - Full implementation
6. **Transaction IDs** - Request idempotency

### Phase 2: Core Features (HIGH)
7. **Room Management** - kick, ban, unban, forget, upgrade
8. **Room Aliases** - Full CRUD
9. **User Directory Search**
10. **Event Redaction**
11. **Event Context**
12. **Relations & Threads**

### Phase 3: Federation (HIGH)
13. **Server Key Management** - Full implementation
14. **Federation Send** - Event distribution
15. **Federation Join/Leave/Invite**
16. **Backfill & Missing Events**
17. **State Resolution**

### Phase 4: Enhanced Features (MEDIUM)
18. **Presence** - Full implementation
19. **Typing Notifications** - Full implementation
20. **Read Receipts** - Full implementation
21. **Spaces** - Hierarchy and navigation
22. **Search** - Messages and users
23. **URL Previews**

### Phase 5: Extended Features (LOW)
24. **Application Services**
25. **Third-Party IDs**
26. **Room Tags**
27. **Advanced Admin**
28. **Emergency Operations**

---

## Estimated Effort

| Phase | Endpoints | Estimated Time |
|-------|-----------|---------------|
| Phase 1 | ~15 | 2-3 days |
| Phase 2 | ~20 | 2-3 days |
| Phase 3 | ~25 | 3-4 days |
| Phase 4 | ~15 | 2-3 days |
| Phase 5 | ~10 | 1-2 days |
| **Total** | **~85** | **10-15 days** |

---

## Next Steps

1. Start with Phase 1 (Critical for Element X)
2. Implement each endpoint with proper error handling
3. Add comprehensive tests
4. Update documentation
5. Deploy and test with Element X after each phase
