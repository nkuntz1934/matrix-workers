# Tuwunel Workers - Development Roadmap

**Project Goal:** Fully functional Matrix homeserver on Cloudflare Workers
**Live Instance:** https://m.easydemo.org
**Started:** December 2024
**Last Updated:** December 8, 2024

---

## Completion Legend

- [ ] Not started
- [~] In progress
- [x] Completed (date in parentheses)

---

## Phase 1: Local Server Stability (Single Server)
*Goal: Reliable messaging for local users with Element X*

### 1.1 Security Hardening
- [x] Move TURN credentials to environment variables (Dec 8, 2024)
- [ ] Move any hardcoded secrets to Wrangler secrets
- [ ] Add input validation for all user-supplied data
- [ ] Implement CSRF protection for sensitive endpoints

### 1.2 Sync Improvements
- [ ] Implement long-polling for traditional sync (use Durable Objects)
- [ ] Add WebSocket support via SyncDurableObject
- [ ] Fix sliding sync incremental updates (INSERT/DELETE/INVALIDATE ops)
- [ ] Implement proper `since` token tracking

### 1.3 Notification System
- [ ] Calculate unread counts from read receipts
- [ ] Implement highlight detection (mentions, keywords)
- [ ] Track read markers per room per user
- [ ] Return accurate counts in sync responses

### 1.4 Real-time Features Polish
- [ ] Integrate typing notifications with sync/sliding-sync
- [ ] Integrate presence updates with sync
- [ ] Add typing timeout cleanup (30 seconds)

---

## Phase 2: E2EE Reliability
*Goal: Encrypted messaging works reliably*

### 2.1 To-Device Message Delivery
- [ ] Include to-device messages in traditional sync response
- [ ] Include to-device messages in sliding sync extensions
- [ ] Implement message acknowledgment and cleanup
- [ ] Add stream position tracking for to-device

### 2.2 Device List Changes
- [ ] Track device changes per user
- [ ] Include `device_lists.changed[]` in sync responses
- [ ] Include `device_lists.left[]` for users who left shared rooms
- [ ] Integrate with sliding sync e2ee extension

### 2.3 Key Management
- [ ] Return accurate `device_one_time_keys_count` in sync
- [ ] Return `device_unused_fallback_key_types` in sync
- [ ] Implement key change notifications across shared rooms

### 2.4 Cross-Signing Verification
- [ ] Implement UIA (User-Interactive Auth) for cross-signing upload
- [ ] Validate cross-signing key signatures
- [ ] Store and return signature chains properly

---

## Phase 3: TURN Server & VoIP
*Goal: Voice/video calls work*

### 3.1 TURN Configuration
- [x] Move TURN_KEY_ID to environment variable (Dec 8, 2024)
- [x] Move TURN_API_TOKEN to Wrangler secret (Dec 8, 2024)
- [x] Add error handling for Cloudflare TURN API failures (Dec 8, 2024)
- [x] Implement credential caching to reduce API calls (Dec 8, 2024)
- [x] Add TTL validation and refresh logic (Dec 8, 2024)

### 3.2 TURN Endpoint Improvements
- [x] Return multiple TURN server URLs (UDP, TCP, TLS) (Dec 11, 2024) - Cloudflare provides these
- [x] Add STUN server URLs to response (Dec 11, 2024) - Added Cloudflare & Google STUN servers
- [x] Implement per-user rate limiting for credential generation (Dec 11, 2024) - 5 req/min per user

### 3.3 Call Signaling (Optional - MatrixRTC)
- [ ] Research MatrixRTC requirements
- [ ] Implement call state events handling
- [ ] Add call membership tracking

---

## Phase 4: Media Improvements
*Goal: Images display properly with thumbnails*

### 4.1 Thumbnail Generation
- [ ] Research Cloudflare Image Resizing (requires Pro+)
- [ ] Alternative: Implement WASM-based image resizing
- [ ] Generate thumbnails on upload for common sizes
- [ ] Store thumbnails in R2 with naming convention
- [ ] Implement lazy thumbnail generation on request

### 4.2 Media Federation
- [ ] Implement remote media fetching
- [ ] Cache remote media in R2
- [ ] Implement media quarantine for moderation

### 4.3 Content Security
- [ ] Add Content-Security-Policy headers
- [ ] Implement media scanning hooks (optional)
- [ ] Add upload rate limiting

---

## Phase 5: Search & Discovery
*Goal: Users can find content and people*

### 5.1 Message Search
- [ ] Implement full-text search using D1 FTS5
- [ ] Add search filters (room, sender, date range)
- [ ] Implement search result highlighting
- [ ] Add search pagination

### 5.2 User Directory
- [ ] Implement `/user_directory/search` endpoint
- [ ] Index users by display name
- [ ] Filter by shared rooms (privacy)
- [ ] Add pagination support

### 5.3 Room Directory
- [ ] Implement full room directory search
- [ ] Add room filtering by type, space
- [ ] Implement federated room directory (Phase 7)

---

## Phase 6: Event Authorization & State
*Goal: Proper Matrix protocol compliance*

### 6.1 Power Level Enforcement
- [ ] Check power levels for all state events
- [ ] Check power levels for message events
- [ ] Implement `events` power level map
- [ ] Implement `users` power level map
- [ ] Add `state_default` and `events_default` handling

### 6.2 Membership Transitions
- [ ] Validate join → leave transitions
- [ ] Validate invite → join transitions
- [ ] Validate ban transitions (only higher power can ban)
- [ ] Implement knock → invite → join flow
- [ ] Add restricted room join validation

### 6.3 Event Validation
- [ ] Validate event structure per room version
- [ ] Validate required fields per event type
- [ ] Implement content hash verification
- [ ] Add redaction rules per room version

---

## Phase 7: Federation Foundation
*Goal: Cryptographic foundation for federation*

### 7.1 Ed25519 Implementation
- [ ] Add `@noble/ed25519` or `tweetnacl` dependency
- [ ] Implement proper key pair generation
- [ ] Implement JSON signing (canonical JSON + signature)
- [ ] Implement signature verification
- [ ] Store server signing keys properly

### 7.2 Event Signing
- [ ] Sign all outgoing events
- [ ] Add `hashes` field to events
- [ ] Add `signatures` field to events
- [ ] Implement event ID calculation (room version dependent)

### 7.3 Signature Verification
- [ ] Fetch remote server keys
- [ ] Cache remote keys with expiry
- [ ] Verify incoming event signatures
- [ ] Handle key rotation (old_verify_keys)

---

## Phase 8: State Resolution
*Goal: Handle concurrent state changes*

### 8.1 State Resolution v2 Algorithm
- [ ] Implement reverse topological ordering
- [ ] Implement auth chain calculation
- [ ] Implement auth chain difference
- [ ] Implement mainline ordering
- [ ] Implement power level comparison
- [ ] Implement lexicographic tiebreakers

### 8.2 Auth Chain Management
- [ ] Build auth chain for new events
- [ ] Store auth chain indices for efficient queries
- [ ] Implement auth chain difference algorithm

### 8.3 State Snapshots
- [ ] Store state snapshots at key points
- [ ] Implement state delta compression
- [ ] Add state cache for performance

---

## Phase 9: Federation - Joining Rooms
*Goal: Users can join rooms on other servers*

### 9.1 Outbound Join
- [ ] Implement server discovery (well-known, SRV)
- [ ] Implement `/make_join` request
- [ ] Sign the join event locally
- [ ] Implement `/send_join` request
- [ ] Process returned state and auth chain

### 9.2 Inbound Join
- [ ] Validate `/make_join` requests
- [ ] Create proper join event template
- [ ] Validate `/send_join` requests
- [ ] Verify join event signature
- [ ] Apply join to local state
- [ ] Return state and auth chain

### 9.3 Leave & Kick Over Federation
- [ ] Implement `/make_leave`
- [ ] Implement `/send_leave`
- [ ] Handle remote kicks

---

## Phase 10: Federation - Event Exchange
*Goal: Messages flow between servers*

### 10.1 Sending Events
- [ ] Queue outbound events in FederationDurableObject
- [ ] Implement retry logic with backoff
- [ ] Batch events in transactions
- [ ] Handle partial failures

### 10.2 Receiving Events
- [ ] Validate incoming PDU signatures
- [ ] Check event authorization
- [ ] Resolve state conflicts
- [ ] Store events properly
- [ ] Notify local users via sync

### 10.3 Backfill & Missing Events
- [ ] Implement `/backfill` endpoint
- [ ] Implement `/get_missing_events`
- [ ] Request missing events on gaps
- [ ] Implement `/event_auth` endpoint

---

## Phase 11: Federation - Invites
*Goal: Cross-server invites work*

### 11.1 Sending Invites
- [ ] Create signed invite event
- [ ] Send via `/invite/v2`
- [ ] Handle invite response

### 11.2 Receiving Invites
- [ ] Validate invite signatures
- [ ] Check invite is allowed (ACLs, etc.)
- [ ] Store stripped state for invitee
- [ ] Notify invitee via sync

### 11.3 Third-Party Invites
- [ ] Implement 3PID invite creation
- [ ] Implement 3PID invite acceptance
- [ ] Handle invite token verification

---

## Phase 12: Advanced Features
*Goal: Feature completeness*

### 12.1 Spaces
- [ ] Implement space hierarchy endpoint
- [ ] Add space child/parent relationships
- [ ] Implement space summary

### 12.2 Threads
- [ ] Implement thread root aggregation
- [ ] Add thread participation tracking
- [ ] Implement thread notifications

### 12.3 Application Services
- [ ] Implement appservice registration
- [ ] Route events to appservices
- [ ] Handle appservice queries
- [ ] Implement exclusive namespace handling

### 12.4 Account Management
- [ ] Implement email/phone 3PID verification
- [ ] Add password reset via email
- [ ] Implement account deletion with data export

---

## Phase 13: Performance & Scaling
*Goal: Production-ready performance*

### 13.1 Caching
- [ ] Implement state cache in KV
- [ ] Cache room summaries
- [ ] Cache user profiles
- [ ] Implement cache invalidation

### 13.2 Database Optimization
- [ ] Add missing indexes
- [ ] Optimize hot queries
- [ ] Implement query result caching
- [ ] Add database connection pooling hints

### 13.3 Rate Limiting Improvements
- [ ] Per-endpoint rate limit tuning
- [ ] Implement graduated rate limits
- [ ] Add rate limit bypass for trusted users
- [ ] Implement federation rate limiting

---

## Phase 14: Monitoring & Operations
*Goal: Observable and maintainable*

### 14.1 Logging & Metrics
- [ ] Add structured logging
- [ ] Implement request tracing
- [ ] Add performance metrics
- [ ] Create admin metrics dashboard

### 14.2 Health Checks
- [ ] Implement comprehensive health endpoint
- [ ] Add database health check
- [ ] Add KV health check
- [ ] Add R2 health check

### 14.3 Backup & Recovery
- [ ] Implement database backup strategy
- [ ] Document recovery procedures
- [ ] Add data export functionality

---

## Completed Milestones

### December 2024
- [x] Initial project setup (Dec 2024)
- [x] Core authentication (register/login/logout) (Dec 2024)
- [x] Basic room operations (create/join/leave) (Dec 2024)
- [x] Message sending and retrieval (Dec 2024)
- [x] Traditional sync endpoint (Dec 2024)
- [x] Sliding sync (MSC3575/MSC4186) (Dec 2024)
- [x] E2EE key upload/query/claim (Dec 2024)
- [x] Key backup API (Dec 2024)
- [x] Cross-signing keys (Dec 2024)
- [x] To-device messages API (Dec 2024)
- [x] Push rules and pushers (Dec 2024)
- [x] Account data API (Dec 2024)
- [x] Media upload/download (Dec 2024)
- [x] URL preview (Dec 2024)
- [x] Room aliases (Dec 2024)
- [x] Room upgrades (Dec 2024)
- [x] Kick/ban/unban (Dec 2024)
- [x] Room knocking (MSC2403) (Dec 2024)
- [x] Read receipts API (Dec 2024)
- [x] Typing notifications API (Dec 2024)
- [x] Presence API (Dec 2024)
- [x] Event redaction (Dec 2024)
- [x] Event context (Dec 2024)
- [x] Event relations API (Dec 2024)
- [x] Room tags (Dec 2024)
- [x] Content reporting (Dec 2024)
- [x] Server notices (Dec 2024)
- [x] Rate limiting middleware (Dec 2024)
- [x] TURN server integration (Dec 2024)
- [x] Admin dashboard (Dec 2024)

---

## Notes

### Priority Guidance
1. **For Element X compatibility:** Focus on Phases 1-3
2. **For multi-user single server:** Complete Phases 1-5
3. **For federation:** Phases 6-11 are required
4. **For production:** All phases recommended

### Dependencies
- Phase 7 (Ed25519) blocks all federation work
- Phase 6 (Authorization) should precede Phase 8 (State Resolution)
- Phase 8 (State Resolution) blocks Phase 10 (Event Exchange)

### External Resources
- [Matrix Spec](https://spec.matrix.org/latest/)
- [State Resolution v2](https://matrix.org/docs/older/stateres-v2/)
- [Conduit Source](https://gitlab.com/famedly/conduit) - Rust reference
- [Synapse Source](https://github.com/matrix-org/synapse) - Python reference
