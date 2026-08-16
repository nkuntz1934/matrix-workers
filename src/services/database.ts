// Database service layer for D1

import type { User, Device, Room, PDU, Membership, Env } from '../types';
import { MatrixApiError } from '../utils/errors';
import { ErrorCodes } from '../types';

// D1 has an approximate 1MB per-row size cap. We validate event size on the
// way in to fail fast with M_TOO_LARGE rather than silently corrupting data.
// EVENT_CONTENT_SOFT_CAP: per-field soft cap matching Matrix spec guidance (64KB content).
// EVENT_ROW_HARD_CAP: full serialized PDU hard cap, leaves headroom under D1's 1MB limit.
const EVENT_CONTENT_SOFT_CAP = 65_536;
const EVENT_ROW_HARD_CAP = 921_600;

export function validateEventSize(event: PDU): void {
  const contentJson = JSON.stringify(event.content ?? {});
  if (contentJson.length > EVENT_CONTENT_SOFT_CAP) {
    throw new MatrixApiError(
      ErrorCodes.M_TOO_LARGE,
      `Event content exceeds ${EVENT_CONTENT_SOFT_CAP} byte limit (got ${contentJson.length})`,
      413
    );
  }
  const fullJson = JSON.stringify(event);
  if (fullJson.length > EVENT_ROW_HARD_CAP) {
    throw new MatrixApiError(
      ErrorCodes.M_TOO_LARGE,
      `Serialized event exceeds ${EVENT_ROW_HARD_CAP} byte D1 row limit (got ${fullJson.length})`,
      413
    );
  }
}

// User operations
export async function createUser(
  db: D1Database,
  userId: string,
  localpart: string,
  passwordHash: string | null,
  isGuest: boolean = false
): Promise<void> {
  await db.prepare(
    `INSERT INTO users (user_id, localpart, password_hash, is_guest, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(userId, localpart, passwordHash, isGuest ? 1 : 0, Date.now(), Date.now()).run();
}

export async function getUserById(db: D1Database, userId: string): Promise<User | null> {
  const result = await db.prepare(
    `SELECT user_id, localpart, display_name, avatar_url, is_guest, is_deactivated, admin, created_at
     FROM users WHERE user_id = ?`
  ).bind(userId).first<{
    user_id: string;
    localpart: string;
    display_name: string | null;
    avatar_url: string | null;
    is_guest: number;
    is_deactivated: number;
    admin: number;
    created_at: number;
  }>();

  if (!result) return null;

  return {
    user_id: result.user_id,
    localpart: result.localpart,
    display_name: result.display_name ?? undefined,
    avatar_url: result.avatar_url ?? undefined,
    is_guest: result.is_guest === 1,
    is_deactivated: result.is_deactivated === 1,
    admin: result.admin === 1,
    created_at: result.created_at,
  };
}

export async function getUserByLocalpart(db: D1Database, localpart: string): Promise<User | null> {
  const result = await db.prepare(
    `SELECT user_id, localpart, display_name, avatar_url, is_guest, is_deactivated, admin, created_at
     FROM users WHERE localpart = ?`
  ).bind(localpart).first<{
    user_id: string;
    localpart: string;
    display_name: string | null;
    avatar_url: string | null;
    is_guest: number;
    is_deactivated: number;
    admin: number;
    created_at: number;
  }>();

  if (!result) return null;

  return {
    user_id: result.user_id,
    localpart: result.localpart,
    display_name: result.display_name ?? undefined,
    avatar_url: result.avatar_url ?? undefined,
    is_guest: result.is_guest === 1,
    is_deactivated: result.is_deactivated === 1,
    admin: result.admin === 1,
    created_at: result.created_at,
  };
}

export async function getPasswordHash(db: D1Database, userId: string): Promise<string | null> {
  const result = await db.prepare(
    `SELECT password_hash FROM users WHERE user_id = ?`
  ).bind(userId).first<{ password_hash: string | null }>();

  return result?.password_hash ?? null;
}

export async function updateUserProfile(
  db: D1Database,
  userId: string,
  displayName?: string,
  avatarUrl?: string
): Promise<void> {
  if (displayName !== undefined) {
    await db.prepare(
      `UPDATE users SET display_name = ?, updated_at = ? WHERE user_id = ?`
    ).bind(displayName, Date.now(), userId).run();
  }
  if (avatarUrl !== undefined) {
    await db.prepare(
      `UPDATE users SET avatar_url = ?, updated_at = ? WHERE user_id = ?`
    ).bind(avatarUrl, Date.now(), userId).run();
  }
}

// Device operations
export async function createDevice(
  db: D1Database,
  userId: string,
  deviceId: string,
  displayName?: string
): Promise<void> {
  await db.prepare(
    `INSERT INTO devices (user_id, device_id, display_name, created_at)
     VALUES (?, ?, ?, ?)`
  ).bind(userId, deviceId, displayName ?? null, Date.now()).run();
}

export async function getDevice(
  db: D1Database,
  userId: string,
  deviceId: string
): Promise<Device | null> {
  const result = await db.prepare(
    `SELECT device_id, user_id, display_name, last_seen_ts, last_seen_ip, created_at
     FROM devices WHERE user_id = ? AND device_id = ?`
  ).bind(userId, deviceId).first<{
    device_id: string;
    user_id: string;
    display_name: string | null;
    last_seen_ts: number | null;
    last_seen_ip: string | null;
    created_at: number;
  }>();

  if (!result) return null;

  return {
    device_id: result.device_id,
    user_id: result.user_id,
    display_name: result.display_name ?? undefined,
    last_seen_ts: result.last_seen_ts ?? undefined,
    last_seen_ip: result.last_seen_ip ?? undefined,
  };
}

export async function getUserDevices(db: D1Database, userId: string): Promise<Device[]> {
  const result = await db.prepare(
    `SELECT device_id, user_id, display_name, last_seen_ts, last_seen_ip
     FROM devices WHERE user_id = ?`
  ).bind(userId).all<{
    device_id: string;
    user_id: string;
    display_name: string | null;
    last_seen_ts: number | null;
    last_seen_ip: string | null;
  }>();

  return result.results.map(r => ({
    device_id: r.device_id,
    user_id: r.user_id,
    display_name: r.display_name ?? undefined,
    last_seen_ts: r.last_seen_ts ?? undefined,
    last_seen_ip: r.last_seen_ip ?? undefined,
  }));
}

export async function deleteDevice(
  db: D1Database,
  userId: string,
  deviceId: string
): Promise<void> {
  await db.prepare(
    `DELETE FROM devices WHERE user_id = ? AND device_id = ?`
  ).bind(userId, deviceId).run();
}

// Access token operations
export async function createAccessToken(
  db: D1Database,
  tokenId: string,
  tokenHash: string,
  userId: string,
  deviceId: string | null
): Promise<void> {
  await db.prepare(
    `INSERT INTO access_tokens (token_id, token_hash, user_id, device_id, created_at)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(tokenId, tokenHash, userId, deviceId, Date.now()).run();
}

export async function getUserByTokenHash(
  db: D1Database,
  tokenHash: string
): Promise<{ userId: string; deviceId: string | null } | null> {
  const result = await db.prepare(
    `SELECT user_id, device_id FROM access_tokens WHERE token_hash = ?`
  ).bind(tokenHash).first<{ user_id: string; device_id: string | null }>();

  if (!result) return null;

  return {
    userId: result.user_id,
    deviceId: result.device_id,
  };
}

export async function deleteAccessToken(db: D1Database, tokenHash: string): Promise<void> {
  await db.prepare(
    `DELETE FROM access_tokens WHERE token_hash = ?`
  ).bind(tokenHash).run();
}

export async function deleteAllUserTokens(db: D1Database, userId: string): Promise<void> {
  await db.prepare(
    `DELETE FROM access_tokens WHERE user_id = ?`
  ).bind(userId).run();
}

// Room operations
export async function createRoom(
  db: D1Database,
  roomId: string,
  roomVersion: string,
  creatorId: string,
  isPublic: boolean = false
): Promise<void> {
  await db.prepare(
    `INSERT INTO rooms (room_id, room_version, creator_id, is_public, created_at)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(roomId, roomVersion, creatorId, isPublic ? 1 : 0, Date.now()).run();
}

export async function getRoom(db: D1Database, roomId: string): Promise<Room | null> {
  const result = await db.prepare(
    `SELECT room_id, room_version, is_public, creator_id, created_at
     FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{
    room_id: string;
    room_version: string;
    is_public: number;
    creator_id: string | null;
    created_at: number;
  }>();

  if (!result) return null;

  return {
    room_id: result.room_id,
    room_version: result.room_version,
    is_public: result.is_public === 1,
    creator_id: result.creator_id ?? undefined,
    created_at: result.created_at,
  };
}

// Event operations
export async function storeEvent(db: D1Database, event: PDU): Promise<number> {
  // Validate row size against D1's ~1MB per-row cap before any write.
  validateEventSize(event);

  // Atomically allocate the next stream ordering using UPDATE...RETURNING.
  // This avoids the race condition where two concurrent calls both read
  // MAX(stream_ordering) and generate the same value.
  const posResult = await db.prepare(
    `UPDATE stream_positions SET position = position + 1 WHERE stream_name = 'events' RETURNING position`
  ).first<{ position: number }>();

  const streamOrdering = posResult?.position ?? 1;

  await db.prepare(
    `INSERT INTO events (event_id, room_id, sender, event_type, state_key, content,
     origin_server_ts, unsigned, depth, auth_events, prev_events, hashes, signatures, stream_ordering)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    event.event_id,
    event.room_id,
    event.sender,
    event.type,
    event.state_key ?? null,
    JSON.stringify(event.content),
    event.origin_server_ts,
    event.unsigned ? JSON.stringify(event.unsigned) : null,
    event.depth,
    JSON.stringify(event.auth_events),
    JSON.stringify(event.prev_events),
    event.hashes ? JSON.stringify(event.hashes) : null,
    event.signatures ? JSON.stringify(event.signatures) : null,
    streamOrdering
  ).run();

  // Update room state if this is a state event
  if (event.state_key !== undefined) {
    await db.prepare(
      `INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
       VALUES (?, ?, ?, ?)`
    ).bind(event.room_id, event.type, event.state_key, event.event_id).run();
  }

  return streamOrdering;
}

// Idempotent variant of storeEvent that uses INSERT OR IGNORE on the events
// table. Returns true if a new row was inserted, false if the event_id was
// already present (indicating a concurrent / retried write was deduplicated).
//
// When the event collides, no stream_ordering is consumed and no state is
// updated — the caller can treat this as "the prior write won".
export async function storeEventIdempotent(
  db: D1Database,
  event: PDU,
): Promise<{ inserted: boolean; streamOrdering: number | null }> {
  // Allocate stream ordering optimistically. If the event already exists we
  // simply waste one stream id; this is preferable to checking-then-inserting
  // (which races) and stream ids are cheap.
  const posResult = await db.prepare(
    `UPDATE stream_positions SET position = position + 1 WHERE stream_name = 'events' RETURNING position`
  ).first<{ position: number }>();

  const streamOrdering = posResult?.position ?? 1;

  const insertResult = await db.prepare(
    `INSERT OR IGNORE INTO events (event_id, room_id, sender, event_type, state_key, content,
     origin_server_ts, unsigned, depth, auth_events, prev_events, hashes, signatures, stream_ordering)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    event.event_id,
    event.room_id,
    event.sender,
    event.type,
    event.state_key ?? null,
    JSON.stringify(event.content),
    event.origin_server_ts,
    event.unsigned ? JSON.stringify(event.unsigned) : null,
    event.depth,
    JSON.stringify(event.auth_events),
    JSON.stringify(event.prev_events),
    event.hashes ? JSON.stringify(event.hashes) : null,
    event.signatures ? JSON.stringify(event.signatures) : null,
    streamOrdering
  ).run();

  // D1 reports rows_written / changes — when 0, the row was ignored as a dup.
  const inserted = (insertResult.meta?.changes ?? 0) > 0;

  if (inserted && event.state_key !== undefined) {
    await db.prepare(
      `INSERT OR REPLACE INTO room_state (room_id, event_type, state_key, event_id)
       VALUES (?, ?, ?, ?)`
    ).bind(event.room_id, event.type, event.state_key, event.event_id).run();
  }

  return { inserted, streamOrdering: inserted ? streamOrdering : null };
}

export async function getEvent(db: D1Database, eventId: string): Promise<PDU | null> {
  const result = await db.prepare(
    `SELECT event_id, room_id, sender, event_type, state_key, content,
     origin_server_ts, unsigned, depth, auth_events, prev_events, hashes, signatures
     FROM events WHERE event_id = ?`
  ).bind(eventId).first<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    unsigned: string | null;
    depth: number;
    auth_events: string;
    prev_events: string;
    hashes: string | null;
    signatures: string | null;
  }>();

  if (!result) return null;

  return {
    event_id: result.event_id,
    room_id: result.room_id,
    sender: result.sender,
    type: result.event_type,
    state_key: result.state_key ?? undefined,
    content: JSON.parse(result.content),
    origin_server_ts: result.origin_server_ts,
    unsigned: result.unsigned ? JSON.parse(result.unsigned) : undefined,
    depth: result.depth,
    auth_events: JSON.parse(result.auth_events),
    prev_events: JSON.parse(result.prev_events),
    hashes: result.hashes ? JSON.parse(result.hashes) : undefined,
    signatures: result.signatures ? JSON.parse(result.signatures) : undefined,
  };
}

export async function getRoomEvents(
  db: D1Database,
  roomId: string,
  fromToken?: number,
  limit: number = 50,
  direction: 'f' | 'b' = 'b'
): Promise<{ events: PDU[]; end: number }> {
  let query: string;
  const params: (string | number)[] = [roomId];

  if (direction === 'b') {
    // Backwards (newest first)
    if (fromToken) {
      query = `SELECT * FROM events WHERE room_id = ? AND stream_ordering < ? ORDER BY stream_ordering DESC LIMIT ?`;
      params.push(fromToken, limit);
    } else {
      query = `SELECT * FROM events WHERE room_id = ? ORDER BY stream_ordering DESC LIMIT ?`;
      params.push(limit);
    }
  } else {
    // Forwards (oldest first)
    if (fromToken) {
      query = `SELECT * FROM events WHERE room_id = ? AND stream_ordering > ? ORDER BY stream_ordering ASC LIMIT ?`;
      params.push(fromToken, limit);
    } else {
      query = `SELECT * FROM events WHERE room_id = ? ORDER BY stream_ordering ASC LIMIT ?`;
      params.push(limit);
    }
  }

  const result = await db.prepare(query).bind(...params).all<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    unsigned: string | null;
    depth: number;
    auth_events: string;
    prev_events: string;
    stream_ordering: number;
  }>();

  const events = result.results.map(r => ({
    event_id: r.event_id,
    room_id: r.room_id,
    sender: r.sender,
    type: r.event_type,
    state_key: r.state_key ?? undefined,
    content: JSON.parse(r.content),
    origin_server_ts: r.origin_server_ts,
    unsigned: r.unsigned ? JSON.parse(r.unsigned) : undefined,
    depth: r.depth,
    auth_events: JSON.parse(r.auth_events),
    prev_events: JSON.parse(r.prev_events),
  }));

  const lastEvent = result.results[result.results.length - 1];
  const end = lastEvent?.stream_ordering ?? fromToken ?? 0;

  return { events, end };
}

// Room state operations
export async function getRoomState(
  db: D1Database,
  roomId: string
): Promise<PDU[]> {
  const result = await db.prepare(
    `SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content,
     e.origin_server_ts, e.unsigned, e.depth, e.auth_events, e.prev_events
     FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ?`
  ).bind(roomId).all<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    unsigned: string | null;
    depth: number;
    auth_events: string;
    prev_events: string;
  }>();

  return result.results.map(r => ({
    event_id: r.event_id,
    room_id: r.room_id,
    sender: r.sender,
    type: r.event_type,
    state_key: r.state_key ?? undefined,
    content: JSON.parse(r.content),
    origin_server_ts: r.origin_server_ts,
    unsigned: r.unsigned ? JSON.parse(r.unsigned) : undefined,
    depth: r.depth,
    auth_events: JSON.parse(r.auth_events),
    prev_events: JSON.parse(r.prev_events),
  }));
}

export async function getStateEvent(
  db: D1Database,
  roomId: string,
  eventType: string,
  stateKey: string = ''
): Promise<PDU | null> {
  const result = await db.prepare(
    `SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content,
     e.origin_server_ts, e.unsigned, e.depth, e.auth_events, e.prev_events
     FROM room_state rs
     JOIN events e ON rs.event_id = e.event_id
     WHERE rs.room_id = ? AND rs.event_type = ? AND rs.state_key = ?`
  ).bind(roomId, eventType, stateKey).first<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    unsigned: string | null;
    depth: number;
    auth_events: string;
    prev_events: string;
  }>();

  if (!result) return null;

  return {
    event_id: result.event_id,
    room_id: result.room_id,
    sender: result.sender,
    type: result.event_type,
    state_key: result.state_key ?? undefined,
    content: JSON.parse(result.content),
    origin_server_ts: result.origin_server_ts,
    unsigned: result.unsigned ? JSON.parse(result.unsigned) : undefined,
    depth: result.depth,
    auth_events: JSON.parse(result.auth_events),
    prev_events: JSON.parse(result.prev_events),
  };
}

// Membership operations
export async function updateMembership(
  db: D1Database,
  roomId: string,
  userId: string,
  membership: Membership,
  eventId: string,
  displayName?: string,
  avatarUrl?: string
): Promise<void> {
  await db.prepare(
    `INSERT OR REPLACE INTO room_memberships (room_id, user_id, membership, event_id, display_name, avatar_url)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(roomId, userId, membership, eventId, displayName ?? null, avatarUrl ?? null).run();
}

// Idempotent join: only writes a membership row if one does not already
// exist with membership='join'. Returns the event_id that ultimately
// represents this user's join (either the new one or the pre-existing one).
//
// This pairs with deterministic event IDs so that two concurrent join
// requests collapse to a single membership event without producing
// duplicate rows in `events` or flapping `room_memberships`.
export async function tryInsertJoinMembership(
  db: D1Database,
  roomId: string,
  userId: string,
  eventId: string,
  displayName?: string,
  avatarUrl?: string
): Promise<{ inserted: boolean; eventId: string }> {
  const result = await db.prepare(
    `INSERT INTO room_memberships (room_id, user_id, membership, event_id, display_name, avatar_url)
     VALUES (?, ?, 'join', ?, ?, ?)
     ON CONFLICT(room_id, user_id) DO UPDATE SET
       membership = CASE
         WHEN room_memberships.membership = 'join' THEN room_memberships.membership
         ELSE excluded.membership
       END,
       event_id = CASE
         WHEN room_memberships.membership = 'join' THEN room_memberships.event_id
         ELSE excluded.event_id
       END,
       display_name = CASE
         WHEN room_memberships.membership = 'join' THEN room_memberships.display_name
         ELSE excluded.display_name
       END,
       avatar_url = CASE
         WHEN room_memberships.membership = 'join' THEN room_memberships.avatar_url
         ELSE excluded.avatar_url
       END
     RETURNING event_id`
  ).bind(roomId, userId, eventId, displayName ?? null, avatarUrl ?? null)
    .first<{ event_id: string }>();

  const finalEventId = result?.event_id ?? eventId;
  return { inserted: finalEventId === eventId, eventId: finalEventId };
}

export async function getMembership(
  db: D1Database,
  roomId: string,
  userId: string
): Promise<{ membership: Membership; eventId: string } | null> {
  const result = await db.prepare(
    `SELECT membership, event_id FROM room_memberships WHERE room_id = ? AND user_id = ?`
  ).bind(roomId, userId).first<{ membership: Membership; event_id: string }>();

  if (!result) return null;

  return {
    membership: result.membership,
    eventId: result.event_id,
  };
}

export async function getUserRooms(
  db: D1Database,
  userId: string,
  membership?: Membership
): Promise<string[]> {
  let query = `SELECT room_id FROM room_memberships WHERE user_id = ?`;
  const params: string[] = [userId];

  if (membership) {
    query += ` AND membership = ?`;
    params.push(membership);
  }

  const result = await db.prepare(query).bind(...params).all<{ room_id: string }>();
  return result.results.map(r => r.room_id);
}

export async function getRoomMembers(
  db: D1Database,
  roomId: string,
  membership?: Membership
): Promise<Array<{ userId: string; membership: Membership; displayName?: string; avatarUrl?: string }>> {
  let query = `SELECT user_id, membership, display_name, avatar_url FROM room_memberships WHERE room_id = ?`;
  const params: string[] = [roomId];

  if (membership) {
    query += ` AND membership = ?`;
    params.push(membership);
  }

  const result = await db.prepare(query).bind(...params).all<{
    user_id: string;
    membership: Membership;
    display_name: string | null;
    avatar_url: string | null;
  }>();

  return result.results.map(r => ({
    userId: r.user_id,
    membership: r.membership,
    displayName: r.display_name ?? undefined,
    avatarUrl: r.avatar_url ?? undefined,
  }));
}

// Room alias operations
export async function createRoomAlias(
  db: D1Database,
  alias: string,
  roomId: string,
  creatorId: string
): Promise<void> {
  await db.prepare(
    `INSERT INTO room_aliases (alias, room_id, creator_id, created_at)
     VALUES (?, ?, ?, ?)`
  ).bind(alias, roomId, creatorId, Date.now()).run();
}

export async function getRoomByAlias(db: D1Database, alias: string): Promise<string | null> {
  const result = await db.prepare(
    `SELECT room_id FROM room_aliases WHERE alias = ?`
  ).bind(alias).first<{ room_id: string }>();

  return result?.room_id ?? null;
}

export async function deleteRoomAlias(db: D1Database, alias: string): Promise<void> {
  await db.prepare(`DELETE FROM room_aliases WHERE alias = ?`).bind(alias).run();
}

// Stream position for sync
export async function getLatestStreamPosition(db: D1Database): Promise<number> {
  const result = await db.prepare(
    `SELECT MAX(stream_ordering) as max_ordering FROM events`
  ).first<{ max_ordering: number | null }>();

  return result?.max_ordering ?? 0;
}

export async function getEventsSince(
  db: D1Database,
  roomId: string,
  since: number,
  limit: number = 100
): Promise<PDU[]> {
  const result = await db.prepare(
    `SELECT event_id, room_id, sender, event_type, state_key, content,
     origin_server_ts, unsigned, depth, auth_events, prev_events
     FROM events
     WHERE room_id = ? AND stream_ordering > ?
     ORDER BY stream_ordering ASC
     LIMIT ?`
  ).bind(roomId, since, limit).all<{
    event_id: string;
    room_id: string;
    sender: string;
    event_type: string;
    state_key: string | null;
    content: string;
    origin_server_ts: number;
    unsigned: string | null;
    depth: number;
    auth_events: string;
    prev_events: string;
  }>();

  return result.results.map(r => ({
    event_id: r.event_id,
    room_id: r.room_id,
    sender: r.sender,
    type: r.event_type,
    state_key: r.state_key ?? undefined,
    content: JSON.parse(r.content),
    origin_server_ts: r.origin_server_ts,
    unsigned: r.unsigned ? JSON.parse(r.unsigned) : undefined,
    depth: r.depth,
    auth_events: JSON.parse(r.auth_events),
    prev_events: JSON.parse(r.prev_events),
  }));
}

// Batch retrieve events by IDs.
// D1 has limits on placeholders per statement and on response size; we page
// through the input list to keep individual queries bounded.
const GET_EVENTS_PAGE_SIZE = 100;

export async function getEventsByIds(db: D1Database, eventIds: string[]): Promise<PDU[]> {
  if (eventIds.length === 0) return [];

  const out: PDU[] = [];
  for (let i = 0; i < eventIds.length; i += GET_EVENTS_PAGE_SIZE) {
    const page = eventIds.slice(i, i + GET_EVENTS_PAGE_SIZE);
    // D1 doesn't support array binding, so we batch with placeholders
    const placeholders = page.map(() => '?').join(', ');
    const result = await db.prepare(
      `SELECT event_id, room_id, sender, event_type, state_key, content,
       origin_server_ts, unsigned, depth, auth_events, prev_events, hashes, signatures
       FROM events WHERE event_id IN (${placeholders})`
    ).bind(...page).all<{
      event_id: string;
      room_id: string;
      sender: string;
      event_type: string;
      state_key: string | null;
      content: string;
      origin_server_ts: number;
      unsigned: string | null;
      depth: number;
      auth_events: string;
      prev_events: string;
      hashes: string | null;
      signatures: string | null;
    }>();

    for (const r of result.results) {
      out.push({
        event_id: r.event_id,
        room_id: r.room_id,
        sender: r.sender,
        type: r.event_type,
        state_key: r.state_key ?? undefined,
        content: JSON.parse(r.content),
        origin_server_ts: r.origin_server_ts,
        unsigned: r.unsigned ? JSON.parse(r.unsigned) : undefined,
        depth: r.depth,
        auth_events: JSON.parse(r.auth_events),
        prev_events: JSON.parse(r.prev_events),
        hashes: r.hashes ? JSON.parse(r.hashes) : undefined,
        signatures: r.signatures ? JSON.parse(r.signatures) : undefined,
      });
    }
  }
  return out;
}

// Cap auth chain traversal to avoid pathological recursion fetching thousands
// of events under D1's per-query limits.
const MAX_AUTH_CHAIN_SIZE = 500;

// Get the auth chain for an event (all auth_events recursively)
export async function getAuthChain(db: D1Database, eventIds: string[]): Promise<PDU[]> {
  const seen = new Set<string>();
  const chain: PDU[] = [];
  const queue = [...eventIds];

  while (queue.length > 0 && chain.length < MAX_AUTH_CHAIN_SIZE) {
    const batch = queue.splice(0, 50).filter(id => !seen.has(id));
    if (batch.length === 0) continue;

    for (const id of batch) seen.add(id);

    const events = await getEventsByIds(db, batch);
    for (const event of events) {
      chain.push(event);
      if (chain.length >= MAX_AUTH_CHAIN_SIZE) {
        console.warn('[getAuthChain] reached MAX_AUTH_CHAIN_SIZE cap', MAX_AUTH_CHAIN_SIZE, 'aborting traversal');
        break;
      }
      for (const authId of event.auth_events) {
        if (!seen.has(authId)) {
          queue.push(authId);
        }
      }
    }
  }

  return chain;
}

// Get the state at a specific event (by traversing auth chain)
export async function getStateAtEvent(db: D1Database, eventId: string): Promise<PDU[]> {
  const event = await getEvent(db, eventId);
  if (!event) return [];

  // Get the auth chain for this event's auth_events
  const authEvents = await getEventsByIds(db, event.auth_events);

  // Build current state from auth events
  const stateMap = new Map<string, PDU>();
  for (const authEvent of authEvents) {
    if (authEvent.state_key !== undefined) {
      stateMap.set(`${authEvent.type}\0${authEvent.state_key}`, authEvent);
    }
  }

  return Array.from(stateMap.values());
}

// Get servers that share rooms with a user
export async function getServersInRoomsWithUser(db: D1Database, userId: string): Promise<string[]> {
  const result = await db.prepare(`
    SELECT DISTINCT
      CASE
        WHEN INSTR(rm2.user_id, ':') > 0 THEN SUBSTR(rm2.user_id, INSTR(rm2.user_id, ':') + 1)
        ELSE NULL
      END as server_name
    FROM room_memberships rm1
    JOIN room_memberships rm2 ON rm1.room_id = rm2.room_id
    WHERE rm1.user_id = ?
      AND rm1.membership = 'join'
      AND rm2.membership = 'join'
      AND rm2.user_id != ?
  `).bind(userId, userId).all<{ server_name: string | null }>();

  return result.results
    .map(r => r.server_name)
    .filter((s): s is string => s !== null);
}

// Notify all room members' SyncDurableObjects when a new event is stored
// This wakes up any long-polling sync requests waiting for events
export async function notifyUsersOfEvent(
  env: Env,
  roomId: string,
  eventId: string,
  eventType: string
): Promise<void> {
  try {
    // Get all joined members of the room
    const members = await env.DB.prepare(
      `SELECT user_id FROM room_memberships WHERE room_id = ? AND membership = 'join'`
    ).bind(roomId).all<{ user_id: string }>();

    console.log('[database] Notifying', members.results.length, 'users of event', eventId,
      'users:', members.results.map(m => m.user_id).join(', '));

    // Notify each user's SyncDurableObject in parallel
    const notifications = members.results.map(async (member) => {
      try {
        const syncDO = env.SYNC.get(env.SYNC.idFromName(member.user_id));
        await syncDO.fetch(new Request('http://internal/notify', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            event_id: eventId,
            room_id: roomId,
            type: eventType,
            timestamp: Date.now(),
          }),
        }));
      } catch (error) {
        // Don't fail the whole operation if one notification fails
        console.error(`[database] Failed to notify user ${member.user_id} of event:`, error);
      }
    });

    await Promise.all(notifications);
  } catch (error) {
    // Log but don't fail - event storage was successful
    console.error('[database] Failed to notify users of event:', error);
  }
}
