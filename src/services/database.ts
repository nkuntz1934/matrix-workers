// Database service layer for D1

import type { User, Device, Room, PDU, Membership, Env } from '../types';
import { applyRedactionsToEvents } from './redaction';
import { calculateContentHash } from '../utils/crypto';

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
  // Get the next stream ordering
  const lastOrdering = await db.prepare(
    `SELECT MAX(stream_ordering) as max_ordering FROM events`
  ).first<{ max_ordering: number | null }>();

  const streamOrdering = (lastOrdering?.max_ordering ?? 0) + 1;

  // Compute content hash if not already present (for locally-created events)
  let hashes = event.hashes;
  if (!hashes) {
    const contentHash = await calculateContentHash(event as unknown as Record<string, unknown>);
    hashes = { sha256: contentHash };
  }

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
    JSON.stringify(hashes),
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

export async function getEvent(db: D1Database, eventId: string): Promise<PDU | null> {
  const result = await db.prepare(
    `SELECT event_id, room_id, sender, event_type, state_key, content,
     origin_server_ts, unsigned, depth, auth_events, prev_events, hashes, signatures,
     redacted_because
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
    redacted_because: string | null;
  }>();

  if (!result) return null;

  const event: PDU = {
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

  // Apply redaction if the event was redacted
  if (result.redacted_because) {
    const [redactedEvent] = await applyRedactionsToEvents(
      [{ event, redactedBecause: result.redacted_because }],
      (id) => getEventRaw(db, id)
    );
    return redactedEvent;
  }

  return event;
}

/**
 * Get an event without applying redaction (for internal use)
 * This is used to fetch redaction events themselves
 */
export async function getEventRaw(db: D1Database, eventId: string): Promise<PDU | null> {
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
      query = `SELECT event_id, room_id, sender, event_type, state_key, content,
               origin_server_ts, unsigned, depth, auth_events, prev_events, stream_ordering,
               redacted_because
               FROM events WHERE room_id = ? AND stream_ordering < ? ORDER BY stream_ordering DESC LIMIT ?`;
      params.push(fromToken, limit);
    } else {
      query = `SELECT event_id, room_id, sender, event_type, state_key, content,
               origin_server_ts, unsigned, depth, auth_events, prev_events, stream_ordering,
               redacted_because
               FROM events WHERE room_id = ? ORDER BY stream_ordering DESC LIMIT ?`;
      params.push(limit);
    }
  } else {
    // Forwards (oldest first)
    if (fromToken) {
      query = `SELECT event_id, room_id, sender, event_type, state_key, content,
               origin_server_ts, unsigned, depth, auth_events, prev_events, stream_ordering,
               redacted_because
               FROM events WHERE room_id = ? AND stream_ordering > ? ORDER BY stream_ordering ASC LIMIT ?`;
      params.push(fromToken, limit);
    } else {
      query = `SELECT event_id, room_id, sender, event_type, state_key, content,
               origin_server_ts, unsigned, depth, auth_events, prev_events, stream_ordering,
               redacted_because
               FROM events WHERE room_id = ? ORDER BY stream_ordering ASC LIMIT ?`;
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
    redacted_because: string | null;
  }>();

  // Build events with their redaction status
  const eventsWithRedaction = result.results.map(r => ({
    event: {
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
    } as PDU,
    redactedBecause: r.redacted_because,
  }));

  // Apply redactions
  const events = await applyRedactionsToEvents(eventsWithRedaction, (id) => getEventRaw(db, id));

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
     e.origin_server_ts, e.unsigned, e.depth, e.auth_events, e.prev_events,
     e.redacted_because
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
    redacted_because: string | null;
  }>();

  // Build events with their redaction status
  const eventsWithRedaction = result.results.map(r => ({
    event: {
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
    } as PDU,
    redactedBecause: r.redacted_because,
  }));

  // Apply redactions
  return applyRedactionsToEvents(eventsWithRedaction, (id) => getEventRaw(db, id));
}

export async function getStateEvent(
  db: D1Database,
  roomId: string,
  eventType: string,
  stateKey: string = ''
): Promise<PDU | null> {
  const result = await db.prepare(
    `SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content,
     e.origin_server_ts, e.unsigned, e.depth, e.auth_events, e.prev_events,
     e.redacted_because
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
    redacted_because: string | null;
  }>();

  if (!result) return null;

  const event: PDU = {
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

  // Apply redaction if the event was redacted
  if (result.redacted_because) {
    const [redactedEvent] = await applyRedactionsToEvents(
      [{ event, redactedBecause: result.redacted_because }],
      (id) => getEventRaw(db, id)
    );
    return redactedEvent;
  }

  return event;
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
     origin_server_ts, unsigned, depth, auth_events, prev_events, redacted_because
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
    redacted_because: string | null;
  }>();

  // Build events with their redaction status
  const eventsWithRedaction = result.results.map(r => ({
    event: {
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
    } as PDU,
    redactedBecause: r.redacted_because,
  }));

  // Apply redactions
  return applyRedactionsToEvents(eventsWithRedaction, (id) => getEventRaw(db, id));
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
