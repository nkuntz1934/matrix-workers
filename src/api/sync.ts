// Matrix sync endpoint

import { Hono } from 'hono';
import type { AppEnv, SyncResponse, JoinedRoom, InvitedRoom, LeftRoom, Env } from '../types';
import { requireAuth } from '../middleware/auth';
import {
  getUserRooms,
  getRoomState,
  getEventsSince,
  getLatestStreamPosition,
} from '../services/database';
import { getVisibilityContext, filterEventsByVisibility } from '../services/history-visibility';
import { getToDeviceMessages } from './to-device';
import {
  getGlobalAccountData,
  getRoomAccountData,
} from './account-data';
import { getReceiptsForRoom } from './receipts';
import { getTypingUsers } from './typing';

// ============================================
// Sync Filter Types and Helpers
// ============================================

interface EventFilter {
  types?: string[];
  not_types?: string[];
  senders?: string[];
  not_senders?: string[];
  limit?: number;
}

interface RoomFilter {
  rooms?: string[];
  not_rooms?: string[];
  timeline?: EventFilter;
  state?: EventFilter;
  ephemeral?: EventFilter;
  account_data?: EventFilter;
  include_leave?: boolean;
}

interface SyncFilter {
  room?: RoomFilter;
  presence?: EventFilter;
  account_data?: EventFilter;
  event_format?: 'client' | 'federation';
  event_fields?: string[];
}

// Load a filter from KV storage or parse inline JSON
async function loadFilter(env: Env, userId: string, filterParam?: string): Promise<SyncFilter | null> {
  if (!filterParam) return null;

  // Check if it's inline JSON (starts with '{')
  if (filterParam.startsWith('{')) {
    try {
      return JSON.parse(filterParam);
    } catch {
      console.warn('[sync] Failed to parse inline filter JSON');
      return null;
    }
  }

  // Otherwise it's a filter ID - load from KV
  const filterJson = await env.CACHE.get(`filter:${userId}:${filterParam}`);
  if (!filterJson) {
    console.warn('[sync] Filter not found:', filterParam);
    return null;
  }

  try {
    return JSON.parse(filterJson);
  } catch {
    console.warn('[sync] Failed to parse stored filter JSON');
    return null;
  }
}

// Apply an event filter to a list of events
function applyEventFilter(events: any[], filter?: EventFilter): any[] {
  if (!filter) return events;

  let result = events.filter(event => {
    // Filter by type whitelist
    if (filter.types && filter.types.length > 0) {
      const matches = filter.types.some(pattern => {
        if (pattern.endsWith('*')) {
          return event.type.startsWith(pattern.slice(0, -1));
        }
        return event.type === pattern;
      });
      if (!matches) return false;
    }

    // Filter by type blacklist
    if (filter.not_types && filter.not_types.length > 0) {
      const excluded = filter.not_types.some(pattern => {
        if (pattern.endsWith('*')) {
          return event.type.startsWith(pattern.slice(0, -1));
        }
        return event.type === pattern;
      });
      if (excluded) return false;
    }

    // Filter by sender whitelist
    if (filter.senders && filter.senders.length > 0) {
      if (!filter.senders.includes(event.sender)) return false;
    }

    // Filter by sender blacklist
    if (filter.not_senders && filter.not_senders.length > 0) {
      if (filter.not_senders.includes(event.sender)) return false;
    }

    return true;
  });

  // Apply limit
  if (filter.limit && filter.limit > 0) {
    result = result.slice(0, filter.limit);
  }

  return result;
}

// Check if a room should be included based on room filter
function shouldIncludeRoom(roomId: string, filter?: RoomFilter): boolean {
  if (!filter) return true;

  // Room whitelist
  if (filter.rooms && filter.rooms.length > 0) {
    if (!filter.rooms.includes(roomId)) return false;
  }

  // Room blacklist
  if (filter.not_rooms && filter.not_rooms.length > 0) {
    if (filter.not_rooms.includes(roomId)) return false;
  }

  return true;
}

// Helper to get one-time key counts for a device
async function getOneTimeKeyCounts(
  db: D1Database,
  userId: string,
  deviceId: string
): Promise<Record<string, number>> {
  const counts = await db.prepare(`
    SELECT algorithm, COUNT(*) as count
    FROM one_time_keys
    WHERE user_id = ? AND device_id = ? AND claimed = 0
    GROUP BY algorithm
  `).bind(userId, deviceId).all<{ algorithm: string; count: number }>();

  const result: Record<string, number> = {};
  for (const row of counts.results) {
    result[row.algorithm] = row.count;
  }
  return result;
}

// Helper to get unused fallback key types for a device
async function getUnusedFallbackKeyTypes(
  db: D1Database,
  userId: string,
  deviceId: string
): Promise<string[]> {
  const keys = await db.prepare(`
    SELECT DISTINCT algorithm
    FROM fallback_keys
    WHERE user_id = ? AND device_id = ? AND used = 0
  `).bind(userId, deviceId).all<{ algorithm: string }>();

  return keys.results.map(row => row.algorithm);
}

// Helper to get device list changes (users whose keys have changed since last sync)
async function getDeviceListChanges(
  db: D1Database,
  userId: string,
  sincePosition: number
): Promise<{ changed: string[]; left: string[] }> {
  // Get users in shared rooms whose device keys have changed
  // Note: We now include the user's own changes as well, because
  // cross-signing signature uploads need to trigger key refresh
  const otherUsersChanged = await db.prepare(`
    SELECT DISTINCT dkc.user_id
    FROM device_key_changes dkc
    WHERE dkc.stream_position > ?
      AND dkc.user_id != ?
      AND EXISTS (
        SELECT 1 FROM room_memberships rm1
        JOIN room_memberships rm2 ON rm1.room_id = rm2.room_id
        WHERE rm1.user_id = ? AND rm1.membership = 'join'
          AND rm2.user_id = dkc.user_id AND rm2.membership = 'join'
      )
  `).bind(sincePosition, userId, userId).all<{ user_id: string }>();

  // Check if the user's own keys have changed (for cross-signing signatures)
  const selfChanged = await db.prepare(`
    SELECT COUNT(*) as count
    FROM device_key_changes dkc
    WHERE dkc.stream_position > ?
      AND dkc.user_id = ?
  `).bind(sincePosition, userId).first<{ count: number }>();

  const changedUsers = otherUsersChanged.results.map(row => row.user_id);

  // Include self in changed list if own keys updated (for cross-signing verification)
  if (selfChanged && selfChanged.count > 0) {
    changedUsers.push(userId);
  }

  // For left, we'd track users who left shared rooms, but for simplicity return empty for now
  return {
    changed: changedUsers,
    left: [],
  };
}

const app = new Hono<AppEnv>();

// GET /_matrix/client/v3/sync - Sync with server
// Parse composite sync token: "s{events}_td{to_device}" or legacy plain number
function parseSyncToken(token: string | undefined): { events: number; toDevice: number } {
  if (!token) {
    return { events: 0, toDevice: 0 };
  }

  // Try composite format first: s84_td119
  const match = token.match(/^s(\d+)_td(\d+)$/);
  if (match) {
    return { events: parseInt(match[1]), toDevice: parseInt(match[2]) };
  }

  // Legacy format: plain number (use for both streams for backwards compat)
  const num = parseInt(token);
  if (!isNaN(num)) {
    return { events: num, toDevice: num };
  }

  return { events: 0, toDevice: 0 };
}

// Build composite sync token
function buildSyncToken(eventsPos: number, toDevicePos: number): string {
  return `s${eventsPos}_td${toDevicePos}`;
}

app.get('/_matrix/client/v3/sync', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const deviceId = c.get('deviceId');

  // Parse query parameters
  const since = c.req.query('since');
  const fullState = c.req.query('full_state') === 'true';
  const filterParam = c.req.query('filter');

  // Load filter if specified
  const filter = await loadFilter(c.env, userId, filterParam);
  if (filterParam && !filter) {
    console.log('[sync] Using no filter (filter not found or invalid)');
  }

  // Parse composite sync token (separate positions for events and to-device)
  const { events: sincePosition, toDevice: sinceToDevice } = parseSyncToken(since);

  // Get current position
  const currentPosition = await getLatestStreamPosition(c.env.DB);

  // Track to-device position for next_batch
  let currentToDevicePos = sinceToDevice;

  // If no changes and timeout, wait (using Durable Objects for long-polling)
  // For now, just return immediately

  // Build sync response (next_batch will be set at the end)
  const response: SyncResponse = {
    next_batch: '', // Set below
    rooms: {
      join: {},
      invite: {},
      leave: {},
    },
    presence: {
      events: [],
    },
    account_data: {
      events: [],
    },
    to_device: {
      events: [],
    },
    device_one_time_keys_count: {},
    device_unused_fallback_key_types: [],
  };

  // Get to-device messages (E2E encryption key exchange, verification, etc.)
  if (deviceId) {
    // Pass the to-device specific position for proper acknowledgment
    const toDeviceResult = await getToDeviceMessages(c.env.DB, userId, deviceId, String(sinceToDevice));
    response.to_device!.events = toDeviceResult.events;

    // Update to-device position for next_batch
    currentToDevicePos = parseInt(toDeviceResult.nextBatch) || sinceToDevice;

    // Get E2E encryption key counts for this device
    response.device_one_time_keys_count = await getOneTimeKeyCounts(c.env.DB, userId, deviceId);
    response.device_unused_fallback_key_types = await getUnusedFallbackKeyTypes(c.env.DB, userId, deviceId);

    // Debug E2EE state for first sync
    if (sincePosition === 0) {
      console.log('[sync] Initial sync E2EE state for', userId, ':', {
        otk_counts: response.device_one_time_keys_count,
        fallback_types: response.device_unused_fallback_key_types,
        to_device_count: response.to_device!.events.length,
      });
    }
  }

  // Get device list changes (users whose keys have changed since last sync)
  if (sincePosition > 0) {
    const deviceListChanges = await getDeviceListChanges(c.env.DB, userId, sincePosition);
    if (deviceListChanges.changed.length > 0 || deviceListChanges.left.length > 0) {
      response.device_lists = deviceListChanges;
    }
  } else {
    // For initial sync, include the user's own ID in device_lists.changed
    // This tells Element X to fetch device keys immediately, which is important
    // for cross-signing verification to work correctly after first login
    response.device_lists = {
      changed: [userId],
      left: [],
    };
    console.log('[sync] Initial sync - including self in device_lists.changed to trigger key fetch');
  }

  // Get global account data
  // For initial sync (no since token), get all account data
  // For incremental sync, only get changed account data since last sync
  let globalAccountData = await getGlobalAccountData(
    c.env.DB,
    userId,
    sincePosition > 0 ? sincePosition : undefined
  );
  // Apply account_data filter to global account data
  globalAccountData = applyEventFilter(globalAccountData, filter?.account_data);
  response.account_data!.events = globalAccountData;

  // Debug: Log global account_data that will be returned (for initial sync)
  if (sincePosition === 0) {
    console.log('[sync] Initial sync account_data for', userId, ':',
      globalAccountData.length > 0 ? globalAccountData.map(e => e.type) : 'none');
  }

  // Get user's joined rooms
  const joinedRoomIds = await getUserRooms(c.env.DB, userId, 'join');
  for (const roomId of joinedRoomIds) {
    // Check if room should be included based on filter
    if (!shouldIncludeRoom(roomId, filter?.room)) {
      continue;
    }

    const joinedRoom: JoinedRoom = {
      timeline: {
        events: [],
        limited: false,
      },
      state: {
        events: [],
      },
      ephemeral: {
        events: [],
      },
      account_data: {
        events: [],
      },
    };

    // Get events since last sync
    const events = await getEventsSince(c.env.DB, roomId, sincePosition);

    // Filter events by history visibility
    const visibilityContext = await getVisibilityContext(c.env.DB, roomId, userId);
    const visibleEvents = filterEventsByVisibility(events, visibilityContext);

    // Separate state and timeline events
    let stateEvents: any[] = [];
    let timelineEvents: any[] = [];

    for (const event of visibleEvents) {
      const clientEvent = {
        type: event.type,
        state_key: event.state_key,
        content: event.content,
        sender: event.sender,
        origin_server_ts: event.origin_server_ts,
        event_id: event.event_id,
        room_id: event.room_id,
        unsigned: event.unsigned,
      };

      if (event.state_key !== undefined) {
        // State event - include in both state and timeline
        stateEvents.push(clientEvent);
      }
      timelineEvents.push(clientEvent);
    }

    // Include full state if requested or initial sync
    if (fullState || sincePosition === 0) {
      const state = await getRoomState(c.env.DB, roomId);
      for (const event of state) {
        const clientEvent = {
          type: event.type,
          state_key: event.state_key,
          content: event.content,
          sender: event.sender,
          origin_server_ts: event.origin_server_ts,
          event_id: event.event_id,
          room_id: event.room_id,
        };
        // Only add if not already in state events from timeline
        if (!stateEvents.find(e => e.event_id === event.event_id)) {
          stateEvents.push(clientEvent);
        }
      }
    }

    // Apply filters to state and timeline events
    stateEvents = applyEventFilter(stateEvents, filter?.room?.state);
    timelineEvents = applyEventFilter(timelineEvents, filter?.room?.timeline);

    joinedRoom.state!.events = stateEvents;
    joinedRoom.timeline!.events = timelineEvents;
    joinedRoom.timeline!.prev_batch = sincePosition.toString();

    // Get room-level account data
    let roomAccountData = await getRoomAccountData(
      c.env.DB,
      userId,
      roomId,
      sincePosition > 0 ? sincePosition : undefined
    );
    // Apply account_data filter to room account data
    roomAccountData = applyEventFilter(roomAccountData, filter?.room?.account_data);
    joinedRoom.account_data!.events = roomAccountData;

    // Get read receipts for this room (from Room Durable Object)
    // Pass userId to filter m.read.private receipts (only visible to owner)
    const receipts = await getReceiptsForRoom(c.env, roomId, userId);
    if (Object.keys(receipts.content).length > 0) {
      joinedRoom.ephemeral!.events.push(receipts);
    }

    // Get typing indicators for this room (from Room Durable Object)
    const typingUsers = await getTypingUsers(c.env, roomId);
    if (typingUsers.length > 0) {
      joinedRoom.ephemeral!.events.push({
        type: 'm.typing',
        content: { user_ids: typingUsers }
      });
    }

    // Apply ephemeral filter
    joinedRoom.ephemeral!.events = applyEventFilter(
      joinedRoom.ephemeral!.events,
      filter?.room?.ephemeral
    );

    response.rooms!.join![roomId] = joinedRoom;
  }

  // Get invited rooms
  const invitedRoomIds = await getUserRooms(c.env.DB, userId, 'invite');
  for (const roomId of invitedRoomIds) {
    // Check if room should be included based on filter
    if (!shouldIncludeRoom(roomId, filter?.room)) {
      continue;
    }

    const state = await getRoomState(c.env.DB, roomId);

    // Strip state for invited rooms
    let strippedState = state.map(event => ({
      type: event.type,
      state_key: event.state_key!,
      content: event.content,
      sender: event.sender,
    }));

    // Apply state filter to invited room state
    strippedState = applyEventFilter(strippedState, filter?.room?.state);

    const invitedRoom: InvitedRoom = {
      invite_state: {
        events: strippedState,
      },
    };

    response.rooms!.invite![roomId] = invitedRoom;
  }

  // Get left rooms (rooms user left since last sync)
  // Check if filter allows left rooms (default: false per spec)
  const includeLeave = filter?.room?.include_leave ?? false;
  if (sincePosition > 0 && (includeLeave || !filter)) {
    const leftRoomIds = await getUserRooms(c.env.DB, userId, 'leave');
    for (const roomId of leftRoomIds) {
      // Check if room should be included based on filter
      if (!shouldIncludeRoom(roomId, filter?.room)) {
        continue;
      }

      // Only include if membership changed since last sync
      const events = await getEventsSince(c.env.DB, roomId, sincePosition);
      const leaveEvent = events.find(
        e => e.type === 'm.room.member' && e.state_key === userId
      );

      if (leaveEvent) {
        const leftRoom: LeftRoom = {
          timeline: {
            events: [
              {
                type: leaveEvent.type,
                state_key: leaveEvent.state_key,
                content: leaveEvent.content,
                sender: leaveEvent.sender,
                origin_server_ts: leaveEvent.origin_server_ts,
                event_id: leaveEvent.event_id,
                room_id: leaveEvent.room_id,
              },
            ],
          },
        };

        response.rooms!.leave![roomId] = leftRoom;
      }
    }
  }

  // Check if there are any changes to return
  const hasRoomChanges = Object.keys(response.rooms!.join!).some(roomId => {
    const room = response.rooms!.join![roomId];
    return room.timeline!.events.length > 0 || room.state!.events.length > 0;
  });
  const hasInvites = Object.keys(response.rooms!.invite!).length > 0;
  const hasLeaves = Object.keys(response.rooms!.leave!).length > 0;
  const hasToDevice = response.to_device!.events.length > 0;
  const hasAccountData = response.account_data!.events.length > 0;
  const hasChanges = hasRoomChanges || hasInvites || hasLeaves || hasToDevice || hasAccountData;

  // Parse timeout from query params (default 0 for no wait, max 30s)
  const timeout = Math.min(parseInt(c.req.query('timeout') || '0'), 30000);

  // If no changes and timeout > 0, wait for events via Durable Object
  if (!hasChanges && timeout > 0 && sincePosition > 0) {
    console.log('[sync] Entering DO wait for', userId, 'timeout:', timeout);
    const syncDO = c.env.SYNC;
    const doId = syncDO.idFromName(userId);
    const stub = syncDO.get(doId);

    // Wait for up to 25s (leave buffer for response)
    const waitTimeout = Math.min(timeout, 25000);
    const waitResponse = await stub.fetch(new Request('http://internal/wait-for-events', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ timeout: waitTimeout }),
    }));

    const waitResult = await waitResponse.json() as { hasEvents: boolean };
    console.log('[sync] DO wait result for', userId, ':', waitResult);

    if (waitResult.hasEvents) {
      console.log('[sync] Woken up early - events arrived for', userId);
      // New events arrived - return empty response with SAME next_batch
      // Client will immediately sync again and get the new events
      // We intentionally do NOT advance next_batch here, so the client
      // re-syncs from the same position and actually sees the events
    }
  } else if (timeout > 0 && sincePosition > 0) {
    console.log('[sync] Skipping DO wait for', userId, '- hasChanges:', hasChanges,
      'roomChanges:', hasRoomChanges, 'invites:', hasInvites, 'leaves:', hasLeaves,
      'toDevice:', hasToDevice, 'accountData:', hasAccountData);
  }

  // Build composite next_batch token with separate positions for each stream
  if (!response.next_batch) {
    response.next_batch = buildSyncToken(currentPosition, currentToDevicePos);
  }

  return c.json(response);
});

export default app;
