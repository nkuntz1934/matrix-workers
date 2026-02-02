// Matrix room endpoints

import { Hono } from 'hono';
import type { AppEnv, RoomCreateContent, RoomMemberContent, PDU } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';
import { generateRoomId, generateEventId, formatRoomAlias } from '../utils/ids';
import { invalidateRoomCache } from '../services/room-cache';
import {
  createRoom,
  getRoom,
  storeEvent,
  getRoomState,
  getStateEvent,
  getRoomEvents,
  updateMembership,
  getMembership,
  getUserRooms,
  getRoomMembers,
  createRoomAlias,
  getRoomByAlias,
  deleteRoomAlias,
  getEvent,
  getEventRaw,
  notifyUsersOfEvent,
} from '../services/database';
import { applyRedactionsToEvents } from '../services/redaction';
import { getVisibilityContext, filterEventsByVisibility } from '../services/history-visibility';
import type { JoinResult } from '../workflows';
import { validateEventContent } from '../services/event-validation';
import { canSendStateEvent, canModifyPowerLevels } from '../services/power-levels';
import type { RoomPowerLevelsContent } from '../types/matrix';

const app = new Hono<AppEnv>();

// Validation for initial_state events
interface StateEventValidation {
  valid: boolean;
  error?: string;
}

function validateStateEvent(event: any, index: number): StateEventValidation {
  // Must be an object
  if (!event || typeof event !== 'object') {
    return { valid: false, error: `initial_state[${index}]: must be an object` };
  }

  // Must have a type property that is a non-empty string
  if (!event.type || typeof event.type !== 'string' || event.type.trim() === '') {
    return { valid: false, error: `initial_state[${index}]: missing or invalid 'type' property` };
  }

  // state_key must be a string if provided (can be empty string)
  if (event.state_key !== undefined && typeof event.state_key !== 'string') {
    return { valid: false, error: `initial_state[${index}]: 'state_key' must be a string` };
  }

  // content must be an object
  if (!event.content || typeof event.content !== 'object' || Array.isArray(event.content)) {
    return { valid: false, error: `initial_state[${index}]: missing or invalid 'content' property` };
  }

  // Disallow certain event types that are created automatically
  const disallowedTypes = ['m.room.create', 'm.room.member', 'm.room.power_levels'];
  if (disallowedTypes.includes(event.type)) {
    return { valid: false, error: `initial_state[${index}]: '${event.type}' cannot be set via initial_state` };
  }

  // Validate m.room.encryption content
  if (event.type === 'm.room.encryption') {
    if (!event.content.algorithm || typeof event.content.algorithm !== 'string') {
      return { valid: false, error: `initial_state[${index}]: m.room.encryption requires 'algorithm'` };
    }
    // Only m.megolm.v1.aes-sha2 is widely supported
    const supportedAlgorithms = ['m.megolm.v1.aes-sha2'];
    if (!supportedAlgorithms.includes(event.content.algorithm)) {
      return { valid: false, error: `initial_state[${index}]: unsupported algorithm '${event.content.algorithm}'` };
    }
  }

  return { valid: true };
}

// Helper to create initial room events
// Returns the create event ID for use in initializing m.fully_read
async function createInitialRoomEvents(
  db: D1Database,
  serverName: string,
  roomId: string,
  roomVersion: string,
  creatorId: string,
  options: {
    name?: string;
    topic?: string;
    preset?: string;
    is_direct?: boolean;
    initial_state?: Array<{ type: string; state_key?: string; content: any }>;
    invite?: string[];
    room_alias_local_part?: string;
  }
): Promise<string> {
  const now = Date.now();
  let depth = 0;
  const authEvents: string[] = [];
  const prevEvents: string[] = [];

  // Helper to create and store an event
  async function createEvent(
    type: string,
    content: any,
    stateKey?: string
  ): Promise<string> {
    const eventId = await generateEventId(serverName);
    const event: PDU = {
      event_id: eventId,
      room_id: roomId,
      sender: creatorId,
      type,
      state_key: stateKey,
      content,
      origin_server_ts: now,
      depth: depth++,
      auth_events: [...authEvents],
      prev_events: [...prevEvents],
    };

    await storeEvent(db, event);

    // Update auth/prev events for next event
    if (stateKey !== undefined) {
      authEvents.push(eventId);
    }
    prevEvents.length = 0;
    prevEvents.push(eventId);

    return eventId;
  }

  // 1. m.room.create
  const createContent: RoomCreateContent = {
    creator: creatorId,
    room_version: roomVersion,
  };
  const createEventId = await createEvent('m.room.create', createContent, '');

  // 2. m.room.member (creator joins)
  const memberContent: RoomMemberContent = {
    membership: 'join',
  };
  const joinEventId = await createEvent('m.room.member', memberContent, creatorId);
  await updateMembership(db, roomId, creatorId, 'join', joinEventId);

  // 3. m.room.power_levels
  const preset = options.preset || 'private_chat';
  const powerLevelsContent = {
    ban: 50,
    events: {
      'm.room.avatar': 50,
      'm.room.canonical_alias': 50,
      'm.room.encryption': 100,
      'm.room.history_visibility': 100,
      'm.room.name': 50,
      'm.room.power_levels': 100,
      'm.room.server_acl': 100,
      'm.room.tombstone': 100,
    },
    events_default: 0,
    invite: preset === 'public_chat' ? 0 : 50,
    kick: 50,
    notifications: { room: 50 },
    redact: 50,
    state_default: 50,
    users: { [creatorId]: 100 },
    users_default: 0,
  };
  await createEvent('m.room.power_levels', powerLevelsContent, '');

  // 4. m.room.join_rules
  let joinRule = 'invite';
  if (preset === 'public_chat') joinRule = 'public';
  else if (preset === 'trusted_private_chat') joinRule = 'invite';
  await createEvent('m.room.join_rules', { join_rule: joinRule }, '');

  // 5. m.room.history_visibility
  let historyVisibility = 'shared';
  if (preset === 'public_chat') historyVisibility = 'shared';
  await createEvent('m.room.history_visibility', { history_visibility: historyVisibility }, '');

  // 6. m.room.guest_access
  let guestAccess = 'forbidden';
  if (preset === 'public_chat') guestAccess = 'can_join';
  await createEvent('m.room.guest_access', { guest_access: guestAccess }, '');

  // Optional: m.room.name
  if (options.name) {
    await createEvent('m.room.name', { name: options.name }, '');
  }

  // Optional: m.room.topic
  if (options.topic) {
    await createEvent('m.room.topic', { topic: options.topic }, '');
  }

  // Process initial_state
  if (options.initial_state) {
    for (const state of options.initial_state) {
      await createEvent(state.type, state.content, state.state_key ?? '');
    }
  }

  // Process invites with individual error handling (best-effort invites)
  // If one invite fails, we continue with the rest - the room is still valid
  if (options.invite) {
    const failedInvites: string[] = [];
    for (const invitee of options.invite) {
      try {
        const inviteContent: RoomMemberContent = {
          membership: 'invite',
          is_direct: options.is_direct,
        };
        const inviteEventId = await createEvent('m.room.member', inviteContent, invitee);
        await updateMembership(db, roomId, invitee, 'invite', inviteEventId);
      } catch (err) {
        console.error(`[createRoom] Failed to invite ${invitee}:`, err);
        failedInvites.push(invitee);
      }
    }
    if (failedInvites.length > 0) {
      console.warn(`[createRoom] Failed invites for room ${roomId}:`, failedInvites);
    }
  }

  // Return the create event ID for m.fully_read initialization
  return createEventId;
}

// POST /_matrix/client/v3/createRoom - Create a new room
app.post('/_matrix/client/v3/createRoom', requireAuth(), async (c) => {
  const userId = c.get('userId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const {
    room_alias_local_part,
    name,
    topic,
    invite,
    room_version,
    initial_state,
    preset,
    is_direct,
    visibility,
  } = body;
  // Note: invite_3pid and creation_content are reserved for future use
  void body.invite_3pid;
  void body.creation_content;

  // Validate room alias if provided
  if (room_alias_local_part) {
    const alias = formatRoomAlias(room_alias_local_part, c.env.SERVER_NAME);
    const existingRoom = await getRoomByAlias(c.env.DB, alias);
    if (existingRoom) {
      return Errors.roomInUse().toResponse();
    }
  }

  // Validate initial_state if provided
  if (initial_state !== undefined) {
    if (!Array.isArray(initial_state)) {
      return c.json({
        errcode: 'M_INVALID_PARAM',
        error: 'initial_state must be an array',
      }, 400);
    }

    // Check for duplicate encryption events
    const encryptionEvents = initial_state.filter((s: any) => s.type === 'm.room.encryption');
    if (encryptionEvents.length > 1) {
      return c.json({
        errcode: 'M_INVALID_PARAM',
        error: 'Cannot specify multiple m.room.encryption events in initial_state',
      }, 400);
    }

    // Validate each state event
    for (let i = 0; i < initial_state.length; i++) {
      const validation = validateStateEvent(initial_state[i], i);
      if (!validation.valid) {
        return c.json({
          errcode: 'M_INVALID_PARAM',
          error: validation.error,
        }, 400);
      }
    }
  }

  // Generate room ID
  const roomId = await generateRoomId(c.env.SERVER_NAME);
  const version = room_version || '10';

  console.log('[createRoom] Creating room:', roomId, 'for user:', userId);

  // Create room in database
  const isPublic = visibility === 'public';
  await createRoom(c.env.DB, roomId, version, userId, isPublic);
  console.log('[createRoom] Room record created in DB');

  // Create initial room events
  let createEventId: string | undefined;
  try {
    createEventId = await createInitialRoomEvents(c.env.DB, c.env.SERVER_NAME, roomId, version, userId, {
      name,
      topic,
      preset,
      is_direct,
      initial_state,
      invite,
      room_alias_local_part,
    });
    console.log('[createRoom] Initial room events created successfully');

    // Initialize m.fully_read marker for the room creator
    // This ensures the room doesn't show all messages as unread
    await c.env.DB.prepare(`
      INSERT INTO account_data (user_id, room_id, event_type, content)
      VALUES (?, ?, 'm.fully_read', ?)
      ON CONFLICT (user_id, room_id, event_type) DO UPDATE SET content = excluded.content
    `).bind(userId, roomId, JSON.stringify({ event_id: createEventId })).run();
    console.log('[createRoom] Initialized m.fully_read marker for creator');
  } catch (err) {
    console.error('[createRoom] Failed to create initial room events:', err);
    // Still return success since room was created, but log the error
    // In production, we should probably roll back or return an error
  }

  // Create room alias if provided
  if (room_alias_local_part) {
    const alias = formatRoomAlias(room_alias_local_part, c.env.SERVER_NAME);
    await createRoomAlias(c.env.DB, alias, roomId, userId);
  }

  // Notify the creator's sync that the room was created
  await notifyUsersOfEvent(c.env, roomId, roomId, 'm.room.create');

  return c.json({
    room_id: roomId,
    room_alias: room_alias_local_part
      ? formatRoomAlias(room_alias_local_part, c.env.SERVER_NAME)
      : undefined,
  });
});

// GET /_matrix/client/v3/joined_rooms - List joined rooms
app.get('/_matrix/client/v3/joined_rooms', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const rooms = await getUserRooms(c.env.DB, userId, 'join');
  return c.json({ joined_rooms: rooms });
});

// Helper to extract server name from room ID (!localpart:server)
function getServerFromRoomId(roomId: string): string | null {
  const match = roomId.match(/^!.+:(.+)$/);
  return match ? match[1] : null;
}

// POST /_matrix/client/v3/rooms/:roomId/join - Join a room
app.post('/_matrix/client/v3/rooms/:roomId/join', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  // Extract server from room ID to check if it's a remote room
  const roomServer = getServerFromRoomId(roomId);
  const isRemoteRoom = roomServer && roomServer !== c.env.SERVER_NAME;

  // Check if room exists locally
  const room = await getRoom(c.env.DB, roomId);

  // For remote rooms that don't exist locally, use the workflow for federation
  if (!room && isRemoteRoom && roomServer) {
    console.log('[rooms] Remote room join via workflow', { roomId, roomServer, userId });

    // Trigger the RoomJoinWorkflow for durable federation handling
    const instance = await c.env.ROOM_JOIN_WORKFLOW.create({
      params: {
        roomId,
        userId,
        isRemote: true,
        remoteServer: roomServer,
      },
    });

    // Wait for the workflow to complete (with timeout)
    // The workflow handles retries internally
    try {
      const status = await instance.status();
      console.log('[rooms] Workflow status', { roomId, status });

      // If workflow is still running, return accepted
      if (status.status === 'running' || status.status === 'queued') {
        // Return success - the join is in progress
        // Client will see the room appear in sync when complete
        return c.json({ room_id: roomId });
      }

      // Check if workflow completed successfully
      const output = status.output as JoinResult | undefined;
      if (status.status === 'complete' && output?.success) {
        return c.json({ room_id: roomId });
      }

      // Workflow failed
      console.error('[rooms] Workflow failed', { roomId, status });
      return Errors.unknown('Failed to join remote room').toResponse();
    } catch (err) {
      console.error('[rooms] Workflow error', { roomId, error: err });
      return Errors.unknown('Failed to join remote room').toResponse();
    }
  }

  // Local room handling (existing code)
  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check current membership
  const currentMembership = await getMembership(c.env.DB, roomId, userId);

  // Check join rules
  const joinRulesEvent = await getStateEvent(c.env.DB, roomId, 'm.room.join_rules');
  const joinRule = (joinRulesEvent?.content as any)?.join_rule || 'invite';

  // Determine if user can join
  let canJoin = false;
  if (joinRule === 'public') {
    canJoin = true;
  } else if (currentMembership?.membership === 'invite') {
    canJoin = true;
  } else if (currentMembership?.membership === 'join') {
    // Already joined
    return c.json({ room_id: roomId });
  }

  if (!canJoin) {
    return Errors.forbidden('Cannot join room').toResponse();
  }

  // Create join event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  // Get current state for auth events
  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (joinRulesEvent) authEvents.push(joinRulesEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (currentMembership) authEvents.push(currentMembership.eventId);

  // Get prev events (latest events in room)
  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'join',
  };

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);
  await updateMembership(c.env.DB, roomId, userId, 'join', eventId);

  // Notify room members about the join
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.room.member');

  return c.json({ room_id: roomId });
});

// POST /_matrix/client/v3/rooms/:roomId/leave - Leave a room
app.post('/_matrix/client/v3/rooms/:roomId/leave', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  // Check current membership
  const currentMembership = await getMembership(c.env.DB, roomId, userId);
  if (!currentMembership || currentMembership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Create leave event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (currentMembership) authEvents.push(currentMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'leave',
  };

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);
  await updateMembership(c.env.DB, roomId, userId, 'leave', eventId);

  // Notify room members about the leave
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.room.member');

  return c.json({});
});

// POST /_matrix/client/v3/rooms/:roomId/knock - Knock on a room (MSC2403)
app.post('/_matrix/client/v3/rooms/:roomId/knock', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  let body: { reason?: string };
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  // Check if room exists
  const room = await getRoom(db, roomId);
  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check current membership
  const currentMembership = await getMembership(db, roomId, userId);
  if (currentMembership?.membership === 'join') {
    return c.json({ room_id: roomId }); // Already joined
  }
  if (currentMembership?.membership === 'ban') {
    return Errors.forbidden('User is banned from this room').toResponse();
  }

  // Check join rules - knock only allowed if join_rule is 'knock' or 'knock_restricted'
  const joinRulesEvent = await getStateEvent(db, roomId, 'm.room.join_rules');
  const joinRule = (joinRulesEvent?.content as any)?.join_rule || 'invite';

  if (!['knock', 'knock_restricted'].includes(joinRule)) {
    return Errors.forbidden('Room does not allow knocking').toResponse();
  }

  // Create knock event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(db, roomId, 'm.room.create');
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (joinRulesEvent) authEvents.push(joinRulesEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (currentMembership) authEvents.push(currentMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(db, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'knock',
    reason: body.reason,
  };

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(db, event);
  await updateMembership(db, roomId, userId, 'knock', eventId);

  // Store in room_knocks table for easy querying
  await db.prepare(`
    INSERT OR REPLACE INTO room_knocks (room_id, user_id, reason, event_id, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(roomId, userId, body.reason || null, eventId, Date.now()).run();

  return c.json({ room_id: roomId });
});

// POST /_matrix/client/v3/knock/:roomIdOrAlias - Knock by ID or alias
app.post('/_matrix/client/v3/knock/:roomIdOrAlias', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomIdOrAlias = c.req.param('roomIdOrAlias');
  const db = c.env.DB;

  let body: { reason?: string; server_name?: string[] };
  try {
    body = await c.req.json();
  } catch {
    body = {};
  }

  let roomId = roomIdOrAlias;

  // If it's an alias, resolve it
  if (roomIdOrAlias.startsWith('#')) {
    const resolved = await getRoomByAlias(db, roomIdOrAlias);
    if (!resolved) {
      return Errors.notFound('Room alias not found').toResponse();
    }
    roomId = resolved;
  }

  // Check if room exists
  const room = await getRoom(db, roomId);
  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check join rules
  const joinRulesEvent = await getStateEvent(db, roomId, 'm.room.join_rules');
  const joinRule = (joinRulesEvent?.content as any)?.join_rule || 'invite';

  if (!['knock', 'knock_restricted'].includes(joinRule)) {
    return Errors.forbidden('Room does not allow knocking').toResponse();
  }

  // Check current membership
  const currentMembership = await getMembership(db, roomId, userId);
  if (currentMembership?.membership === 'join') {
    return c.json({ room_id: roomId });
  }
  if (currentMembership?.membership === 'ban') {
    return Errors.forbidden('User is banned from this room').toResponse();
  }

  // Create knock event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(db, roomId, 'm.room.create');
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (joinRulesEvent) authEvents.push(joinRulesEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (currentMembership) authEvents.push(currentMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(db, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'knock',
    reason: body.reason,
  };

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(db, event);
  await updateMembership(db, roomId, userId, 'knock', eventId);

  await db.prepare(`
    INSERT OR REPLACE INTO room_knocks (room_id, user_id, reason, event_id, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).bind(roomId, userId, body.reason || null, eventId, Date.now()).run();

  return c.json({ room_id: roomId });
});

// GET /_matrix/client/v3/rooms/:roomId/state - Get all current state
app.get('/_matrix/client/v3/rooms/:roomId/state', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const state = await getRoomState(c.env.DB, roomId);

  // Format events for client
  const clientEvents = state.map(e => ({
    type: e.type,
    state_key: e.state_key,
    content: e.content,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    event_id: e.event_id,
    room_id: e.room_id,
  }));

  return c.json(clientEvents);
});

// GET /_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey? - Get specific state
app.get('/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey?', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventType = c.req.param('eventType');
  const stateKey = c.req.param('stateKey') ?? '';

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const event = await getStateEvent(c.env.DB, roomId, eventType, stateKey);
  if (!event) {
    return Errors.notFound('State event not found').toResponse();
  }

  return c.json(event.content);
});

// PUT /_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey? - Set state
app.put('/_matrix/client/v3/rooms/:roomId/state/:eventType/:stateKey?', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventType = c.req.param('eventType');
  const stateKey = c.req.param('stateKey') ?? '';

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  let content: any;
  try {
    content = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate event content based on type
  const contentValidation = validateEventContent(eventType, content);
  if (!contentValidation.valid) {
    return c.json(
      { errcode: contentValidation.errcode || 'M_BAD_JSON', error: contentValidation.error },
      400
    );
  }

  // Check power level for state events
  if (eventType === 'm.room.power_levels') {
    // Special handling for power levels changes
    const powerCheck = await canModifyPowerLevels(
      c.env.DB,
      roomId,
      userId,
      content as RoomPowerLevelsContent
    );
    if (!powerCheck.allowed) {
      return Errors.forbidden(powerCheck.reason || 'Insufficient power level').toResponse();
    }
  } else {
    const powerCheck = await canSendStateEvent(c.env.DB, roomId, userId, eventType, stateKey);
    if (!powerCheck.allowed) {
      return Errors.forbidden(powerCheck.reason || 'Insufficient power level').toResponse();
    }
  }

  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (membership) authEvents.push(membership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: eventType,
    state_key: stateKey,
    content,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);

  // Invalidate room metadata cache if this is a metadata-affecting state event
  const CACHED_STATE_TYPES = ['m.room.name', 'm.room.avatar', 'm.room.topic', 'm.room.canonical_alias', 'm.room.member'];
  if (CACHED_STATE_TYPES.includes(eventType)) {
    // Non-blocking cache invalidation
    invalidateRoomCache(c.env.CACHE, roomId).catch(() => {});
  }

  // Update membership table if this is a membership event
  if (eventType === 'm.room.member') {
    await updateMembership(
      c.env.DB,
      roomId,
      stateKey,
      content.membership,
      eventId,
      content.displayname,
      content.avatar_url
    );
  }

  // Notify room members about the state change (wakes up long-polling syncs)
  await notifyUsersOfEvent(c.env, roomId, eventId, eventType);

  return c.json({ event_id: eventId });
});

// GET /_matrix/client/v3/rooms/:roomId/members - Get room members
app.get('/_matrix/client/v3/rooms/:roomId/members', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const members = await getRoomMembers(c.env.DB, roomId);

  // Get full member events - OPTIMIZED: fetch in parallel instead of sequential
  const events = await Promise.all(
    members.map(member =>
      getStateEvent(c.env.DB, roomId, 'm.room.member', member.userId)
    )
  );

  const memberEvents = events
    .filter((event): event is NonNullable<typeof event> => event !== null && event !== undefined)
    .map(event => ({
      type: event.type,
      state_key: event.state_key,
      content: event.content,
      sender: event.sender,
      origin_server_ts: event.origin_server_ts,
      event_id: event.event_id,
      room_id: event.room_id,
    }));

  return c.json({ chunk: memberEvents });
});

// GET /_matrix/client/v3/rooms/:roomId/messages - Get room messages
app.get('/_matrix/client/v3/rooms/:roomId/messages', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const from = c.req.query('from');
  const dir = (c.req.query('dir') || 'b') as 'f' | 'b';
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 100);

  // Parse token - handle both 's123' format (from sliding-sync) and plain '123' format
  let fromToken: number | undefined;
  if (from) {
    const tokenStr = from.startsWith('s') ? from.slice(1) : from;
    const parsed = parseInt(tokenStr);
    fromToken = isNaN(parsed) ? undefined : parsed;
  }
  const { events, end } = await getRoomEvents(c.env.DB, roomId, fromToken, limit, dir);

  // Filter events by history visibility
  const visibilityContext = await getVisibilityContext(c.env.DB, roomId, userId);
  const visibleEvents = filterEventsByVisibility(events, visibilityContext);

  // Format events for client
  const clientEvents = visibleEvents.map(e => ({
    type: e.type,
    state_key: e.state_key,
    content: e.content,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    event_id: e.event_id,
    room_id: e.room_id,
    unsigned: e.unsigned,
  }));

  // Build response - omit 'end' if no events returned (reached start/end of timeline)
  // This prevents infinite retry loops when client paginates past available events
  // Use 's' prefix for consistency with sliding-sync prev_batch tokens
  const response: { start: string; end?: string; chunk: typeof clientEvents } = {
    start: from || 's0',
    chunk: clientEvents,
  };

  // Only include 'end' if we have events to paginate from
  if (visibleEvents.length > 0) {
    response.end = `s${end}`;
  }

  return c.json(response);
});

// GET /_matrix/client/v3/rooms/:roomId/event/:eventId - Get specific event
app.get('/_matrix/client/v3/rooms/:roomId/event/:eventId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const event = await getEvent(c.env.DB, eventId);
  if (!event || event.room_id !== roomId) {
    return Errors.notFound('Event not found').toResponse();
  }

  return c.json({
    type: event.type,
    state_key: event.state_key,
    content: event.content,
    sender: event.sender,
    origin_server_ts: event.origin_server_ts,
    event_id: event.event_id,
    room_id: event.room_id,
    unsigned: event.unsigned,
  });
});

// PUT /_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId - Send message
app.put('/_matrix/client/v3/rooms/:roomId/send/:eventType/:txnId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventType = c.req.param('eventType');
  const txnId = c.req.param('txnId');

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  let content: any;
  try {
    content = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  // Validate event content based on type
  const contentValidation = validateEventContent(eventType, content);
  if (!contentValidation.valid) {
    return c.json(
      { errcode: contentValidation.errcode || 'M_BAD_JSON', error: contentValidation.error },
      400
    );
  }

  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (membership) authEvents.push(membership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: eventType,
    content,
    origin_server_ts: Date.now(),
    unsigned: { transaction_id: txnId },
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);

  // Notify all room members that a new message was sent (wakes up long-polling syncs)
  await notifyUsersOfEvent(c.env, roomId, eventId, eventType);

  // Send push notifications via durable workflow (fire and forget)
  // Only for message and encrypted event types
  if (eventType === 'm.room.message' || eventType === 'm.room.encrypted') {
    c.executionCtx.waitUntil(
      c.env.PUSH_NOTIFICATION_WORKFLOW.create({
        params: {
          eventId,
          roomId,
          eventType,
          sender: userId,
          content,
          originServerTs: event.origin_server_ts,
        },
      }).catch(err => {
        console.error('[rooms] Push notification workflow error:', err);
      })
    );
  }

  return c.json({ event_id: eventId });
});

// POST /_matrix/client/v3/rooms/:roomId/invite - Invite a user
app.post('/_matrix/client/v3/rooms/:roomId/invite', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { user_id: inviteeId } = body;
  if (!inviteeId) {
    return Errors.missingParam('user_id').toResponse();
  }

  // Check inviter membership
  const inviterMembership = await getMembership(c.env.DB, roomId, userId);
  if (!inviterMembership || inviterMembership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check power levels
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');
  const powerLevels = powerLevelsEvent?.content as any || {};
  const userPower = powerLevels.users?.[userId] ?? powerLevels.users_default ?? 0;
  const invitePower = powerLevels.invite ?? 50;

  if (userPower < invitePower) {
    return Errors.forbidden('Insufficient power level to invite').toResponse();
  }

  // Check if already invited or joined
  const inviteeMembership = await getMembership(c.env.DB, roomId, inviteeId);
  if (inviteeMembership?.membership === 'join') {
    return Errors.forbidden('User is already in the room').toResponse();
  }
  if (inviteeMembership?.membership === 'invite') {
    return c.json({}); // Already invited, idempotent
  }

  // Create invite event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (inviterMembership) authEvents.push(inviterMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'invite',
  };

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: inviteeId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);
  await updateMembership(c.env.DB, roomId, inviteeId, 'invite', eventId);

  // Notify room members and the invitee about the invite
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.room.member');

  return c.json({});
});

// POST /_matrix/client/v3/rooms/:roomId/kick - Kick a user
app.post('/_matrix/client/v3/rooms/:roomId/kick', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { user_id: targetId, reason } = body;
  if (!targetId) {
    return Errors.missingParam('user_id').toResponse();
  }

  // Check kicker membership
  const kickerMembership = await getMembership(c.env.DB, roomId, userId);
  if (!kickerMembership || kickerMembership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check target membership
  const targetMembership = await getMembership(c.env.DB, roomId, targetId);
  if (!targetMembership || targetMembership.membership !== 'join') {
    return Errors.forbidden('User is not in the room').toResponse();
  }

  // Check power levels
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');
  const powerLevels = powerLevelsEvent?.content as any || {};
  const userPower = powerLevels.users?.[userId] ?? powerLevels.users_default ?? 0;
  const targetPower = powerLevels.users?.[targetId] ?? powerLevels.users_default ?? 0;
  const kickPower = powerLevels.kick ?? 50;

  if (userPower < kickPower || userPower <= targetPower) {
    return Errors.forbidden('Insufficient power level to kick').toResponse();
  }

  // Create leave event for target
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (kickerMembership) authEvents.push(kickerMembership.eventId);
  if (targetMembership) authEvents.push(targetMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'leave',
    reason,
  };

  // Validate membership content
  const contentValidation = validateEventContent('m.room.member', memberContent);
  if (!contentValidation.valid) {
    return c.json(
      { errcode: contentValidation.errcode || 'M_BAD_JSON', error: contentValidation.error },
      400
    );
  }

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: targetId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);
  await updateMembership(c.env.DB, roomId, targetId, 'leave', eventId);

  // Notify room members about the kick
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.room.member');

  return c.json({});
});

// POST /_matrix/client/v3/rooms/:roomId/ban - Ban a user
app.post('/_matrix/client/v3/rooms/:roomId/ban', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { user_id: targetId, reason } = body;
  if (!targetId) {
    return Errors.missingParam('user_id').toResponse();
  }

  // Check banner membership
  const bannerMembership = await getMembership(c.env.DB, roomId, userId);
  if (!bannerMembership || bannerMembership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check power levels
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');
  const powerLevels = powerLevelsEvent?.content as any || {};
  const userPower = powerLevels.users?.[userId] ?? powerLevels.users_default ?? 0;
  const targetPower = powerLevels.users?.[targetId] ?? powerLevels.users_default ?? 0;
  const banPower = powerLevels.ban ?? 50;

  if (userPower < banPower || userPower <= targetPower) {
    return Errors.forbidden('Insufficient power level to ban').toResponse();
  }

  // Create ban event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');
  const targetMembership = await getMembership(c.env.DB, roomId, targetId);

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (bannerMembership) authEvents.push(bannerMembership.eventId);
  if (targetMembership) authEvents.push(targetMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'ban',
    reason,
  };

  // Validate membership content
  const contentValidation = validateEventContent('m.room.member', memberContent);
  if (!contentValidation.valid) {
    return c.json(
      { errcode: contentValidation.errcode || 'M_BAD_JSON', error: contentValidation.error },
      400
    );
  }

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: targetId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);
  await updateMembership(c.env.DB, roomId, targetId, 'ban', eventId);

  // Notify room members about the ban
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.room.member');

  return c.json({});
});

// POST /_matrix/client/v3/rooms/:roomId/unban - Unban a user
app.post('/_matrix/client/v3/rooms/:roomId/unban', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { user_id: targetId, reason } = body;
  if (!targetId) {
    return Errors.missingParam('user_id').toResponse();
  }

  // Check unbanner membership
  const unbannerMembership = await getMembership(c.env.DB, roomId, userId);
  if (!unbannerMembership || unbannerMembership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check target is actually banned
  const targetMembership = await getMembership(c.env.DB, roomId, targetId);
  if (!targetMembership || targetMembership.membership !== 'ban') {
    return Errors.forbidden('User is not banned').toResponse();
  }

  // Check power levels
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');
  const powerLevels = powerLevelsEvent?.content as any || {};
  const userPower = powerLevels.users?.[userId] ?? powerLevels.users_default ?? 0;
  const banPower = powerLevels.ban ?? 50;

  if (userPower < banPower) {
    return Errors.forbidden('Insufficient power level to unban').toResponse();
  }

  // Create leave event (unban sets membership to leave)
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (unbannerMembership) authEvents.push(unbannerMembership.eventId);
  if (targetMembership) authEvents.push(targetMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'leave',
    reason,
  };

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: targetId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);
  await updateMembership(c.env.DB, roomId, targetId, 'leave', eventId);

  // Notify room members about the unban
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.room.member');

  return c.json({});
});

// POST /_matrix/client/v3/rooms/:roomId/forget - Forget a room
app.post('/_matrix/client/v3/rooms/:roomId/forget', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  // Check that user has left the room
  const membership = await getMembership(db, roomId, userId);
  if (membership && membership.membership === 'join') {
    return Errors.forbidden('Cannot forget room while still a member').toResponse();
  }

  // Remove membership record entirely
  await db.prepare(`
    DELETE FROM room_memberships WHERE room_id = ? AND user_id = ?
  `).bind(roomId, userId).run();

  return c.json({});
});

// PUT /_matrix/client/v3/rooms/:roomId/redact/:eventId/:txnId - Redact an event
app.put('/_matrix/client/v3/rooms/:roomId/redact/:eventId/:txnId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const targetEventId = c.req.param('eventId');
  const txnId = c.req.param('txnId');

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Get the target event
  const targetEvent = await getEvent(c.env.DB, targetEventId);
  if (!targetEvent || targetEvent.room_id !== roomId) {
    return Errors.notFound('Event not found').toResponse();
  }

  // Check power levels for redaction
  const powerLevelsEvent = await getStateEvent(c.env.DB, roomId, 'm.room.power_levels');
  const powerLevels = powerLevelsEvent?.content as any || {};
  const userPower = powerLevels.users?.[userId] ?? powerLevels.users_default ?? 0;
  const redactPower = powerLevels.redact ?? 50;

  // Users can redact their own messages, or need redact power level
  if (targetEvent.sender !== userId && userPower < redactPower) {
    return Errors.forbidden('Insufficient power level to redact').toResponse();
  }

  let body: any = {};
  try {
    body = await c.req.json();
  } catch {
    // Body is optional for redaction
  }

  // Create redaction event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(c.env.DB, roomId, 'm.room.create');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (membership) authEvents.push(membership.eventId);

  const { events: latestEvents } = await getRoomEvents(c.env.DB, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const redactionContent: any = {
    redacts: targetEventId,
  };
  if (body.reason) {
    redactionContent.reason = body.reason;
  }

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.redaction',
    content: redactionContent,
    redacts: targetEventId,
    origin_server_ts: Date.now(),
    unsigned: { transaction_id: txnId },
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(c.env.DB, event);

  // Mark the original event as redacted
  await c.env.DB.prepare(`
    UPDATE events SET redacted_because = ? WHERE event_id = ?
  `).bind(eventId, targetEventId).run();

  // Notify room members about the redaction
  await notifyUsersOfEvent(c.env, roomId, eventId, 'm.room.redaction');

  return c.json({ event_id: eventId });
});

// GET /_matrix/client/v3/rooms/:roomId/context/:eventId - Get context around an event
// NOTE: This endpoint is used by Element X NSE (Notification Service Extension) to fetch
// event content for rich push notifications. If you see this endpoint being called
// shortly after a push notification is sent, that's the NSE working correctly.
app.get('/_matrix/client/v3/rooms/:roomId/context/:eventId', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const eventId = c.req.param('eventId');
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 100);
  const userAgent = c.req.header('User-Agent');

  // NSE Detection logging - /context is a key endpoint for push notification content
  // NSE typically requests small limit (1-5) for single event context
  const isLikelyNSE = limit <= 5;
  console.log('[rooms/context] Request:', {
    userId,
    roomId,
    eventId,
    limit,
    userAgent: userAgent?.substring(0, 100),
    isLikelyNSE,
    timestamp: new Date().toISOString(),
  });

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    console.log('[rooms/context] DENIED - not a member:', { userId, roomId, eventId });
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Get the target event
  const targetEvent = await getEvent(c.env.DB, eventId);
  if (!targetEvent || targetEvent.room_id !== roomId) {
    console.log('[rooms/context] Event not found:', { eventId, roomId, eventRoomId: targetEvent?.room_id });
    return Errors.notFound('Event not found').toResponse();
  }

  console.log('[rooms/context] Found event:', {
    eventId,
    eventType: targetEvent.type,
    sender: targetEvent.sender,
    timestamp: targetEvent.origin_server_ts,
  });

  // Get events before and after (including redacted_because for content stripping)
  const halfLimit = Math.floor(limit / 2);

  const eventsBefore = await c.env.DB.prepare(`
    SELECT event_id, room_id, sender, event_type, state_key, content,
           origin_server_ts, unsigned, depth, auth_events, prev_events, redacted_because
    FROM events WHERE room_id = ? AND origin_server_ts < ?
    ORDER BY origin_server_ts DESC LIMIT ?
  `).bind(roomId, targetEvent.origin_server_ts, halfLimit).all<{
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

  const eventsAfter = await c.env.DB.prepare(`
    SELECT event_id, room_id, sender, event_type, state_key, content,
           origin_server_ts, unsigned, depth, auth_events, prev_events, redacted_because
    FROM events WHERE room_id = ? AND origin_server_ts > ?
    ORDER BY origin_server_ts ASC LIMIT ?
  `).bind(roomId, targetEvent.origin_server_ts, halfLimit).all<{
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
  const buildEventsWithRedaction = (results: typeof eventsBefore.results) =>
    results.map(e => ({
      event: {
        event_id: e.event_id,
        room_id: e.room_id,
        sender: e.sender,
        type: e.event_type,
        state_key: e.state_key ?? undefined,
        content: JSON.parse(e.content || '{}'),
        origin_server_ts: e.origin_server_ts,
        unsigned: e.unsigned ? JSON.parse(e.unsigned) : undefined,
        depth: e.depth,
        auth_events: JSON.parse(e.auth_events || '[]'),
        prev_events: JSON.parse(e.prev_events || '[]'),
      } as PDU,
      redactedBecause: e.redacted_because,
    }));

  // Apply redactions
  const processedEventsBefore = await applyRedactionsToEvents(
    buildEventsWithRedaction(eventsBefore.results),
    (id) => getEventRaw(c.env.DB, id)
  );
  const processedEventsAfter = await applyRedactionsToEvents(
    buildEventsWithRedaction(eventsAfter.results),
    (id) => getEventRaw(c.env.DB, id)
  );

  // Filter by history visibility
  const visibilityContext = await getVisibilityContext(c.env.DB, roomId, userId);
  const visibleEventsBefore = filterEventsByVisibility(processedEventsBefore, visibilityContext);
  const visibleEventsAfter = filterEventsByVisibility(processedEventsAfter, visibilityContext);

  // Format events for client response
  const formatEvent = (e: PDU) => ({
    type: e.type,
    state_key: e.state_key,
    content: e.content,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    event_id: e.event_id,
    room_id: e.room_id,
    unsigned: e.unsigned,
  });

  // Get current state (already handles redaction via getRoomState)
  const state = await getRoomState(c.env.DB, roomId);
  const stateEvents = state.map(e => ({
    type: e.type,
    state_key: e.state_key,
    content: e.content,
    sender: e.sender,
    origin_server_ts: e.origin_server_ts,
    event_id: e.event_id,
    room_id: e.room_id,
    unsigned: e.unsigned,
  }));

  return c.json({
    event: formatEvent(targetEvent),
    events_before: visibleEventsBefore.reverse().map(formatEvent),
    events_after: visibleEventsAfter.map(formatEvent),
    state: stateEvents,
    start: eventsBefore.results.length > 0 ? String(eventsBefore.results[0].origin_server_ts) : undefined,
    end: eventsAfter.results.length > 0 ? String(eventsAfter.results[eventsAfter.results.length - 1].origin_server_ts) : undefined,
  });
});

// GET /_matrix/client/v3/rooms/:roomId/joined_members - Get joined members with details
app.get('/_matrix/client/v3/rooms/:roomId/joined_members', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');

  // Check membership
  const membership = await getMembership(c.env.DB, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const members = await c.env.DB.prepare(`
    SELECT user_id, display_name, avatar_url
    FROM room_memberships
    WHERE room_id = ? AND membership = 'join'
  `).bind(roomId).all<{
    user_id: string;
    display_name: string | null;
    avatar_url: string | null;
  }>();

  const joined: Record<string, { display_name?: string; avatar_url?: string }> = {};
  for (const member of members.results) {
    joined[member.user_id] = {
      display_name: member.display_name || undefined,
      avatar_url: member.avatar_url || undefined,
    };
  }

  return c.json({ joined });
});

// GET /_matrix/client/v3/rooms/:roomId/aliases - Get room aliases
app.get('/_matrix/client/v3/rooms/:roomId/aliases', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  // Check membership
  const membership = await getMembership(db, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  const aliases = await db.prepare(`
    SELECT alias FROM room_aliases WHERE room_id = ?
  `).bind(roomId).all<{ alias: string }>();

  return c.json({
    aliases: aliases.results.map(a => a.alias),
  });
});

// POST /_matrix/client/v3/join/:roomIdOrAlias - Join room by ID or alias
app.post('/_matrix/client/v3/join/:roomIdOrAlias', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomIdOrAlias = decodeURIComponent(c.req.param('roomIdOrAlias'));
  const db = c.env.DB;

  let roomId: string;

  // Determine if it's an alias or room ID
  if (roomIdOrAlias.startsWith('#')) {
    // It's an alias, resolve it
    const resolved = await getRoomByAlias(db, roomIdOrAlias);
    if (!resolved) {
      return Errors.notFound('Room alias not found').toResponse();
    }
    roomId = resolved;
  } else {
    roomId = roomIdOrAlias;
  }

  // Check if room exists
  const room = await getRoom(db, roomId);
  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check current membership
  const currentMembership = await getMembership(db, roomId, userId);

  // Check join rules
  const joinRulesEvent = await getStateEvent(db, roomId, 'm.room.join_rules');
  const joinRule = (joinRulesEvent?.content as any)?.join_rule || 'invite';

  // Determine if user can join
  let canJoin = false;
  if (joinRule === 'public') {
    canJoin = true;
  } else if (currentMembership?.membership === 'invite') {
    canJoin = true;
  } else if (currentMembership?.membership === 'join') {
    return c.json({ room_id: roomId });
  }

  if (!canJoin) {
    return Errors.forbidden('Cannot join room').toResponse();
  }

  // Create join event
  const eventId = await generateEventId(c.env.SERVER_NAME);

  const createEvent = await getStateEvent(db, roomId, 'm.room.create');
  const powerLevelsEvent = await getStateEvent(db, roomId, 'm.room.power_levels');

  const authEvents: string[] = [];
  if (createEvent) authEvents.push(createEvent.event_id);
  if (joinRulesEvent) authEvents.push(joinRulesEvent.event_id);
  if (powerLevelsEvent) authEvents.push(powerLevelsEvent.event_id);
  if (currentMembership) authEvents.push(currentMembership.eventId);

  const { events: latestEvents } = await getRoomEvents(db, roomId, undefined, 1);
  const prevEvents = latestEvents.map(e => e.event_id);

  const memberContent: RoomMemberContent = {
    membership: 'join',
  };

  const event: PDU = {
    event_id: eventId,
    room_id: roomId,
    sender: userId,
    type: 'm.room.member',
    state_key: userId,
    content: memberContent,
    origin_server_ts: Date.now(),
    depth: (latestEvents[0]?.depth ?? 0) + 1,
    auth_events: authEvents,
    prev_events: prevEvents,
  };

  await storeEvent(db, event);
  await updateMembership(db, roomId, userId, 'join', eventId);

  return c.json({ room_id: roomId });
});

// Room alias endpoints
// GET /_matrix/client/v3/directory/room/:roomAlias
app.get('/_matrix/client/v3/directory/room/:roomAlias', async (c) => {
  const alias = decodeURIComponent(c.req.param('roomAlias'));

  const roomId = await getRoomByAlias(c.env.DB, alias);
  if (!roomId) {
    return Errors.notFound('Room alias not found').toResponse();
  }

  return c.json({
    room_id: roomId,
    servers: [c.env.SERVER_NAME],
  });
});

// PUT /_matrix/client/v3/directory/room/:roomAlias
app.put('/_matrix/client/v3/directory/room/:roomAlias', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const alias = decodeURIComponent(c.req.param('roomAlias'));

  let body: any;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const { room_id } = body;
  if (!room_id) {
    return Errors.missingParam('room_id').toResponse();
  }

  // Check if alias already exists
  const existing = await getRoomByAlias(c.env.DB, alias);
  if (existing) {
    return Errors.roomInUse().toResponse();
  }

  // Check if user has permission (is member of room)
  const membership = await getMembership(c.env.DB, room_id, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  await createRoomAlias(c.env.DB, alias, room_id, userId);
  return c.json({});
});

// DELETE /_matrix/client/v3/directory/room/:roomAlias
app.delete('/_matrix/client/v3/directory/room/:roomAlias', requireAuth(), async (c) => {
  // Note: userId could be used for permission checks in future
  void c.get('userId');
  const alias = decodeURIComponent(c.req.param('roomAlias'));

  const roomId = await getRoomByAlias(c.env.DB, alias);
  if (!roomId) {
    return Errors.notFound('Room alias not found').toResponse();
  }

  await deleteRoomAlias(c.env.DB, alias);
  return c.json({});
});

// ============================================
// Room Summary (MSC3266)
// ============================================

// GET /_matrix/client/v1/room_summary/:roomIdOrAlias - Get a summary of a room
// Allows previewing a room without joining it (if permitted by room settings)
app.get('/_matrix/client/v1/room_summary/:roomIdOrAlias', async (c) => {
  const roomIdOrAlias = decodeURIComponent(c.req.param('roomIdOrAlias'));
  const db = c.env.DB;

  let roomId = roomIdOrAlias;

  // Resolve alias to room_id if needed
  if (roomIdOrAlias.startsWith('#')) {
    const aliasResult = await db.prepare(
      `SELECT room_id FROM room_aliases WHERE alias = ?`
    ).bind(roomIdOrAlias).first<{ room_id: string }>();
    if (!aliasResult) {
      return Errors.notFound('Room alias not found').toResponse();
    }
    roomId = aliasResult.room_id;
  }

  // Get room info
  const room = await db.prepare(
    `SELECT room_id, room_version, is_public FROM rooms WHERE room_id = ?`
  ).bind(roomId).first<{ room_id: string; room_version: string; is_public: number }>();

  if (!room) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Get room state events we need
  const stateEvents = await db.prepare(`
    SELECT e.event_type, e.content FROM room_state rs
    JOIN events e ON rs.event_id = e.event_id
    WHERE rs.room_id = ? AND rs.event_type IN (
      'm.room.name', 'm.room.topic', 'm.room.avatar',
      'm.room.join_rules', 'm.room.canonical_alias', 'm.room.encryption',
      'm.room.history_visibility', 'm.room.guest_access'
    )
  `).bind(roomId).all<{ event_type: string; content: string }>();

  // Get member count
  const memberCount = await db.prepare(
    `SELECT COUNT(*) as count FROM room_memberships WHERE room_id = ? AND membership = 'join'`
  ).bind(roomId).first<{ count: number }>();

  // Build response
  const response: Record<string, unknown> = {
    room_id: roomId,
    num_joined_members: memberCount?.count || 0,
    room_version: room.room_version,
  };

  // Extract state
  let joinRule = 'invite';
  let historyVisibility = 'shared';
  let worldReadable = false;
  let guestCanJoin = false;

  for (const event of stateEvents.results || []) {
    const content = JSON.parse(event.content);
    switch (event.event_type) {
      case 'm.room.name':
        response.name = content.name;
        break;
      case 'm.room.topic':
        response.topic = content.topic;
        break;
      case 'm.room.avatar':
        response.avatar_url = content.url;
        break;
      case 'm.room.join_rules':
        joinRule = content.join_rule;
        response.join_rule = joinRule;
        break;
      case 'm.room.canonical_alias':
        response.canonical_alias = content.alias;
        break;
      case 'm.room.encryption':
        response.encryption = content.algorithm;
        break;
      case 'm.room.history_visibility':
        historyVisibility = content.history_visibility;
        worldReadable = historyVisibility === 'world_readable';
        break;
      case 'm.room.guest_access':
        guestCanJoin = content.guest_access === 'can_join';
        break;
    }
  }

  response.world_readable = worldReadable;
  response.guest_can_join = guestCanJoin;

  // Check user membership if authenticated (optional auth)
  const authHeader = c.req.header('Authorization');
  if (authHeader?.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    const { hashToken } = await import('../utils/crypto');
    const tokenHash = await hashToken(token);
    const tokenResult = await db.prepare(
      `SELECT user_id FROM access_tokens WHERE token_hash = ?`
    ).bind(tokenHash).first<{ user_id: string }>();

    if (tokenResult) {
      const membership = await db.prepare(
        `SELECT membership FROM room_memberships WHERE room_id = ? AND user_id = ?`
      ).bind(roomId, tokenResult.user_id).first<{ membership: string }>();
      response.membership = membership?.membership || 'leave';
    }
  }

  // Check if room summary is allowed based on join rules
  // For non-public rooms, only show summary if user is a member or if world_readable
  if (!room.is_public && !worldReadable && !response.membership) {
    // Don't reveal room existence for private rooms to non-members
    if (!['public', 'knock', 'knock_restricted'].includes(joinRule)) {
      return Errors.notFound('Room not found').toResponse();
    }
  }

  return c.json(response);
});

// ============================================
// Timestamp to Event (MSC3030)
// ============================================

// GET /_matrix/client/v3/rooms/:roomId/timestamp_to_event
// Finds the closest event to a given timestamp
app.get('/_matrix/client/v3/rooms/:roomId/timestamp_to_event', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const roomId = c.req.param('roomId');
  const db = c.env.DB;

  // Parse required parameters
  const tsParam = c.req.query('ts');
  const dirParam = c.req.query('dir');

  if (!tsParam) {
    return Errors.missingParam('ts').toResponse();
  }
  if (!dirParam) {
    return Errors.missingParam('dir').toResponse();
  }

  const ts = parseInt(tsParam, 10);
  if (isNaN(ts)) {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: 'ts must be a valid integer timestamp in milliseconds',
    }, 400);
  }

  if (dirParam !== 'f' && dirParam !== 'b') {
    return c.json({
      errcode: 'M_INVALID_PARAM',
      error: "dir must be 'f' (forward) or 'b' (backward)",
    }, 400);
  }

  // Check membership - user must be joined to the room
  const membership = await getMembership(db, roomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Query for the closest event
  let event: { event_id: string; origin_server_ts: number } | null = null;

  if (dirParam === 'f') {
    // Forward: find the closest event at or after the timestamp
    event = await db.prepare(`
      SELECT event_id, origin_server_ts
      FROM events
      WHERE room_id = ? AND origin_server_ts >= ?
      ORDER BY origin_server_ts ASC
      LIMIT 1
    `).bind(roomId, ts).first<{ event_id: string; origin_server_ts: number }>();
  } else {
    // Backward: find the closest event at or before the timestamp
    event = await db.prepare(`
      SELECT event_id, origin_server_ts
      FROM events
      WHERE room_id = ? AND origin_server_ts <= ?
      ORDER BY origin_server_ts DESC
      LIMIT 1
    `).bind(roomId, ts).first<{ event_id: string; origin_server_ts: number }>();
  }

  if (!event) {
    return Errors.notFound('No event found for the given timestamp').toResponse();
  }

  return c.json({
    event_id: event.event_id,
    origin_server_ts: event.origin_server_ts,
  });
});

// ============================================
// Room Upgrade
// ============================================

// Supported room versions
const SUPPORTED_ROOM_VERSIONS = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11', '12'];

// POST /_matrix/client/v3/rooms/:roomId/upgrade - Upgrade a room to a new version
app.post('/_matrix/client/v3/rooms/:roomId/upgrade', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const oldRoomId = c.req.param('roomId');
  const db = c.env.DB;
  const serverName = c.env.SERVER_NAME;

  let body: { new_version: string };
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  if (!body.new_version) {
    return Errors.missingParam('new_version').toResponse();
  }

  // Validate room version
  if (!SUPPORTED_ROOM_VERSIONS.includes(body.new_version)) {
    return c.json({
      errcode: 'M_UNSUPPORTED_ROOM_VERSION',
      error: `Room version ${body.new_version} is not supported`,
    }, 400);
  }

  // Check if old room exists
  const oldRoom = await getRoom(db, oldRoomId);
  if (!oldRoom) {
    return Errors.notFound('Room not found').toResponse();
  }

  // Check user is a member
  const membership = await getMembership(db, oldRoomId, userId);
  if (!membership || membership.membership !== 'join') {
    return Errors.forbidden('Not a member of this room').toResponse();
  }

  // Check user has permission to send m.room.tombstone events
  // User needs power level >= events['m.room.tombstone'] (default 100 for state events)
  const powerLevelsEvent = await getStateEvent(db, oldRoomId, 'm.room.power_levels', '');
  const powerLevels = powerLevelsEvent ? JSON.parse(typeof powerLevelsEvent.content === 'string' ? powerLevelsEvent.content : JSON.stringify(powerLevelsEvent.content)) : null;

  const userPowerLevel = powerLevels?.users?.[userId] ?? powerLevels?.users_default ?? 0;
  const tombstonePowerLevel = powerLevels?.events?.['m.room.tombstone'] ?? powerLevels?.state_default ?? 50;

  if (userPowerLevel < tombstonePowerLevel) {
    return Errors.forbidden('Insufficient power level to upgrade room').toResponse();
  }

  // Get current room state to copy to new room
  const currentState = await getRoomState(db, oldRoomId);
  const now = Date.now();

  // Generate new room ID
  const newRoomId = await generateRoomId(serverName);

  // Get the last event ID from old room for predecessor
  const lastEvent = await db.prepare(`
    SELECT event_id FROM events WHERE room_id = ? ORDER BY depth DESC LIMIT 1
  `).bind(oldRoomId).first<{ event_id: string }>();

  // Create the new room
  await createRoom(db, newRoomId, body.new_version, userId, false);

  let depth = 0;
  const authEvents: string[] = [];
  const prevEvents: string[] = [];

  // Helper to create events in new room
  async function createNewRoomEvent(type: string, content: any, stateKey?: string): Promise<string> {
    const eventId = await generateEventId(serverName);
    const event: PDU = {
      event_id: eventId,
      room_id: newRoomId,
      sender: userId,
      type,
      state_key: stateKey,
      content,
      origin_server_ts: now + depth,
      depth: depth++,
      auth_events: [...authEvents],
      prev_events: [...prevEvents],
    };

    await storeEvent(db, event);

    if (stateKey !== undefined) {
      authEvents.push(eventId);
    }
    prevEvents.length = 0;
    prevEvents.push(eventId);

    return eventId;
  }

  // 1. Create m.room.create with predecessor
  const createContent: RoomCreateContent = {
    creator: userId,
    room_version: body.new_version,
    predecessor: {
      room_id: oldRoomId,
      event_id: lastEvent?.event_id || '',
    },
  };
  await createNewRoomEvent('m.room.create', createContent, '');

  // 2. Creator joins
  const joinEventId = await createNewRoomEvent('m.room.member', { membership: 'join' }, userId);
  await updateMembership(db, newRoomId, userId, 'join', joinEventId);

  // 3. Copy power levels (with adjustments)
  if (powerLevels) {
    await createNewRoomEvent('m.room.power_levels', powerLevels, '');
  } else {
    // Default power levels
    await createNewRoomEvent('m.room.power_levels', {
      users: { [userId]: 100 },
      users_default: 0,
      events_default: 0,
      state_default: 50,
      ban: 50,
      kick: 50,
      redact: 50,
      invite: 0,
    }, '');
  }

  // 4. Copy join rules
  const joinRulesEvent = currentState.find(e => e.type === 'm.room.join_rules');
  if (joinRulesEvent) {
    const content = typeof joinRulesEvent.content === 'string'
      ? JSON.parse(joinRulesEvent.content)
      : joinRulesEvent.content;
    await createNewRoomEvent('m.room.join_rules', content, '');
  } else {
    await createNewRoomEvent('m.room.join_rules', { join_rule: 'invite' }, '');
  }

  // 5. Copy history visibility
  const historyEvent = currentState.find(e => e.type === 'm.room.history_visibility');
  if (historyEvent) {
    const content = typeof historyEvent.content === 'string'
      ? JSON.parse(historyEvent.content)
      : historyEvent.content;
    await createNewRoomEvent('m.room.history_visibility', content, '');
  } else {
    await createNewRoomEvent('m.room.history_visibility', { history_visibility: 'shared' }, '');
  }

  // 6. Copy room name
  const nameEvent = currentState.find(e => e.type === 'm.room.name');
  if (nameEvent) {
    const content = typeof nameEvent.content === 'string'
      ? JSON.parse(nameEvent.content)
      : nameEvent.content;
    await createNewRoomEvent('m.room.name', content, '');
  }

  // 7. Copy room topic
  const topicEvent = currentState.find(e => e.type === 'm.room.topic');
  if (topicEvent) {
    const content = typeof topicEvent.content === 'string'
      ? JSON.parse(topicEvent.content)
      : topicEvent.content;
    await createNewRoomEvent('m.room.topic', content, '');
  }

  // 8. Copy room avatar
  const avatarEvent = currentState.find(e => e.type === 'm.room.avatar');
  if (avatarEvent) {
    const content = typeof avatarEvent.content === 'string'
      ? JSON.parse(avatarEvent.content)
      : avatarEvent.content;
    await createNewRoomEvent('m.room.avatar', content, '');
  }

  // 9. Copy encryption settings
  const encryptionEvent = currentState.find(e => e.type === 'm.room.encryption');
  if (encryptionEvent) {
    const content = typeof encryptionEvent.content === 'string'
      ? JSON.parse(encryptionEvent.content)
      : encryptionEvent.content;
    await createNewRoomEvent('m.room.encryption', content, '');
  }

  // 10. Copy guest access
  const guestAccessEvent = currentState.find(e => e.type === 'm.room.guest_access');
  if (guestAccessEvent) {
    const content = typeof guestAccessEvent.content === 'string'
      ? JSON.parse(guestAccessEvent.content)
      : guestAccessEvent.content;
    await createNewRoomEvent('m.room.guest_access', content, '');
  }

  // Now send tombstone to old room
  const oldRoomState = await getRoomState(db, oldRoomId);
  const oldPrevEvent = await db.prepare(`
    SELECT event_id, depth FROM events WHERE room_id = ? ORDER BY depth DESC LIMIT 1
  `).bind(oldRoomId).first<{ event_id: string; depth: number }>();

  const oldAuthEvents = oldRoomState
    .filter(e => ['m.room.create', 'm.room.power_levels', 'm.room.member'].includes(e.type))
    .filter(e => e.state_key === '' || e.state_key === userId)
    .map(e => e.event_id);

  const tombstoneEventId = await generateEventId(serverName);
  const tombstoneEvent: PDU = {
    event_id: tombstoneEventId,
    room_id: oldRoomId,
    sender: userId,
    type: 'm.room.tombstone',
    state_key: '',
    content: {
      body: 'This room has been replaced',
      replacement_room: newRoomId,
    },
    origin_server_ts: now,
    depth: (oldPrevEvent?.depth || 0) + 1,
    auth_events: oldAuthEvents,
    prev_events: oldPrevEvent ? [oldPrevEvent.event_id] : [],
  };

  await storeEvent(db, tombstoneEvent);

  // Update old room's power levels to restrict posting
  // Elevate events_default to prevent casual messaging
  const newPowerLevels = powerLevels ? { ...powerLevels } : {
    users: { [userId]: 100 },
    users_default: 0,
    events_default: 100, // Set high to prevent messaging
    state_default: 100,
    ban: 100,
    kick: 100,
    redact: 100,
    invite: 100,
  };
  newPowerLevels.events_default = 100;
  newPowerLevels.invite = 100;

  const restrictEventId = await generateEventId(serverName);
  const restrictEvent: PDU = {
    event_id: restrictEventId,
    room_id: oldRoomId,
    sender: userId,
    type: 'm.room.power_levels',
    state_key: '',
    content: newPowerLevels,
    origin_server_ts: now + 1,
    depth: (oldPrevEvent?.depth || 0) + 2,
    auth_events: oldAuthEvents,
    prev_events: [tombstoneEventId],
  };

  await storeEvent(db, restrictEvent);

  // Migrate local room aliases to point to new room
  const aliases = await db.prepare(`
    SELECT alias FROM room_aliases WHERE room_id = ?
  `).bind(oldRoomId).all<{ alias: string }>();

  for (const aliasRow of aliases.results) {
    await db.prepare(`
      UPDATE room_aliases SET room_id = ? WHERE alias = ?
    `).bind(newRoomId, aliasRow.alias).run();
  }

  return c.json({
    replacement_room: newRoomId,
  });
});

export default app;
