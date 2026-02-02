// Matrix event authorization checking
// Implements authorization rules per Matrix spec:
// https://spec.matrix.org/v1.12/server-server-api/#authorization-rules

import type {
  PDU,
  RoomCreateContent,
  RoomMemberContent,
  RoomPowerLevelsContent,
  RoomJoinRulesContent,
  Membership,
} from '../types/matrix';

/**
 * Result of an authorization check
 */
export interface AuthorizationResult {
  authorized: boolean;
  reason?: string;
}

/**
 * Room state needed for authorization checks
 */
export interface RoomAuthState {
  createEvent?: PDU;
  powerLevelsEvent?: PDU;
  joinRulesEvent?: PDU;
  memberEvents: Map<string, PDU>; // user_id -> membership event
}

/**
 * Check if an event is authorized according to Matrix auth rules
 */
export async function checkEventAuthorization(
  event: PDU,
  authState: RoomAuthState
): Promise<AuthorizationResult> {
  // Rule 1: If type is m.room.create
  if (event.type === 'm.room.create') {
    return checkCreateEvent(event);
  }

  // Rule 2: Reject if no create event
  if (!authState.createEvent) {
    return { authorized: false, reason: 'No m.room.create event in auth chain' };
  }

  // Rule 3: If type is m.room.member
  if (event.type === 'm.room.member') {
    return checkMemberEvent(event, authState);
  }

  // Rule 4: If sender not in room, reject
  const senderMembership = getSenderMembership(event.sender, authState);
  if (senderMembership !== 'join') {
    return { authorized: false, reason: 'Sender is not in the room' };
  }

  // Rule 5: If type is m.room.third_party_invite
  if (event.type === 'm.room.third_party_invite') {
    return checkThirdPartyInvite(event, authState);
  }

  // Rule 6: Check power levels for other events
  return checkPowerLevels(event, authState);
}

/**
 * Check m.room.create event authorization
 */
function checkCreateEvent(event: PDU): AuthorizationResult {
  // Create event must have empty auth_events
  if (event.auth_events && event.auth_events.length > 0) {
    return { authorized: false, reason: 'm.room.create must have empty auth_events' };
  }

  // Create event must have empty prev_events
  if (event.prev_events && event.prev_events.length > 0) {
    return { authorized: false, reason: 'm.room.create must have empty prev_events' };
  }

  // Room version must be recognized (basic check)
  const content = event.content as RoomCreateContent;
  const roomVersion = content.room_version || '1';
  const supportedVersions = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '10', '11'];
  if (!supportedVersions.includes(roomVersion)) {
    return { authorized: false, reason: `Unsupported room version: ${roomVersion}` };
  }

  return { authorized: true };
}

/**
 * Check m.room.member event authorization
 */
function checkMemberEvent(event: PDU, authState: RoomAuthState): AuthorizationResult {
  const content = event.content as RoomMemberContent;
  const targetUserId = event.state_key;
  const membership = content.membership;

  if (!targetUserId) {
    return { authorized: false, reason: 'Member event must have state_key' };
  }

  if (!membership) {
    return { authorized: false, reason: 'Member event must have membership field' };
  }

  const validMemberships: Membership[] = ['invite', 'join', 'leave', 'ban', 'knock'];
  if (!validMemberships.includes(membership)) {
    return { authorized: false, reason: `Invalid membership value: ${membership}` };
  }

  const senderMembership = getSenderMembership(event.sender, authState);
  const targetMembership = getTargetMembership(targetUserId, authState);

  switch (membership) {
    case 'join':
      return checkJoin(event, authState, senderMembership, targetMembership);
    case 'invite':
      return checkInvite(event, authState, senderMembership, targetMembership);
    case 'leave':
      return checkLeave(event, authState, senderMembership, targetMembership);
    case 'ban':
      return checkBan(event, authState, senderMembership, targetMembership);
    case 'knock':
      return checkKnock(event, authState, senderMembership, targetMembership);
    default:
      return { authorized: false, reason: `Unknown membership: ${membership}` };
  }
}

/**
 * Check join membership transition
 */
function checkJoin(
  event: PDU,
  authState: RoomAuthState,
  _senderMembership: Membership | null,
  targetMembership: Membership | null
): AuthorizationResult {
  const targetUserId = event.state_key!;

  // User can only join for themselves
  if (event.sender !== targetUserId) {
    return { authorized: false, reason: 'Cannot set join membership for another user' };
  }

  // Check join rules
  const joinRules = getJoinRules(authState);

  // If currently banned, cannot join
  if (targetMembership === 'ban') {
    return { authorized: false, reason: 'User is banned from the room' };
  }

  // If join_rule is public, allow join
  if (joinRules === 'public') {
    return { authorized: true };
  }

  // If join_rule is invite, must be invited
  if (joinRules === 'invite') {
    if (targetMembership === 'invite' || targetMembership === 'join') {
      return { authorized: true };
    }
    return { authorized: false, reason: 'Room requires invite to join' };
  }

  // If join_rule is knock, must be invited or knocked
  if (joinRules === 'knock' || joinRules === 'knock_restricted') {
    if (targetMembership === 'invite' || targetMembership === 'join') {
      return { authorized: true };
    }
    // Knock handling would go here
    return { authorized: false, reason: 'Room requires invite to join' };
  }

  // If join_rule is restricted, check allow list or invite
  if (joinRules === 'restricted') {
    if (targetMembership === 'invite' || targetMembership === 'join') {
      return { authorized: true };
    }
    // TODO: Check allow list for restricted joins
    return { authorized: false, reason: 'Room is restricted' };
  }

  return { authorized: false, reason: 'Join not allowed by room rules' };
}

/**
 * Check invite membership transition
 */
function checkInvite(
  event: PDU,
  authState: RoomAuthState,
  senderMembership: Membership | null,
  targetMembership: Membership | null
): AuthorizationResult {
  // Sender must be in room
  if (senderMembership !== 'join') {
    return { authorized: false, reason: 'Sender must be in room to invite' };
  }

  // Cannot invite banned user
  if (targetMembership === 'ban') {
    return { authorized: false, reason: 'Cannot invite banned user' };
  }

  // Check invite power level
  const senderPowerLevel = getUserPowerLevel(event.sender, authState);
  const requiredLevel = getInvitePowerLevel(authState);

  if (senderPowerLevel < requiredLevel) {
    return { authorized: false, reason: 'Insufficient power level to invite' };
  }

  return { authorized: true };
}

/**
 * Check leave membership transition
 */
function checkLeave(
  event: PDU,
  authState: RoomAuthState,
  senderMembership: Membership | null,
  targetMembership: Membership | null
): AuthorizationResult {
  const targetUserId = event.state_key!;

  // User leaving themselves
  if (event.sender === targetUserId) {
    // Can always leave if currently in room or invited
    if (targetMembership === 'join' || targetMembership === 'invite') {
      return { authorized: true };
    }
    return { authorized: false, reason: 'User is not in room' };
  }

  // Kicking another user
  if (senderMembership !== 'join') {
    return { authorized: false, reason: 'Sender must be in room to kick' };
  }

  // Cannot kick banned user (must unban first)
  if (targetMembership === 'ban') {
    return { authorized: false, reason: 'Cannot kick banned user, must unban' };
  }

  // Check kick power level
  const senderPowerLevel = getUserPowerLevel(event.sender, authState);
  const targetPowerLevel = getUserPowerLevel(targetUserId, authState);
  const kickLevel = getKickPowerLevel(authState);

  if (senderPowerLevel < kickLevel) {
    return { authorized: false, reason: 'Insufficient power level to kick' };
  }

  if (senderPowerLevel <= targetPowerLevel) {
    return { authorized: false, reason: 'Cannot kick user with equal or higher power level' };
  }

  return { authorized: true };
}

/**
 * Check ban membership transition
 */
function checkBan(
  event: PDU,
  authState: RoomAuthState,
  senderMembership: Membership | null,
  _targetMembership: Membership | null
): AuthorizationResult {
  const targetUserId = event.state_key!;

  if (senderMembership !== 'join') {
    return { authorized: false, reason: 'Sender must be in room to ban' };
  }

  const senderPowerLevel = getUserPowerLevel(event.sender, authState);
  const targetPowerLevel = getUserPowerLevel(targetUserId, authState);
  const banLevel = getBanPowerLevel(authState);

  if (senderPowerLevel < banLevel) {
    return { authorized: false, reason: 'Insufficient power level to ban' };
  }

  if (senderPowerLevel <= targetPowerLevel) {
    return { authorized: false, reason: 'Cannot ban user with equal or higher power level' };
  }

  return { authorized: true };
}

/**
 * Check knock membership transition
 */
function checkKnock(
  event: PDU,
  authState: RoomAuthState,
  senderMembership: Membership | null,
  targetMembership: Membership | null
): AuthorizationResult {
  void senderMembership; // Not used for knock, but kept for consistency
  const targetUserId = event.state_key!;

  // Can only knock for self
  if (event.sender !== targetUserId) {
    return { authorized: false, reason: 'Can only knock for self' };
  }

  // Cannot knock if banned
  if (targetMembership === 'ban') {
    return { authorized: false, reason: 'Cannot knock when banned' };
  }

  // Cannot knock if already in room
  if (targetMembership === 'join') {
    return { authorized: false, reason: 'Already in room' };
  }

  // Check join rules allow knocking
  const joinRules = getJoinRules(authState);
  if (joinRules !== 'knock' && joinRules !== 'knock_restricted') {
    return { authorized: false, reason: 'Room does not allow knocking' };
  }

  return { authorized: true };
}

/**
 * Check third party invite authorization
 */
function checkThirdPartyInvite(event: PDU, authState: RoomAuthState): AuthorizationResult {
  const senderMembership = getSenderMembership(event.sender, authState);

  if (senderMembership !== 'join') {
    return { authorized: false, reason: 'Sender must be in room' };
  }

  const senderPowerLevel = getUserPowerLevel(event.sender, authState);
  const requiredLevel = getInvitePowerLevel(authState);

  if (senderPowerLevel < requiredLevel) {
    return { authorized: false, reason: 'Insufficient power level for third party invite' };
  }

  return { authorized: true };
}

/**
 * Check power levels for non-member events
 */
function checkPowerLevels(event: PDU, authState: RoomAuthState): AuthorizationResult {
  const senderPowerLevel = getUserPowerLevel(event.sender, authState);
  const requiredLevel = getRequiredPowerLevel(event, authState);

  if (senderPowerLevel < requiredLevel) {
    return {
      authorized: false,
      reason: `Insufficient power level: have ${senderPowerLevel}, need ${requiredLevel}`,
    };
  }

  // Special check for m.room.power_levels
  if (event.type === 'm.room.power_levels') {
    return checkPowerLevelsChange(event, authState, senderPowerLevel);
  }

  return { authorized: true };
}

/**
 * Check power levels change authorization
 */
function checkPowerLevelsChange(
  event: PDU,
  authState: RoomAuthState,
  senderPowerLevel: number
): AuthorizationResult {
  const currentPowerLevels = authState.powerLevelsEvent?.content as RoomPowerLevelsContent | undefined;
  const newPowerLevels = event.content as RoomPowerLevelsContent;

  // Check each user power level change
  if (newPowerLevels.users) {
    for (const [userId, newLevel] of Object.entries(newPowerLevels.users)) {
      const currentLevel = currentPowerLevels?.users?.[userId] ?? currentPowerLevels?.users_default ?? 0;

      // Cannot set power level higher than own
      if (newLevel > senderPowerLevel) {
        return { authorized: false, reason: `Cannot set power level higher than own for ${userId}` };
      }

      // Cannot change power level of user with equal or higher power
      if (currentLevel >= senderPowerLevel && newLevel !== currentLevel) {
        return { authorized: false, reason: `Cannot change power level of ${userId}` };
      }
    }
  }

  return { authorized: true };
}

// Helper functions

function getSenderMembership(senderId: string, authState: RoomAuthState): Membership | null {
  const memberEvent = authState.memberEvents.get(senderId);
  if (!memberEvent) return null;
  return (memberEvent.content as RoomMemberContent).membership;
}

function getTargetMembership(targetId: string, authState: RoomAuthState): Membership | null {
  const memberEvent = authState.memberEvents.get(targetId);
  if (!memberEvent) return null;
  return (memberEvent.content as RoomMemberContent).membership;
}

function getJoinRules(authState: RoomAuthState): string {
  if (!authState.joinRulesEvent) return 'invite';
  const content = authState.joinRulesEvent.content as unknown as RoomJoinRulesContent;
  return content.join_rule || 'invite';
}

function getUserPowerLevel(userId: string, authState: RoomAuthState): number {
  if (!authState.powerLevelsEvent) {
    // Default: creator has 100, others have 0
    const creator = (authState.createEvent?.content as RoomCreateContent)?.creator;
    return userId === creator ? 100 : 0;
  }

  const powerLevels = authState.powerLevelsEvent.content as RoomPowerLevelsContent;
  return powerLevels.users?.[userId] ?? powerLevels.users_default ?? 0;
}

function getRequiredPowerLevel(event: PDU, authState: RoomAuthState): number {
  if (!authState.powerLevelsEvent) {
    // Default power levels per spec
    return event.state_key !== undefined ? 50 : 0;
  }

  const powerLevels = authState.powerLevelsEvent.content as RoomPowerLevelsContent;

  // Check event-specific power level
  if (powerLevels.events && powerLevels.events[event.type] !== undefined) {
    return powerLevels.events[event.type];
  }

  // State events use state_default, message events use events_default
  if (event.state_key !== undefined) {
    return powerLevels.state_default ?? 50;
  }

  return powerLevels.events_default ?? 0;
}

function getInvitePowerLevel(authState: RoomAuthState): number {
  if (!authState.powerLevelsEvent) return 0;
  const powerLevels = authState.powerLevelsEvent.content as RoomPowerLevelsContent;
  return powerLevels.invite ?? 0;
}

function getKickPowerLevel(authState: RoomAuthState): number {
  if (!authState.powerLevelsEvent) return 50;
  const powerLevels = authState.powerLevelsEvent.content as RoomPowerLevelsContent;
  return powerLevels.kick ?? 50;
}

function getBanPowerLevel(authState: RoomAuthState): number {
  if (!authState.powerLevelsEvent) return 50;
  const powerLevels = authState.powerLevelsEvent.content as RoomPowerLevelsContent;
  return powerLevels.ban ?? 50;
}

/**
 * Build auth state from a list of auth events (from PDU's auth_events)
 */
export function buildAuthStateFromEvents(events: PDU[]): RoomAuthState {
  const state: RoomAuthState = {
    memberEvents: new Map(),
  };

  for (const event of events) {
    if (event.type === 'm.room.create') {
      state.createEvent = event;
    } else if (event.type === 'm.room.power_levels') {
      state.powerLevelsEvent = event;
    } else if (event.type === 'm.room.join_rules') {
      state.joinRulesEvent = event;
    } else if (event.type === 'm.room.member' && event.state_key) {
      state.memberEvents.set(event.state_key, event);
    }
  }

  return state;
}

/**
 * Fetch auth state from database for a room
 */
export async function fetchRoomAuthState(
  db: D1Database,
  roomId: string
): Promise<RoomAuthState> {
  const state: RoomAuthState = {
    memberEvents: new Map(),
  };

  // Fetch relevant state events
  const stateTypes = ['m.room.create', 'm.room.power_levels', 'm.room.join_rules', 'm.room.member'];

  const result = await db
    .prepare(
      `SELECT e.event_id, e.room_id, e.sender, e.event_type, e.state_key, e.content,
              e.origin_server_ts, e.depth, e.auth_events, e.prev_events
       FROM room_state rs
       JOIN events e ON rs.event_id = e.event_id
       WHERE rs.room_id = ? AND rs.event_type IN (${stateTypes.map(() => '?').join(', ')})`
    )
    .bind(roomId, ...stateTypes)
    .all<{
      event_id: string;
      room_id: string;
      sender: string;
      event_type: string;
      state_key: string | null;
      content: string;
      origin_server_ts: number;
      depth: number;
      auth_events: string;
      prev_events: string;
    }>();

  for (const row of result.results) {
    const pdu: PDU = {
      event_id: row.event_id,
      room_id: row.room_id,
      sender: row.sender,
      type: row.event_type,
      state_key: row.state_key ?? undefined,
      content: JSON.parse(row.content),
      origin_server_ts: row.origin_server_ts,
      depth: row.depth,
      auth_events: JSON.parse(row.auth_events),
      prev_events: JSON.parse(row.prev_events),
    };

    if (pdu.type === 'm.room.create') {
      state.createEvent = pdu;
    } else if (pdu.type === 'm.room.power_levels') {
      state.powerLevelsEvent = pdu;
    } else if (pdu.type === 'm.room.join_rules') {
      state.joinRulesEvent = pdu;
    } else if (pdu.type === 'm.room.member' && pdu.state_key) {
      state.memberEvents.set(pdu.state_key, pdu);
    }
  }

  return state;
}

/**
 * Validate that auth_events chain is complete and valid
 */
export async function validateAuthChain(
  _db: D1Database,
  event: PDU,
  authEvents: PDU[]
): Promise<AuthorizationResult> {
  // Build lookup map for auth events
  const authEventMap = new Map<string, PDU>();
  for (const authEvent of authEvents) {
    authEventMap.set(authEvent.event_id, authEvent);
  }

  // Check all referenced auth_events exist
  for (const requiredId of event.auth_events) {
    if (!authEventMap.has(requiredId)) {
      return { authorized: false, reason: `Missing auth event: ${requiredId}` };
    }
  }

  // Check auth events are valid types
  const validAuthTypes = [
    'm.room.create',
    'm.room.power_levels',
    'm.room.join_rules',
    'm.room.member',
    'm.room.third_party_invite',
  ];

  for (const authEvent of authEvents) {
    if (!validAuthTypes.includes(authEvent.type)) {
      return { authorized: false, reason: `Invalid auth event type: ${authEvent.type}` };
    }
  }

  // Must include m.room.create (except for create event itself)
  const createEvent = authEvents.find((e) => e.type === 'm.room.create');
  if (!createEvent && event.type !== 'm.room.create') {
    return { authorized: false, reason: 'Auth chain must include m.room.create' };
  }

  // Must include sender's membership (except for create event)
  if (event.type !== 'm.room.create') {
    const hasSenderMembership = authEvents.some(
      (e) => e.type === 'm.room.member' && e.state_key === event.sender
    );
    if (!hasSenderMembership) {
      return { authorized: false, reason: "Auth chain must include sender's membership" };
    }
  }

  // Check for power_levels if event requires power level checks
  // (state events and certain room events need power levels)
  if (event.type !== 'm.room.create' && event.state_key !== undefined) {
    // State events (other than member events for self) typically need power_levels
    // However, power_levels is not strictly required if using default levels
    // We check if it exists in auth_events when the event references it
  }

  // Check for DAG cycles in auth chain
  const cycleResult = detectAuthChainCycle(event, authEventMap);
  if (!cycleResult.valid) {
    return { authorized: false, reason: cycleResult.reason };
  }

  // Recursively validate each auth event is itself authorized
  const recursiveResult = await validateAuthEventsRecursively(authEvents, authEventMap);
  if (!recursiveResult.authorized) {
    return recursiveResult;
  }

  return { authorized: true };
}

/**
 * Detect cycles in the auth event DAG
 * Returns { valid: true } if no cycles, { valid: false, reason } if cycle detected
 */
function detectAuthChainCycle(
  event: PDU,
  authEventMap: Map<string, PDU>
): { valid: boolean; reason?: string } {
  const visited = new Set<string>();
  const recursionStack = new Set<string>();

  function hasCycle(eventId: string): boolean {
    if (recursionStack.has(eventId)) {
      return true; // Cycle detected
    }
    if (visited.has(eventId)) {
      return false; // Already fully explored, no cycle from here
    }

    visited.add(eventId);
    recursionStack.add(eventId);

    const currentEvent = authEventMap.get(eventId);
    if (currentEvent && currentEvent.auth_events) {
      for (const authEventId of currentEvent.auth_events) {
        if (hasCycle(authEventId)) {
          return true;
        }
      }
    }

    recursionStack.delete(eventId);
    return false;
  }

  // Check for cycles starting from the main event
  if (event.auth_events) {
    for (const authEventId of event.auth_events) {
      if (hasCycle(authEventId)) {
        return { valid: false, reason: `Cycle detected in auth chain involving ${authEventId}` };
      }
    }
  }

  // Also check that no auth event references the main event (direct cycle)
  for (const authEvent of authEventMap.values()) {
    if (authEvent.auth_events?.includes(event.event_id)) {
      return { valid: false, reason: `Auth event ${authEvent.event_id} references the event being validated` };
    }
  }

  return { valid: true };
}

/**
 * Recursively validate that each auth event is itself authorized by its own auth events
 */
async function validateAuthEventsRecursively(
  authEvents: PDU[],
  authEventMap: Map<string, PDU>
): Promise<AuthorizationResult> {
  // Process auth events in topological order (create first, then others)
  const sortedAuthEvents = [...authEvents].sort((a, b) => {
    // Create event always comes first
    if (a.type === 'm.room.create') return -1;
    if (b.type === 'm.room.create') return 1;
    // Then by depth
    return (a.depth ?? 0) - (b.depth ?? 0);
  });

  for (const authEvent of sortedAuthEvents) {
    // Skip create event - it authorizes itself (checked separately)
    if (authEvent.type === 'm.room.create') {
      const createResult = await checkEventAuthorization(authEvent, {
        memberEvents: new Map(),
      });
      if (!createResult.authorized) {
        return {
          authorized: false,
          reason: `Auth event ${authEvent.event_id} (m.room.create) is invalid: ${createResult.reason}`,
        };
      }
      continue;
    }

    // Get this auth event's own auth events
    const eventAuthEvents: PDU[] = [];
    for (const refId of authEvent.auth_events || []) {
      const refEvent = authEventMap.get(refId);
      if (refEvent) {
        eventAuthEvents.push(refEvent);
      }
      // Note: We don't fail if auth event is missing here because
      // it might be a historical event not in the provided set
    }

    // Build auth state from this event's auth events
    const authState = buildAuthStateFromEvents(eventAuthEvents);

    // Check if this auth event is authorized
    const authResult = await checkEventAuthorization(authEvent, authState);
    if (!authResult.authorized) {
      return {
        authorized: false,
        reason: `Auth event ${authEvent.event_id} (${authEvent.type}) is not authorized: ${authResult.reason}`,
      };
    }
  }

  return { authorized: true };
}

/**
 * Extended auth chain validation for send_join - validates the joining event
 * against the room's current state and the provided auth chain
 */
export async function validateSendJoinAuthChain(
  joinEvent: PDU,
  roomAuthState: RoomAuthState,
  providedAuthEvents: PDU[]
): Promise<AuthorizationResult> {
  // First, validate the auth chain structure
  const authEventMap = new Map<string, PDU>();
  for (const authEvent of providedAuthEvents) {
    authEventMap.set(authEvent.event_id, authEvent);
  }

  // Check for cycles
  const cycleResult = detectAuthChainCycle(joinEvent, authEventMap);
  if (!cycleResult.valid) {
    return { authorized: false, reason: cycleResult.reason };
  }

  // Validate the join event references valid auth events
  for (const authEventId of joinEvent.auth_events || []) {
    if (!authEventMap.has(authEventId)) {
      // Check if it's in the room's existing state
      const inRoomState =
        (roomAuthState.createEvent?.event_id === authEventId) ||
        (roomAuthState.powerLevelsEvent?.event_id === authEventId) ||
        (roomAuthState.joinRulesEvent?.event_id === authEventId) ||
        Array.from(roomAuthState.memberEvents.values()).some(e => e.event_id === authEventId);

      if (!inRoomState) {
        return { authorized: false, reason: `Missing auth event: ${authEventId}` };
      }
    }
  }

  // Validate the join event is authorized
  const authResult = await checkEventAuthorization(joinEvent, roomAuthState);
  if (!authResult.authorized) {
    return authResult;
  }

  return { authorized: true };
}
