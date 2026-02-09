// State Resolution Algorithm v2 (Room Versions 2+)
// Implements the full state resolution algorithm per Matrix spec

import type { PDU, RoomPowerLevelsContent } from '../types';
import { buildStateMap, stateKey, checkEventAuth, type RoomStateMap } from './event-auth';
import { resolveStateV1 } from './state-resolution-v1';
import { getRoomVersion } from './room-versions';

// Auth event types used in state resolution
const AUTH_EVENT_TYPES = new Set([
  'm.room.create',
  'm.room.power_levels',
  'm.room.join_rules',
  'm.room.member',
  'm.room.third_party_invite',
]);

/**
 * Main entry point: resolve state given multiple state sets from different branches.
 * Selects the appropriate algorithm based on room version.
 */
export function resolveState(
  roomVersion: string,
  stateSets: PDU[][]
): PDU[] {
  const version = getRoomVersion(roomVersion);
  if (!version || version.stateResolution === 'v1') {
    return resolveStateV1(stateSets);
  }
  return resolveStateV2(stateSets, roomVersion);
}

/**
 * State Resolution v2 algorithm.
 *
 * 1. Separate conflicted vs unconflicted state
 * 2. Resolve auth events first via iterative auth checking
 * 3. Resolve remaining via reverse topological power ordering
 */
function resolveStateV2(stateSets: PDU[][], roomVersion: string): PDU[] {
  if (stateSets.length === 0) return [];
  if (stateSets.length === 1) return stateSets[0];

  // Step 1: Separate unconflicted and conflicted state
  const { unconflicted, conflicted } = separateState(stateSets);

  if (conflicted.size === 0) {
    return Array.from(unconflicted.values());
  }

  // Step 2: Separate conflicted into auth events and non-auth events
  const conflictedAuth: PDU[] = [];
  const conflictedOther: PDU[] = [];

  for (const events of conflicted.values()) {
    for (const event of events) {
      if (isAuthEvent(event)) {
        conflictedAuth.push(event);
      } else {
        conflictedOther.push(event);
      }
    }
  }

  // Step 3: Resolve auth events first using reverse topological power ordering
  const sortedAuth = reverseTopologicalPowerOrder(conflictedAuth);

  // Build the partial resolved state starting from unconflicted
  const resolvedState = new Map(unconflicted);

  // Iteratively apply auth events, checking authorization
  for (const authEvent of sortedAuth) {
    if (authEvent.state_key === undefined) continue;

    const currentState = Array.from(resolvedState.values());
    const authResult = checkEventAuth(authEvent, currentState, roomVersion);

    if (authResult.allowed) {
      const key = stateKey(authEvent.type, authEvent.state_key);
      resolvedState.set(key, authEvent);
    }
  }

  // Step 4: Resolve remaining (non-auth) conflicted events
  const sortedOther = reverseTopologicalPowerOrder(conflictedOther);

  for (const event of sortedOther) {
    if (event.state_key === undefined) continue;

    const currentState = Array.from(resolvedState.values());
    const authResult = checkEventAuth(event, currentState, roomVersion);

    if (authResult.allowed) {
      const key = stateKey(event.type, event.state_key);
      resolvedState.set(key, event);
    }
  }

  return Array.from(resolvedState.values());
}

/**
 * Separate state into unconflicted (same event in all sets) and conflicted (differs between sets).
 */
function separateState(stateSets: PDU[][]): {
  unconflicted: RoomStateMap;
  conflicted: Map<string, PDU[]>;
} {
  // Build state maps for each set
  const maps = stateSets.map(buildStateMap);

  // Collect all possible state keys
  const allKeys = new Set<string>();
  for (const map of maps) {
    for (const key of map.keys()) {
      allKeys.add(key);
    }
  }

  const unconflicted: RoomStateMap = new Map();
  const conflicted = new Map<string, PDU[]>();

  for (const key of allKeys) {
    const events = maps
      .map(m => m.get(key))
      .filter((e): e is PDU => e !== undefined);

    // Check if all present events agree
    const eventIds = new Set(events.map(e => e.event_id));

    if (eventIds.size === 1 && events.length === maps.length) {
      // Same event in all state sets (unconflicted)
      unconflicted.set(key, events[0]);
    } else {
      // Different events or missing in some sets (conflicted)
      // Deduplicate by event_id
      const seen = new Set<string>();
      const uniqueEvents: PDU[] = [];
      for (const event of events) {
        if (!seen.has(event.event_id)) {
          seen.add(event.event_id);
          uniqueEvents.push(event);
        }
      }
      conflicted.set(key, uniqueEvents);
    }
  }

  return { unconflicted, conflicted };
}

/** Check if an event is an auth event type */
function isAuthEvent(event: PDU): boolean {
  return AUTH_EVENT_TYPES.has(event.type);
}

/**
 * Sort events in reverse topological power order.
 * This is the mainline ordering:
 * 1. Events with higher power level senders first
 * 2. Then by origin_server_ts ascending
 * 3. Then by event_id ascending (lexicographic)
 */
function reverseTopologicalPowerOrder(events: PDU[]): PDU[] {
  // Build a map of event_id -> event for auth chain traversal
  const eventMap = new Map<string, PDU>();
  for (const event of events) {
    eventMap.set(event.event_id, event);
  }

  // Extract the power level from the events themselves or assume default
  const powerLevelEvent = events.find(e => e.type === 'm.room.power_levels');
  const powerLevels: RoomPowerLevelsContent = powerLevelEvent
    ? (powerLevelEvent.content as RoomPowerLevelsContent)
    : { users: {}, users_default: 0 };

  function getSenderPower(event: PDU): number {
    return powerLevels.users?.[event.sender] ?? powerLevels.users_default ?? 0;
  }

  // Sort by:
  // 1. Power level of sender (descending)
  // 2. origin_server_ts (ascending)
  // 3. event_id (ascending, lexicographic)
  return [...events].sort((a, b) => {
    const powerA = getSenderPower(a);
    const powerB = getSenderPower(b);

    if (powerA !== powerB) return powerB - powerA;
    if (a.origin_server_ts !== b.origin_server_ts) return a.origin_server_ts - b.origin_server_ts;
    return a.event_id < b.event_id ? -1 : a.event_id > b.event_id ? 1 : 0;
  });
}
