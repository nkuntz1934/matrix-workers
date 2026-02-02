// Matrix State Resolution v2
// Implements the state resolution algorithm for room versions 2+
// https://spec.matrix.org/v1.12/rooms/v2/

import type { PDU } from '../types/matrix';
import {
  checkEventAuthorization,
  buildAuthStateFromEvents,
  type RoomAuthState,
} from './authorization';

/**
 * Map of state key to event(s)
 */
type StateMap = Map<string, PDU>;

/**
 * Result of state resolution
 */
export interface StateResolutionResult {
  /** The resolved state events */
  resolvedState: PDU[];
  /** Whether there were any conflicts that needed resolution */
  hadConflicts: boolean;
  /** Events that were rejected during resolution (failed auth) */
  rejectedEvents: PDU[];
}

/**
 * Create a state key string from event type and state key
 */
function makeStateKeyStr(eventType: string, stateKey: string): string {
  return `${eventType}\0${stateKey}`;
}

/**
 * Resolve conflicting room state using State Resolution v2
 *
 * @param stateSets - Array of state sets from different forks
 * @param authEvents - All auth events available for authorization checks
 * @returns The resolved state
 */
export async function resolveState(
  stateSets: PDU[][],
  authEvents: PDU[]
): Promise<StateResolutionResult> {
  if (stateSets.length === 0) {
    return { resolvedState: [], hadConflicts: false, rejectedEvents: [] };
  }

  if (stateSets.length === 1) {
    return { resolvedState: stateSets[0], hadConflicts: false, rejectedEvents: [] };
  }

  // Step 1: Separate into unconflicted and conflicted state
  const { unconflicted, conflicted } = separateState(stateSets);

  if (conflicted.size === 0) {
    // No conflicts, return unconflicted state
    return {
      resolvedState: Array.from(unconflicted.values()),
      hadConflicts: false,
      rejectedEvents: [],
    };
  }

  // Step 2: Build full auth chain for resolution
  const authEventMap = new Map<string, PDU>();
  for (const event of authEvents) {
    authEventMap.set(event.event_id, event);
  }

  // Step 3: Resolve each conflicted state key
  const resolved = new Map<string, PDU>(unconflicted);
  const rejectedEvents: PDU[] = [];

  for (const [stateKeyStr, conflictingEvents] of conflicted) {
    const winner = await resolveConflict(
      conflictingEvents,
      resolved,
      authEventMap,
      rejectedEvents
    );
    if (winner) {
      resolved.set(stateKeyStr, winner);
    }
  }

  return {
    resolvedState: Array.from(resolved.values()),
    hadConflicts: true,
    rejectedEvents,
  };
}

/**
 * Separate state sets into unconflicted and conflicted events
 */
function separateState(stateSets: PDU[][]): {
  unconflicted: StateMap;
  conflicted: Map<string, PDU[]>;
} {
  const unconflicted = new Map<string, PDU>();
  const conflicted = new Map<string, PDU[]>();

  // Build maps for each state set
  const stateMaps: StateMap[] = stateSets.map((stateSet) => {
    const map = new Map<string, PDU>();
    for (const event of stateSet) {
      if (event.state_key !== undefined) {
        const key = makeStateKeyStr(event.type, event.state_key);
        map.set(key, event);
      }
    }
    return map;
  });

  // Find all state keys across all sets
  const allStateKeys = new Set<string>();
  for (const stateMap of stateMaps) {
    for (const key of stateMap.keys()) {
      allStateKeys.add(key);
    }
  }

  // Categorize each state key
  for (const stateKeyStr of allStateKeys) {
    const events: PDU[] = [];
    const eventIds = new Set<string>();

    for (const stateMap of stateMaps) {
      const event = stateMap.get(stateKeyStr);
      if (event && !eventIds.has(event.event_id)) {
        events.push(event);
        eventIds.add(event.event_id);
      }
    }

    if (events.length === 1) {
      // Same event in all sets (or only present in one set)
      unconflicted.set(stateKeyStr, events[0]);
    } else if (events.length > 1) {
      // Check if all events are the same
      const allSame = events.every((e) => e.event_id === events[0].event_id);
      if (allSame) {
        unconflicted.set(stateKeyStr, events[0]);
      } else {
        conflicted.set(stateKeyStr, events);
      }
    }
  }

  return { unconflicted, conflicted };
}

/**
 * Resolve a conflict between multiple events for the same state key
 * Uses the mainline ordering algorithm from State Resolution v2
 */
async function resolveConflict(
  conflictingEvents: PDU[],
  currentResolved: StateMap,
  authEventMap: Map<string, PDU>,
  rejectedEvents: PDU[]
): Promise<PDU | null> {
  // Sort events by the resolution ordering
  const sortedEvents = [...conflictingEvents].sort((a, b) => {
    return compareEventsForResolution(a, b, currentResolved, authEventMap);
  });

  // Try each event in order until one passes auth
  for (const event of sortedEvents) {
    // Build auth state for checking this event
    const authState = buildAuthStateForEvent(event, currentResolved, authEventMap);

    // Check if this event is authorized
    const authResult = await checkEventAuthorization(event, authState);
    if (authResult.authorized) {
      return event;
    } else {
      rejectedEvents.push(event);
    }
  }

  // No event passed auth - return null (state key will be unset)
  return null;
}

/**
 * Compare two events for state resolution ordering
 * Returns negative if a should come before b, positive if b should come before a
 */
function compareEventsForResolution(
  a: PDU,
  b: PDU,
  currentResolved: StateMap,
  authEventMap: Map<string, PDU>
): number {
  // 1. Compare by power level of sender (higher power wins, so comes first)
  const aPower = getSenderPowerLevel(a.sender, currentResolved, authEventMap);
  const bPower = getSenderPowerLevel(b.sender, currentResolved, authEventMap);

  if (aPower !== bPower) {
    return bPower - aPower; // Higher power comes first
  }

  // 2. Compare by origin_server_ts (earlier wins, so comes first)
  if (a.origin_server_ts !== b.origin_server_ts) {
    return a.origin_server_ts - b.origin_server_ts;
  }

  // 3. Compare by event_id lexicographically
  return a.event_id.localeCompare(b.event_id);
}

/**
 * Get the power level of a user from the current resolved state
 */
function getSenderPowerLevel(
  userId: string,
  currentResolved: StateMap,
  authEventMap: Map<string, PDU>
): number {
  // Try to get power levels from resolved state first
  const powerLevelsKey = makeStateKeyStr('m.room.power_levels', '');
  let powerLevelsEvent = currentResolved.get(powerLevelsKey);

  // Fall back to auth events if not in resolved state
  if (!powerLevelsEvent) {
    for (const event of authEventMap.values()) {
      if (event.type === 'm.room.power_levels' && event.state_key === '') {
        powerLevelsEvent = event;
        break;
      }
    }
  }

  if (!powerLevelsEvent) {
    // No power levels event - use defaults
    // Check if user is room creator
    const createKey = makeStateKeyStr('m.room.create', '');
    const createEvent = currentResolved.get(createKey) ||
      Array.from(authEventMap.values()).find(e => e.type === 'm.room.create');

    if (createEvent) {
      const creator = (createEvent.content as { creator?: string })?.creator;
      if (creator === userId) {
        return 100; // Creator default power level
      }
    }
    return 0; // Default power level
  }

  const content = powerLevelsEvent.content as {
    users?: Record<string, number>;
    users_default?: number;
  };

  return content.users?.[userId] ?? content.users_default ?? 0;
}

/**
 * Build auth state for checking a specific event during resolution
 */
function buildAuthStateForEvent(
  event: PDU,
  currentResolved: StateMap,
  authEventMap: Map<string, PDU>
): RoomAuthState {
  // Collect relevant events for auth state
  const authEvents: PDU[] = [];

  // Get create event
  const createKey = makeStateKeyStr('m.room.create', '');
  const createEvent = currentResolved.get(createKey) ||
    Array.from(authEventMap.values()).find(e => e.type === 'm.room.create');
  if (createEvent) {
    authEvents.push(createEvent);
  }

  // Get power levels
  const powerLevelsKey = makeStateKeyStr('m.room.power_levels', '');
  const powerLevelsEvent = currentResolved.get(powerLevelsKey) ||
    Array.from(authEventMap.values()).find(e => e.type === 'm.room.power_levels' && e.state_key === '');
  if (powerLevelsEvent) {
    authEvents.push(powerLevelsEvent);
  }

  // Get join rules
  const joinRulesKey = makeStateKeyStr('m.room.join_rules', '');
  const joinRulesEvent = currentResolved.get(joinRulesKey) ||
    Array.from(authEventMap.values()).find(e => e.type === 'm.room.join_rules' && e.state_key === '');
  if (joinRulesEvent) {
    authEvents.push(joinRulesEvent);
  }

  // Get sender's membership
  const senderMemberKey = makeStateKeyStr('m.room.member', event.sender);
  const senderMemberEvent = currentResolved.get(senderMemberKey) ||
    Array.from(authEventMap.values()).find(e => e.type === 'm.room.member' && e.state_key === event.sender);
  if (senderMemberEvent) {
    authEvents.push(senderMemberEvent);
  }

  // If this is a member event, get target's membership
  if (event.type === 'm.room.member' && event.state_key && event.state_key !== event.sender) {
    const targetMemberKey = makeStateKeyStr('m.room.member', event.state_key);
    const targetMemberEvent = currentResolved.get(targetMemberKey) ||
      Array.from(authEventMap.values()).find(e => e.type === 'm.room.member' && e.state_key === event.state_key);
    if (targetMemberEvent) {
      authEvents.push(targetMemberEvent);
    }
  }

  return buildAuthStateFromEvents(authEvents);
}

/**
 * Resolve state when processing a new event
 * Compares the new event against the current state and resolves if needed
 */
export async function resolveStateWithNewEvent(
  newEvent: PDU,
  currentState: PDU[],
  authEvents: PDU[]
): Promise<StateResolutionResult> {
  if (newEvent.state_key === undefined) {
    // Not a state event, no resolution needed
    return { resolvedState: currentState, hadConflicts: false, rejectedEvents: [] };
  }

  const stateKeyStr = makeStateKeyStr(newEvent.type, newEvent.state_key);

  // Find existing event for this state key
  const existingEvent = currentState.find(
    (e) => e.type === newEvent.type && e.state_key === newEvent.state_key
  );

  if (!existingEvent) {
    // No existing state for this key - just add the new event
    return {
      resolvedState: [...currentState, newEvent],
      hadConflicts: false,
      rejectedEvents: [],
    };
  }

  if (existingEvent.event_id === newEvent.event_id) {
    // Same event, no change needed
    return { resolvedState: currentState, hadConflicts: false, rejectedEvents: [] };
  }

  // We have a conflict - resolve it
  const authEventMap = new Map<string, PDU>();
  for (const event of authEvents) {
    authEventMap.set(event.event_id, event);
  }

  // Build current resolved state map (excluding the conflicting key)
  const currentResolved = new Map<string, PDU>();
  for (const event of currentState) {
    if (event.state_key !== undefined) {
      const key = makeStateKeyStr(event.type, event.state_key);
      if (key !== stateKeyStr) {
        currentResolved.set(key, event);
      }
    }
  }

  const rejectedEvents: PDU[] = [];
  const winner = await resolveConflict(
    [existingEvent, newEvent],
    currentResolved,
    authEventMap,
    rejectedEvents
  );

  // Build new state with the winner
  const newState = currentState.filter(
    (e) => !(e.type === newEvent.type && e.state_key === newEvent.state_key)
  );

  if (winner) {
    newState.push(winner);
  }

  return {
    resolvedState: newState,
    hadConflicts: true,
    rejectedEvents,
  };
}

/**
 * Check if a new state event should replace existing state
 * Used for simple conflict resolution during normal event processing
 */
export async function shouldReplaceState(
  newEvent: PDU,
  existingEvent: PDU,
  authEvents: PDU[]
): Promise<{ replace: boolean; reason?: string }> {
  if (newEvent.state_key === undefined) {
    return { replace: false, reason: 'Not a state event' };
  }

  // Build auth context
  const authEventMap = new Map<string, PDU>();
  for (const event of authEvents) {
    authEventMap.set(event.event_id, event);
  }

  const currentResolved = new Map<string, PDU>();

  // Compare events using resolution ordering
  const comparison = compareEventsForResolution(
    newEvent,
    existingEvent,
    currentResolved,
    authEventMap
  );

  if (comparison < 0) {
    // New event wins according to resolution rules
    // But we still need to verify it's authorized
    const authState = buildAuthStateForEvent(newEvent, currentResolved, authEventMap);
    const authResult = await checkEventAuthorization(newEvent, authState);

    if (authResult.authorized) {
      return { replace: true };
    } else {
      return { replace: false, reason: authResult.reason };
    }
  }

  return { replace: false, reason: 'Existing event has priority' };
}
