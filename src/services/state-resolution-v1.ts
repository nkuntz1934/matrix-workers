// State Resolution Algorithm v1 (Room Version 1)
// Simple: sort by depth, then by event_id lexicographically

import type { PDU } from '../types';
import { stateKey } from './event-auth';

/**
 * Resolve conflicting state using the v1 algorithm.
 * Takes multiple state sets (from different prev_events) and merges them.
 * Conflicting state is resolved by picking the event with the highest depth,
 * with event_id as a tiebreaker.
 */
export function resolveStateV1(stateSets: PDU[][]): PDU[] {
  // Collect all state events grouped by (type, state_key)
  const allState = new Map<string, PDU[]>();

  for (const stateSet of stateSets) {
    for (const event of stateSet) {
      if (event.state_key === undefined) continue;
      const key = stateKey(event.type, event.state_key);
      const existing = allState.get(key) || [];
      // Don't add duplicates
      if (!existing.some(e => e.event_id === event.event_id)) {
        existing.push(event);
      }
      allState.set(key, existing);
    }
  }

  // For each state key, pick the winner
  const resolved: PDU[] = [];

  for (const events of allState.values()) {
    if (events.length === 1) {
      resolved.push(events[0]);
      continue;
    }

    // Sort by depth descending, then event_id ascending for tiebreak
    events.sort((a, b) => {
      if (a.depth !== b.depth) return b.depth - a.depth;
      return a.event_id < b.event_id ? -1 : a.event_id > b.event_id ? 1 : 0;
    });

    resolved.push(events[0]);
  }

  return resolved;
}
