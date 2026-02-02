// History visibility enforcement per Matrix spec
// https://spec.matrix.org/v1.12/client-server-api/#room-history-visibility

import { getStateEvent } from './database';

/**
 * History visibility values per Matrix spec
 * - world_readable: Anyone can read, even non-members
 * - shared: Members can read all messages (current and past)
 * - invited: Members can read from when they were invited
 * - joined: Members can read from when they joined
 */
export type HistoryVisibility = 'world_readable' | 'shared' | 'invited' | 'joined';

export interface VisibilityContext {
  visibility: HistoryVisibility;
  /** Timestamp when user was first invited (if applicable) */
  invitedAt?: number;
  /** Timestamp when user joined (if applicable) */
  joinedAt?: number;
  /** Whether user is currently a member */
  isMember: boolean;
  /** Whether user was ever a member */
  wasEverMember: boolean;
}

/**
 * Get the current history visibility setting for a room
 */
export async function getRoomHistoryVisibility(
  db: D1Database,
  roomId: string
): Promise<HistoryVisibility> {
  const event = await getStateEvent(db, roomId, 'm.room.history_visibility');
  if (!event?.content) {
    return 'shared'; // Default per spec
  }
  const content = event.content as { history_visibility?: string };
  const visibility = content.history_visibility;

  if (visibility === 'world_readable' || visibility === 'shared' ||
      visibility === 'invited' || visibility === 'joined') {
    return visibility;
  }
  return 'shared'; // Default for invalid values
}

/**
 * Get the user's membership history timestamps for a room
 * Returns when the user was first invited and when they joined
 */
export async function getMembershipTimestamps(
  db: D1Database,
  roomId: string,
  userId: string
): Promise<{ invitedAt?: number; joinedAt?: number; isMember: boolean; wasEverMember: boolean }> {
  // Get all membership events for this user in this room, ordered by time
  const result = await db.prepare(`
    SELECT e.origin_server_ts, e.content
    FROM events e
    WHERE e.room_id = ?
      AND e.event_type = 'm.room.member'
      AND e.state_key = ?
    ORDER BY e.origin_server_ts ASC
  `).bind(roomId, userId).all<{ origin_server_ts: number; content: string }>();

  let invitedAt: number | undefined;
  let joinedAt: number | undefined;
  let currentMembership: string | undefined;

  for (const row of result.results) {
    const content = JSON.parse(row.content) as { membership?: string };
    const membership = content.membership;

    // Track first invite
    if (membership === 'invite' && invitedAt === undefined) {
      invitedAt = row.origin_server_ts;
    }

    // Track first join (could be after invite, or direct join for public rooms)
    if (membership === 'join' && joinedAt === undefined) {
      joinedAt = row.origin_server_ts;
    }

    currentMembership = membership;
  }

  const isMember = currentMembership === 'join';
  const wasEverMember = joinedAt !== undefined || invitedAt !== undefined;

  return { invitedAt, joinedAt, isMember, wasEverMember };
}

/**
 * Get full visibility context for a user in a room
 */
export async function getVisibilityContext(
  db: D1Database,
  roomId: string,
  userId: string
): Promise<VisibilityContext> {
  const [visibility, timestamps] = await Promise.all([
    getRoomHistoryVisibility(db, roomId),
    getMembershipTimestamps(db, roomId, userId),
  ]);

  return {
    visibility,
    ...timestamps,
  };
}

/**
 * Check if a user can see an event based on history visibility rules
 */
export function canSeeEvent(
  event: { origin_server_ts: number; type?: string; state_key?: string },
  context: VisibilityContext
): boolean {
  // World readable - anyone can see
  if (context.visibility === 'world_readable') {
    return true;
  }

  // For all other visibility levels, must be/have been a member
  if (!context.wasEverMember) {
    return false;
  }

  // Shared - current and past members can see everything
  if (context.visibility === 'shared') {
    return true;
  }

  // Invited - can see from invite time onwards
  if (context.visibility === 'invited') {
    const visibleFrom = context.invitedAt ?? context.joinedAt;
    if (visibleFrom === undefined) {
      return false;
    }
    return event.origin_server_ts >= visibleFrom;
  }

  // Joined - can see from join time onwards
  if (context.visibility === 'joined') {
    if (context.joinedAt === undefined) {
      return false;
    }
    return event.origin_server_ts >= context.joinedAt;
  }

  // Unknown visibility - default deny
  return false;
}

/**
 * Filter an array of events based on history visibility
 * This is the main function to use when filtering events for a user
 */
export function filterEventsByVisibility<T extends { origin_server_ts: number }>(
  events: T[],
  context: VisibilityContext
): T[] {
  // Fast path for common cases
  if (context.visibility === 'world_readable') {
    return events;
  }

  if (context.visibility === 'shared' && context.wasEverMember) {
    return events;
  }

  // Need to filter based on timestamps
  return events.filter(event => canSeeEvent(event, context));
}

/**
 * Convenience function to filter events for a user in a room
 * Combines getting context and filtering in one call
 */
export async function filterEventsForUser<T extends { origin_server_ts: number }>(
  db: D1Database,
  roomId: string,
  userId: string,
  events: T[]
): Promise<T[]> {
  if (events.length === 0) {
    return events;
  }

  const context = await getVisibilityContext(db, roomId, userId);
  return filterEventsByVisibility(events, context);
}
