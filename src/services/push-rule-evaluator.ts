// Push Rule Evaluator Service
// Provides notification and highlight counting using push rule evaluation
// Extracted for use by sync and sliding-sync endpoints

import { evaluatePushRules } from '../api/push';

export { evaluatePushRules };

interface UnreadEvent {
  event_id: string;
  event_type: string;
  content: string;
  sender: string;
  room_id: string;
  state_key?: string;
}

/**
 * Count notifications and highlights for unread events in a room
 * using the user's push rules for accurate counting.
 */
export async function countNotificationsWithRules(
  db: D1Database,
  userId: string,
  roomId: string,
  sinceStreamOrdering?: number,
): Promise<{ notification_count: number; highlight_count: number }> {
  // Get the user's read marker
  let readStreamOrdering = sinceStreamOrdering;

  if (readStreamOrdering === undefined) {
    const fullyReadMarker = await db.prepare(`
      SELECT content FROM account_data
      WHERE user_id = ? AND room_id = ? AND event_type = 'm.fully_read'
    `).bind(userId, roomId).first<{ content: string }>();

    if (fullyReadMarker) {
      try {
        const markerContent = JSON.parse(fullyReadMarker.content);
        const readEvent = await db.prepare(`
          SELECT stream_ordering FROM events WHERE event_id = ?
        `).bind(markerContent.event_id).first<{ stream_ordering: number }>();
        readStreamOrdering = readEvent?.stream_ordering;
      } catch { /* ignore */ }
    }
  }

  // Get unread events (messages and encrypted events from others)
  let unreadEvents: UnreadEvent[];
  if (readStreamOrdering) {
    const results = await db.prepare(`
      SELECT event_id, event_type as type, content, sender, room_id, state_key
      FROM events
      WHERE room_id = ? AND stream_ordering > ? AND sender != ?
        AND event_type IN ('m.room.message', 'm.room.encrypted')
      ORDER BY stream_ordering ASC
      LIMIT 500
    `).bind(roomId, readStreamOrdering, userId).all<UnreadEvent>();
    unreadEvents = results.results;
  } else {
    const results = await db.prepare(`
      SELECT event_id, event_type as type, content, sender, room_id, state_key
      FROM events
      WHERE room_id = ? AND sender != ?
        AND event_type IN ('m.room.message', 'm.room.encrypted')
      ORDER BY stream_ordering DESC
      LIMIT 500
    `).bind(roomId, userId).all<UnreadEvent>();
    unreadEvents = results.results;
  }

  if (unreadEvents.length === 0) {
    return { notification_count: 0, highlight_count: 0 };
  }

  // Get room member count for push rule evaluation
  const memberCount = await db.prepare(`
    SELECT COUNT(*) as count FROM room_memberships
    WHERE room_id = ? AND membership = 'join'
  `).bind(roomId).first<{ count: number }>();

  // Get user's display name for mention detection
  const user = await db.prepare(`
    SELECT display_name FROM users WHERE user_id = ?
  `).bind(userId).first<{ display_name: string | null }>();

  let notificationCount = 0;
  let highlightCount = 0;

  for (const event of unreadEvents) {
    let parsedContent: Record<string, unknown>;
    try {
      parsedContent = typeof event.content === 'string' ? JSON.parse(event.content) : event.content;
    } catch {
      parsedContent = {};
    }

    const result = await evaluatePushRules(
      db,
      userId,
      {
        type: event.event_type,
        content: parsedContent,
        sender: event.sender,
        room_id: event.room_id,
        state_key: event.state_key,
      },
      memberCount?.count || 1,
      user?.display_name || undefined,
    );

    if (result.notify) {
      notificationCount++;
    }
    if (result.highlight) {
      highlightCount++;
    }
  }

  return { notification_count: notificationCount, highlight_count: highlightCount };
}
