// Search API
// Implements: https://spec.matrix.org/v1.12/client-server-api/#searching
//
// Provides full-text search for room messages

import { Hono } from 'hono';
import type { AppEnv } from '../types';
import { Errors } from '../utils/errors';
import { requireAuth } from '../middleware/auth';

const app = new Hono<AppEnv>();

// ============================================
// Types
// ============================================

interface SearchRequest {
  search_categories: {
    room_events?: {
      search_term: string;
      keys?: string[];
      filter?: {
        rooms?: string[];
        not_rooms?: string[];
        senders?: string[];
        not_senders?: string[];
        types?: string[];
        not_types?: string[];
      };
      order_by?: 'recent' | 'rank';
      event_context?: {
        before_limit?: number;
        after_limit?: number;
        include_profile?: boolean;
      };
      include_state?: boolean;
      groupings?: {
        group_by: Array<{ key: string }>;
      };
    };
  };
}

interface SearchResult {
  event_id: string;
  rank: number;
  result: {
    event_id: string;
    type: string;
    room_id: string;
    sender: string;
    origin_server_ts: number;
    content: Record<string, any>;
  };
  context?: {
    events_before: any[];
    events_after: any[];
    profile_info?: Record<string, { displayname?: string; avatar_url?: string }>;
    start?: string;
    end?: string;
  };
}

// ============================================
// Endpoints
// ============================================

// POST /_matrix/client/v3/search - Search room events
app.post('/_matrix/client/v3/search', requireAuth(), async (c) => {
  const userId = c.get('userId');
  const db = c.env.DB;

  // Parse pagination
  const nextBatch = c.req.query('next_batch');

  let body: SearchRequest;
  try {
    body = await c.req.json();
  } catch {
    return Errors.badJson().toResponse();
  }

  const roomEvents = body.search_categories?.room_events;
  if (!roomEvents) {
    return c.json({
      search_categories: {
        room_events: {
          results: [],
          count: 0,
          highlights: [],
        },
      },
    });
  }

  const searchTerm = roomEvents.search_term;
  if (!searchTerm || searchTerm.trim().length === 0) {
    return c.json({
      search_categories: {
        room_events: {
          results: [],
          count: 0,
          highlights: [],
        },
      },
    });
  }

  const filter = roomEvents.filter || {};
  const orderBy = roomEvents.order_by || 'recent';
  const eventContext = roomEvents.event_context;
  const includeState = roomEvents.include_state || false;

  // Get rooms the user is a member of
  const userRooms = await db.prepare(`
    SELECT room_id FROM room_memberships
    WHERE user_id = ? AND membership IN ('join', 'leave')
  `).bind(userId).all<{ room_id: string }>();

  const userRoomIds = new Set(userRooms.results.map(r => r.room_id));

  // Apply room filters
  let searchRoomIds = Array.from(userRoomIds);

  if (filter.rooms && filter.rooms.length > 0) {
    searchRoomIds = searchRoomIds.filter(r => filter.rooms!.includes(r));
  }

  if (filter.not_rooms && filter.not_rooms.length > 0) {
    searchRoomIds = searchRoomIds.filter(r => !filter.not_rooms!.includes(r));
  }

  if (searchRoomIds.length === 0) {
    return c.json({
      search_categories: {
        room_events: {
          results: [],
          count: 0,
          highlights: [],
        },
      },
    });
  }

  // Build the search query using FTS5 for ranked full-text search
  const limit = 50;
  let offset = 0;

  if (nextBatch) {
    try {
      offset = parseInt(nextBatch, 10);
    } catch {}
  }

  // Use FTS5 MATCH for full-text search with BM25 ranking
  // Escape FTS5 special characters in search term
  const ftsSearchTerm = searchTerm.replace(/['"*()]/g, ' ').trim();

  let query = `
    SELECT e.event_id, e.event_type, e.room_id, e.sender, e.origin_server_ts, e.content,
           bm25(events_fts) as rank
    FROM events_fts fts
    JOIN events e ON fts.event_id = e.event_id
    WHERE fts.body MATCH ?
      AND e.room_id IN (${searchRoomIds.map(() => '?').join(',')})
  `;

  const params: any[] = [ftsSearchTerm, ...searchRoomIds];

  // Apply sender filter
  if (filter.senders && filter.senders.length > 0) {
    query += ` AND e.sender IN (${filter.senders.map(() => '?').join(',')})`;
    params.push(...filter.senders);
  }

  if (filter.not_senders && filter.not_senders.length > 0) {
    query += ` AND e.sender NOT IN (${filter.not_senders.map(() => '?').join(',')})`;
    params.push(...filter.not_senders);
  }

  // Apply type filter (though we're already filtering for m.room.message)
  if (filter.types && filter.types.length > 0) {
    query += ` AND e.event_type IN (${filter.types.map(() => '?').join(',')})`;
    params.push(...filter.types);
  }

  if (filter.not_types && filter.not_types.length > 0) {
    query += ` AND e.event_type NOT IN (${filter.not_types.map(() => '?').join(',')})`;
    params.push(...filter.not_types);
  }

  // Order by
  if (orderBy === 'rank') {
    query += ` ORDER BY rank ASC`; // BM25 returns negative values, lower = better
  } else {
    query += ` ORDER BY e.origin_server_ts DESC`;
  }

  query += ` LIMIT ? OFFSET ?`;
  params.push(limit + 1, offset);

  const results = await db.prepare(query).bind(...params).all<{
    event_id: string;
    event_type: string;
    room_id: string;
    sender: string;
    origin_server_ts: number;
    content: string;
    rank: number;
  }>();

  // Check if there are more results
  const hasMore = results.results.length > limit;
  const searchResults = results.results.slice(0, limit);

  // Get count (approximate for performance)
  const countQuery = `
    SELECT COUNT(*) as total
    FROM events_fts fts
    JOIN events e ON fts.event_id = e.event_id
    WHERE fts.body MATCH ?
      AND e.room_id IN (${searchRoomIds.map(() => '?').join(',')})
  `;
  const countResult = await db.prepare(countQuery).bind(ftsSearchTerm, ...searchRoomIds).first<{ total: number }>();
  const totalCount = countResult?.total || 0;

  // Build response
  const formattedResults: SearchResult[] = [];

  for (const event of searchResults) {
    let content: Record<string, any> = {};
    try {
      content = JSON.parse(event.content);
    } catch {}

    const result: SearchResult = {
      event_id: event.event_id,
      rank: Math.abs(event.rank || 0),
      result: {
        event_id: event.event_id,
        type: event.event_type,
        room_id: event.room_id,
        sender: event.sender,
        origin_server_ts: event.origin_server_ts,
        content,
      },
    };

    // Add context if requested
    if (eventContext) {
      const beforeLimit = eventContext.before_limit || 5;
      const afterLimit = eventContext.after_limit || 5;

      // Get events before
      const eventsBefore = await db.prepare(`
        SELECT event_id, event_type, sender, origin_server_ts, content
        FROM events
        WHERE room_id = ? AND origin_server_ts < ?
        ORDER BY origin_server_ts DESC
        LIMIT ?
      `).bind(event.room_id, event.origin_server_ts, beforeLimit).all<{
        event_id: string;
        event_type: string;
        sender: string;
        origin_server_ts: number;
        content: string;
      }>();

      // Get events after
      const eventsAfter = await db.prepare(`
        SELECT event_id, event_type, sender, origin_server_ts, content
        FROM events
        WHERE room_id = ? AND origin_server_ts > ?
        ORDER BY origin_server_ts ASC
        LIMIT ?
      `).bind(event.room_id, event.origin_server_ts, afterLimit).all<{
        event_id: string;
        event_type: string;
        sender: string;
        origin_server_ts: number;
        content: string;
      }>();

      result.context = {
        events_before: eventsBefore.results.reverse().map(e => ({
          event_id: e.event_id,
          type: e.event_type,
          sender: e.sender,
          origin_server_ts: e.origin_server_ts,
          content: JSON.parse(e.content),
          room_id: event.room_id,
        })),
        events_after: eventsAfter.results.map(e => ({
          event_id: e.event_id,
          type: e.event_type,
          sender: e.sender,
          origin_server_ts: e.origin_server_ts,
          content: JSON.parse(e.content),
          room_id: event.room_id,
        })),
      };

      // Add profile info if requested
      if (eventContext.include_profile) {
        const senders = new Set<string>();
        senders.add(event.sender);
        eventsBefore.results.forEach(e => senders.add(e.sender));
        eventsAfter.results.forEach(e => senders.add(e.sender));

        const profiles: Record<string, { displayname?: string; avatar_url?: string }> = {};

        for (const senderId of senders) {
          const profile = await db.prepare(`
            SELECT display_name, avatar_url FROM users WHERE user_id = ?
          `).bind(senderId).first<{ display_name: string | null; avatar_url: string | null }>();

          if (profile) {
            profiles[senderId] = {
              displayname: profile.display_name || undefined,
              avatar_url: profile.avatar_url || undefined,
            };
          }
        }

        result.context.profile_info = profiles;
      }
    }

    formattedResults.push(result);
  }

  // Extract highlights (words that matched)
  const highlights = extractHighlights(searchTerm);

  // Build response
  const response: any = {
    search_categories: {
      room_events: {
        results: formattedResults,
        count: totalCount,
        highlights,
      },
    },
  };

  // Add pagination token if there are more results
  if (hasMore) {
    response.search_categories.room_events.next_batch = String(offset + limit);
  }

  // Add room state if requested
  if (includeState && formattedResults.length > 0) {
    const roomIds = new Set(formattedResults.map(r => r.result.room_id));
    const state: Record<string, any[]> = {};

    for (const roomId of roomIds) {
      const roomState = await db.prepare(`
        SELECT e.event_type, e.state_key, e.sender, e.content, e.origin_server_ts
        FROM room_state rs
        JOIN events e ON rs.event_id = e.event_id
        WHERE rs.room_id = ?
      `).bind(roomId).all<{
        event_type: string;
        state_key: string;
        sender: string;
        content: string;
        origin_server_ts: number;
      }>();

      state[roomId] = roomState.results.map(s => ({
        type: s.event_type,
        state_key: s.state_key,
        sender: s.sender,
        content: JSON.parse(s.content),
        origin_server_ts: s.origin_server_ts,
        room_id: roomId,
      }));
    }

    response.search_categories.room_events.state = state;
  }

  // Add groupings if requested
  if (roomEvents.groupings?.group_by) {
    const groups: Record<string, any> = {};

    for (const groupBy of roomEvents.groupings.group_by) {
      if (groupBy.key === 'room_id') {
        const roomGroups: Record<string, { results: string[]; order: number; next_batch?: string }> = {};

        for (const result of formattedResults) {
          const roomId = result.result.room_id;
          if (!roomGroups[roomId]) {
            roomGroups[roomId] = { results: [], order: 0 };
          }
          roomGroups[roomId].results.push(result.event_id);
        }

        groups.room_id = roomGroups;
      } else if (groupBy.key === 'sender') {
        const senderGroups: Record<string, { results: string[]; order: number; next_batch?: string }> = {};

        for (const result of formattedResults) {
          const sender = result.result.sender;
          if (!senderGroups[sender]) {
            senderGroups[sender] = { results: [], order: 0 };
          }
          senderGroups[sender].results.push(result.event_id);
        }

        groups.sender = senderGroups;
      }
    }

    if (Object.keys(groups).length > 0) {
      response.search_categories.room_events.groups = groups;
    }
  }

  return c.json(response);
});

// Helper function to extract highlight terms
function extractHighlights(searchTerm: string): string[] {
  // Split search term into words and return unique terms
  const words = searchTerm.toLowerCase().split(/\s+/).filter(w => w.length > 0);
  return [...new Set(words)];
}

export default app;
